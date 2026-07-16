import re
from datetime import datetime, timedelta, timezone

from flask import (
    Blueprint,
    abort,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import current_user
from sqlalchemy import or_
from werkzeug.security import check_password_hash, generate_password_hash

from models import Paste, User, db, generate_random_id
from properties import (
    BANNED_URLS,
)
from routes.helper import (
    get_client_ip,
    get_total_pages,
    is_ip_banned,
    login_required,
    sanitize_content
)

bp = Blueprint("paste", __name__)


@bp.route("/", methods=["GET", "POST"])
def index():
    ip = get_client_ip()
    if is_ip_banned(ip):
        return jsonify({"success": False, "error": "your ip has been banned!"}), 200

    if request.method == "POST":
        if "_user_id" not in session:
            return jsonify({"success": False, "error": "please log in to submit!"}), 200

        user_id = session["_user_id"]
        one_day_ago = datetime.now(timezone.utc) - timedelta(days=1)
        claim_count = (
            Paste.query.filter_by(user_id=user_id)
            .filter(Paste.published_at.isnot(None))
            .filter(Paste.published_at >= one_day_ago)
            .count()
        )

        if claim_count >= 10:
            return jsonify(
                {"success": False, "error": "you have reached the daily claim limit."}
            ), 200

        raw_content = request.form.get("content")
        if raw_content is None:
            return jsonify({"success": False, "error": "no content provided!"}), 200

        content = sanitize_content(raw_content)
        if not content:
            return jsonify(
                {"success": False, "error": "content is empty after sanitization."}
            ), 200

        custom_id = request.form.get("custom_id", "").strip()

        if custom_id:
            if not re.match(r"^[a-zA-Z0-9_-]+$", custom_id):
                return jsonify(
                    {"success": False, "error": "invalid url format/characters"}
                ), 200
            if custom_id in BANNED_URLS:
                return jsonify({"success": False, "error": "this url is banned."}), 200
            if db.session.get(Paste, custom_id):
                return jsonify(
                    {"success": False, "error": "that url is already taken!"}
                ), 200
            paste_id = custom_id
        else:
            while True:
                paste_id = generate_random_id()
                if not db.session.get(Paste, paste_id):
                    break

        new_paste = Paste(
            id=paste_id,
            content=content,
            user_id=user_id,
            published_at=datetime.now(timezone.utc),
            last_edited_at=datetime.now(timezone.utc),
        )
        db.session.add(new_paste)
        db.session.commit()

        return redirect(
            url_for("paste.view_paste", paste_id=paste_id)
)

    return render_template("index.html")


@bp.route("/<paste_id>")
def view_paste(paste_id):
    paste = db.session.get(Paste, paste_id)
    if not paste:
        abort(404)

    if paste.password_hash:
        if not session.get(f"paste_{paste_id}_unlocked"):
            return redirect(url_for("paste.view_protected_paste", paste_id=paste_id))

    user = db.session.get(User, session.get("_user_id"))
    safe_content = sanitize_content(paste.content)

    cookie_key = "viewed_paste"

    response = make_response(
        render_template(
            "paste/view_paste.html",
            paste=paste,
            current_user=user,
            safe_content=safe_content,
            published_at=paste.published_at,
            last_edited_at=paste.last_edited_at,
            logged_in=("_user_id" in session),
        )
    )

    if not request.cookies.get(cookie_key):
        paste.views = (paste.views or 0) + 1
        db.session.commit()

        response.set_cookie(
            cookie_key, "true", max_age=60 * 60 * 24 * 7, path=f"/{paste_id}"
        )

    return response


@bp.route("/edit/<paste_id>", methods=["GET", "POST"])
def edit_paste(paste_id):
    paste = db.session.get(Paste, paste_id)
    if not paste:
        abort(404)

    if request.method == "POST":
        raw_content = request.form.get("content")
        if raw_content is None:
            abort(400)

        sanitized_content = sanitize_content(raw_content)
        if sanitized_content is None:
            sanitized_content = ""

        paste.content = sanitized_content
        paste.last_edited_at = datetime.now(timezone.utc)

        def get_form_value(key):
            value = request.form.get(key)
            if value is None:
                return ""
            value_stripped = value.strip()
            if value_stripped.lower() == "none" or value_stripped == "":
                return ""
            return value

        paste.meta_description = get_form_value("meta_description")
        paste.meta_image = get_form_value("meta_image")
        paste.theme_color = get_form_value("theme_color")
        paste.page_title = get_form_value("page_title")
        paste.favicon_url = get_form_value("favicon_url")

        try:
            db.session.commit()
        except Exception as e:
            print(f"error during commit: {e}")

        return redirect(url_for("paste.view_paste", paste_id=paste_id))

    for attr in [
        "meta_description",
        "meta_image",
        "theme_color",
        "page_title",
        "favicon_url",
    ]:
        value = getattr(paste, attr)
        if value is None or value.lower() == "none":
            setattr(paste, attr, "")

    return render_template("paste/edit_paste.html", paste=paste)


@bp.route("/update_password/<paste_id>", methods=["GET", "POST"])
@login_required
def update_paste_password(paste_id):
    paste = db.session.get(Paste, paste_id)
    if not paste:
        return "paste not found.", 404

    current_user = db.session.get(User, session.get("_user_id"))
    if not current_user:
        return redirect(url_for("user.login"))

    if paste.user_id != current_user.id and not current_user.is_admin:
        return "you don't have permission.", 403

    if request.method == "POST":
        new_password = request.form.get("new_password")
        if new_password:
            paste.password_hash = generate_password_hash(new_password)
            db.session.commit()
            return redirect(url_for("paste.view_paste", paste_id=paste_id))
        else:
            return jsonify(success=False, error="password cannot be empty.")

    return render_template("paste/update_password.html", paste=paste)


@bp.route("/remove_paste_password/<paste_id>", methods=["POST"])
def remove_paste_password(paste_id):
    paste = db.get_or_404(Paste, paste_id)
    paste.password_hash = None

    try:
        db.session.commit()
        return redirect(url_for("paste.view_paste", paste_id=paste_id))
    except Exception as e:
        db.session.rollback()
        return jsonify(
            success=False, error=f"error removing password for {paste_id}: {e}"
        )


@bp.route("/<paste_id>/protected", methods=["GET", "POST"])
def view_protected_paste(paste_id):
    paste = db.session.get(Paste, paste_id)
    if not paste:
        abort(404)

    if not paste.password_hash:
        return redirect(url_for("paste.view_paste", paste_id=paste_id))

    if request.method == "POST":
        entered_password = request.form.get("password")
        if entered_password and check_password_hash(
            paste.password_hash, entered_password
        ):
            session[f"paste_{paste_id}_unlocked"] = True
            return redirect(url_for("paste.view_paste", paste_id=paste_id))
        else:
            error = "incorrect password. please try again."
            return render_template("paste/password_prompt.html", error=error)

    if session.get(f"paste_{paste_id}_unlocked"):
        return redirect(url_for("paste.view_paste", paste_id=paste_id))

    return render_template("paste/password_prompt.html")


@bp.route("/transfer/<paste_id>", methods=["GET"])
@login_required
def transfer_ownership(paste_id):
    paste = db.session.get(Paste, paste_id)
    if not paste:
        return "paste not found.", 404

    current_user_obj = db.session.get(User, session.get("_user_id"))
    if current_user_obj is None:
        return redirect(url_for("user.login"))

    if paste.user_id != current_user_obj.id and not current_user_obj.is_admin:
        return "you don't have permission.", 403

    return render_template("paste/transfer_paste.html", paste=paste)


@bp.route("/transfer/<paste_id>", methods=["POST"])
@login_required
def handle_transfer(paste_id):
    paste = db.session.get(Paste, paste_id)
    if not paste:
        return jsonify(success=False, error="paste not found!"), 404

    current_user_obj = db.session.get(User, session.get("_user_id"))
    if current_user_obj is None:
        return jsonify(success=False, error="user not logged in!!!"), 401

    if paste.user_id != current_user_obj.id and not current_user_obj.is_admin:
        return jsonify(success=False, error="you don't have the perms for this"), 403

    new_owner_username = request.form.get("new_owner")
    new_owner = User.query.filter_by(username=new_owner_username).first()
    if not new_owner:
        return jsonify(
            success=False, error="new owner ...not found? check your spelling"
        ), 400

    if new_owner.id == current_user_obj.id:
        return jsonify(
            success=False,
            error="you cannot transfer the paste to yourself.",
        ), 400

    paste.user_id = new_owner.id
    db.session.commit()

    return jsonify(success=True)


@bp.route("/<paste_id>/delete", methods=["POST"])
@login_required
def delete_paste(paste_id):
    paste = db.session.get(Paste, paste_id)
    if not paste:
        abort(404)

    user = db.session.get(User, session.get("_user_id"))
    if user is None:
        return redirect(url_for("user.login"))

    if paste.user_id != user.id and not user.is_admin:
        abort(403)
    db.session.delete(paste)
    db.session.commit()
    return redirect(url_for("paste.index"))


@bp.route("/<paste_id>/report")
@login_required
def report(paste_id):
    paste = db.session.get(Paste, paste_id)
    if paste is None:
        abort(404)
    return render_template("paste/report.html", paste=paste)


@bp.route("/<paste_id>/report", methods=["POST"])
def report_post(paste_id):
    paste = db.session.get(Paste, paste_id)
    if paste is None:
        abort(404)
    if not current_user.is_authenticated:
        abort(401)

    if paste.user_id != current_user.id:
        abort(403)

    paste.user_id = None
    db.session.commit()
    return redirect(url_for("paste.dashboard"))


@bp.route("/<paste_id>/reclaim")
@login_required
def reclaim(paste_id):
    paste = db.session.get(Paste, paste_id)
    if paste is None:
        abort(404)
    return render_template("paste/reclaim.html", paste=paste)


@bp.route("/<paste_id>/reclaim", methods=["POST"])
def reclaim_post(paste_id):
    paste = db.session.get(Paste, paste_id)
    if paste is None:
        abort(404)
    if paste.user_id != current_user.id:
        abort(403)
    paste.user_id = None
    db.session.commit()
    return redirect(url_for("paste.dashboard", paste=paste))


@bp.route("/extras/<paste_id>")
@login_required
def paste_extras(paste_id):
    paste = db.session.get(Paste, paste_id)
    if paste is None:
        abort(404)
    return render_template("paste/paste_extras.html", paste=paste)


@bp.route("/dashboard")
@login_required
def dashboard():
    user = db.session.get(User, session.get("_user_id"))
    if user is None:
        session.pop("_user_id", None)
        return redirect(url_for("user.login"))

    search_query = request.args.get("search", "")
    page = int(request.args.get("page", 1))
    per_page = 5

    pastes_query = Paste.query.filter_by(user_id=user.id)
    if search_query:
        pastes_query = pastes_query.filter(
            or_(
                Paste.id.cast(db.String).contains(search_query),
                Paste.content.contains(search_query),
            )
        )
    total = pastes_query.count()
    total_pages = get_total_pages(total, per_page)

    user_pastes = (
        pastes_query.order_by(Paste.last_edited_at.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )

    return render_template(
        "user/dashboard.html",
        pastes=user_pastes,
        page=page,
        total=total,
        total_pages=total_pages,
        per_page=per_page,
        search=search_query,
    )
