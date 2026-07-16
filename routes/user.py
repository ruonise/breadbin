import os
import re

from flask import (
    Blueprint,
    current_app,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask.typing import ResponseReturnValue
from flask_login import current_user, login_user
from PIL import Image
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename

from models import InviteCode, IPLog, User, db
from properties import (
    CURRENT_POLICY_VERSION,
)
from routes.helper import (
    get_client_ip,
    is_ip_banned,
    login_required,
    sanitize_css,
    sanitize_css_block
)

bp = Blueprint("user", __name__)


@bp.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        invite_code_input = request.form.get("invite_code", "").strip()

        if invite_code_input:
            invite = InviteCode.query.filter_by(
                code=invite_code_input, used=False
            ).first()
            if not invite:
                error = "invalid or already used invite code!"
                return render_template("user/register.html", error=error)
        else:
            error = "invite code is required!"
            return render_template("user/register.html", error=error)

        if User.query.filter_by(username=username).first():
            error = "username already exists!!"
        else:
            user = User(
                username=username, privacy_policy=CURRENT_POLICY_VERSION, is_admin=False
            )
            user.set_password(password)
            db.session.add(user)
            db.session.commit()

            if invite:
                invite.used = True
                invite.used_by = user.id
                invite.used_at = db.func.now()
                db.session.commit()

            session["user_id"] = user.id

            return redirect(url_for("paste.index"))

    return render_template("user/register.html", error=error)


@bp.route("/login", methods=["GET", "POST"])
def login():
    error = None
    ip = get_client_ip()
    if is_ip_banned(ip):
        return "your ip has been banned!", 403
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username).first()
        if user:
            if user.check_password(password):
                login_user(user)
                ip_address = get_client_ip()
                if user and ip_address:
                    ip_log = IPLog(user=user, ip_address=ip_address)
                    db.session.add(ip_log)
                    db.session.commit()
                return redirect(url_for("paste.index"))
            else:
                error = "password incorrect!"
        else:
            error = "invalid credentials."
    return render_template("user/login.html", error=error)


@bp.route("/logout")
def logout():
    session.pop("_user_id", None)
    return redirect(url_for("paste.index"))


@bp.route("/edit_profile", methods=["GET", "POST"])
@login_required
def edit_profile() -> ResponseReturnValue:
    user = db.session.get(User, session.get("_user_id"))

    if user is None:
        return redirect(url_for("user.login"))

    if request.method == "POST":

        custom_css_input = request.form.get("custom_css", "")
        user.custom_css = sanitize_css_block(custom_css_input)
        bio_html = request.form.get("bio", "").strip()
        user.bio = bio_html
        file = request.files.get("profile_picture")
        if file and file.filename:
            filename = secure_filename(file.filename)
            webp_filename = f"user_{user.id}.webp"

            filepath = os.path.join(current_app.config["UPLOAD_FOLDER"], filename)
            webp_filepath = os.path.join(
                current_app.config["UPLOAD_FOLDER"], webp_filename
            )

            file.save(filepath)

            try:
                img = Image.open(filepath)
                img.save(webp_filepath, "WEBP")
                os.remove(filepath)

                old_pfp = user.profile_picture
                if old_pfp and old_pfp != webp_filename:
                    old_pfp_path = os.path.join(
                        current_app.config["UPLOAD_FOLDER"], old_pfp
                    )
                    if os.path.exists(old_pfp_path):
                        os.remove(old_pfp_path)

                user.profile_picture = webp_filename

            except Exception as e:
                print(f"error converting image: {e}")
                user.profile_picture = webp_filename

        new_username = request.form.get("username", "").strip()
        if new_username and new_username != user.username:
            existing_user = User.query.filter_by(username=new_username).first()

            if not existing_user:
                user.username = new_username
            else:
                error_message = (
                    "username already exists.. please choose a different one."
                )
                return render_template(
                    "user/edit_profile.html",
                    user=user,
                    error=error_message
                )

        db.session.commit()

        return redirect(url_for("user.profile", username=user.username))

    return render_template("user/edit_profile.html", user=user)

@bp.route("/profile/<username>", methods=["GET", "POST"])
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    visitor_username = None
    if "user_id" in session:
        current_user_obj = db.session.get(User, session.get("_user_id"))
        if current_user_obj:
            visitor_username = current_user_obj.username

    is_owner = session.get("user_id") == user.id

    if request.method == "POST":
        if not is_owner:
            return redirect(url_for("user.profile", username=user.username))

        bio = request.form.get("bio", "")
        user.bio = bio

        file = request.files.get("profile_picture")
        if file and file.filename:
            filename = secure_filename(file.filename)
            upload_folder = current_app.config["UPLOAD_FOLDER"]
            filepath = os.path.join(upload_folder, filename)
            file.save(filepath)
            user.profile_picture = filename

        db.session.commit()
        return redirect(url_for("user.profile", username=user.username))

    return render_template(
        "user/profile.html",
        user=user,
        is_owner=is_owner,
        visitor_username=visitor_username,
        profile_owner_username=user.username,
        current_user=current_user,
    )


@bp.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    user = db.session.get(User, session.get("_user_id"))
    if user is None:
        return redirect(url_for("user.login"))

    if request.method == "POST":
        current_password = request.form.get("current_password", "").strip()
        new_password = request.form.get("new_password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()

        if not user.check_password(current_password):
            return jsonify(
                {"success": False, "error": "current password is incorrect."}
            )

        if new_password != confirm_password:
            return jsonify({"success": False, "error": "new passwords do not match."})

        user.set_password(new_password)
        db.session.commit()
        return jsonify(
            {
                "success": True,
                "redirect_url": url_for("user.profile", username=user.username),
            }
        )

    return render_template("user/change_password.html")


@bp.route("/accept_terms", methods=["GET", "POST"])
def accept_terms():
    if request.method == "POST":
        if g.current_user:
            g.current_user.privacy_policy = CURRENT_POLICY_VERSION
            db.session.commit()
        return redirect(url_for("paste.index"))
    return render_template("accept_terms.html")


@bp.route("/delete_account", methods=["GET", "POST"])
@login_required
def delete_account():
    user = db.session.get(User, session.get("_user_id"))
    if user is None:
        return redirect(url_for("user.login"))

    if request.method == "POST":
        password_input = request.form.get("password", "").strip()
        if not check_password_hash(user.password_hash, password_input):
            error = "incorrect password."
            return render_template("user/delete_account.html", user=user, error=error)

        try:
            for paste in user.pastes:
                db.session.delete(paste)
            db.session.flush()
            db.session.delete(user)

            db.session.commit()
        except Exception as e:
            print("error during deletion:", e)
            db.session.rollback()
            error = "an error occurred. please try again later!"
            return render_template("user/delete_account.html", user=user, error=error)

        session.clear()
        return redirect(url_for("paste.index"))

    return render_template("user/delete_account.html", user=user)
