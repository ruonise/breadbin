from urllib.parse import unquote
from flask import (
    Blueprint,
    render_template,
    request,
    jsonify
)
from flask_login import current_user
import secrets
from models import (
    AuditLog,
    BannedIP,
    IPLog,
    InviteCode,
    User,
    admin_required,
    generate_random_id,
    db,
)
from utils.audit import log_action, redirect_with_message

bp = Blueprint("admin", __name__)


@bp.route("/debug")
@admin_required
def debug():
    user_info = {
        "id": current_user.id,
        "username": current_user.username,
        "description": current_user.description,
        "is_authenticated": current_user.is_authenticated,
    }

    return render_template(
        "admin/debug.html",
        data={"user": user_info},
        user=current_user,
    )


@bp.route("/admin/<user_id>")
def admin_profile(user_id):
    user = db.session.get(User, user_id)

    if not user:
        return "user not found", 404

    page = request.args.get("page", 1, type=int)

    ip_logs = (
        IPLog.query
        .filter_by(user_id=user.id)
        .order_by(IPLog.id.desc())
        .paginate(page=page, per_page=2, error_out=False)
    )

    banned_ips = [
        ip.ip_address
        for ip in db.session.query(BannedIP.ip_address).all()
    ]

    return render_template(
        "admin/admin_profile.html",
        profile_user=user,
        ip_logs=ip_logs,
        banned_ips=banned_ips,
        user=current_user,
        owner=user,
    )


@bp.route("/admin/<user_id>/ban", methods=["POST"])
@admin_required
def ban_user(user_id):
    user = User.query.filter_by(id=user_id).first()

    if not user:
        return redirect_with_message("paste.index", "user not found")

    try:
        user.is_banned = True
        db.session.commit()

        log_action(event="ban_user", target_user=user)

    except Exception as e:
        db.session.rollback()
        return redirect_with_message("paste.index", f"{'generic_error'}: {e}")

    return redirect_with_message("paste.index", "user banned")


@bp.route("/admin/<user_id>/unban", methods=["POST"])
@admin_required
def unban_user(user_id):
    user = User.query.filter_by(id=user_id).first()

    if not user:
        return redirect_with_message("paste.index", "user notfound")

    try:
        user.is_banned = False
        db.session.commit()

        log_action(event="unban_user", target_user=user)

    except Exception as e:
        db.session.rollback()
        return redirect_with_message("paste.index", f"{'generic error'}: {e}")

    return redirect_with_message("paste.index", "useruser unbanned")


@bp.route("/admin/ip/<ip_address>/ban", methods=["POST"])
@admin_required
def ban_ip(ip_address):
    ip_address = unquote(str(ip_address).strip())

    banned_ip = (
        db.session.query(BannedIP).filter(BannedIP.ip_address == ip_address).first()
    )

    if banned_ip:
        return redirect_with_message("paste.index", "ip already banned")

    try:
        db.session.add(BannedIP(ip_address=ip_address, reason=None))
        db.session.commit()

        log_action(event="ban_ip", ip_address=ip_address)

    except Exception as e:
        db.session.rollback()
        return redirect_with_message("paste.index", f"{'generic error'}: {e}")

    return redirect_with_message("paste.index", "ip banned success")


@bp.route("/admin/ip/<ip_address>/unban", methods=["POST"])
@admin_required
def unban_ip(ip_address):
    ip_address = unquote(str(ip_address).strip())

    banned_ip = (
        db.session.query(BannedIP).filter(BannedIP.ip_address == ip_address).first()
    )

    if not banned_ip:
        return redirect_with_message("paste.index", "ip not found")

    try:
        db.session.delete(banned_ip)
        db.session.commit()

        log_action(event="unban_ip", ip_address=ip_address)

    except Exception as e:
        db.session.rollback()
        return redirect_with_message("paste.index", f"{'generic error'}: {e}")

    return redirect_with_message("paste.index", "ip unbanned success")


@bp.route("/admin/<user_id>/update_password", methods=["POST"])
@admin_required
def update_password(user_id):
    user = db.session.get(User, user_id)
    new_password = request.form.get("password")

    if not user or not new_password:
        return redirect_with_message("paste.index", "missing password")

    try:
        user.set_password(new_password)
        db.session.commit()

        log_action(event="update_user_password", target_user=user)

    except Exception as e:
        db.session.rollback()
        return redirect_with_message("paste.index", f"generic error: {e}")

    return redirect_with_message("paste.index", "password updated success")


@bp.route("/admin/audit-logs")
@admin_required
def audit_logs():
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(500).all()

    banned_ips = {ip.ip_address: ip for ip in BannedIP.query.all()}

    return render_template(
        "admin/audit_logs.html",
        logs=logs,
        banned_ips=banned_ips,
        user=current_user,
    )


@bp.route("/about")
def about():
    return render_template("admin/about.html", user=current_user)


@bp.route("/terms_of_service")
def tos():
    return render_template("admin/tos.html", user=current_user)


@bp.route("/privacy_policy")
def privacy():
    return render_template("admin/privacy.html", user=current_user)


@bp.route("/banned")
def banned_page():
    return render_template("banned.html")


@bp.route("/debug-ips")
def debug_ips():
    return {"banned_ips": [r.ip_address for r in BannedIP.query.all()]}


@bp.route("/admin/ip-management")
@admin_required
def ip_management():
    banned_ips = BannedIP.query.order_by(BannedIP.banned_at.desc()).all()

    return render_template(
        "admin/ip_management.html",
        banned_ips=banned_ips,
        user=current_user,
    )



@bp.route("/admin/generate_invite", methods=["GET", "POST"])
@admin_required
def generate_invite():
    generated_code = None

    if request.method == "POST":
        code = secrets.token_hex(8)

        invite = InviteCode(
            code=code,
            creator_id=current_user.id
        )

        db.session.add(invite)
        db.session.commit()

        generated_code = code

    return render_template(
        "admin/generate_invite.html",
        generated_code=generated_code
    )



@bp.route("/admin/delete_invite_code/<code_id>", methods=["POST"])
@admin_required
def delete_invite_code(code_id):
    code = InviteCode.query.get_or_404(code_id)
    db.session.delete(code)
    db.session.commit()
    return redirect(url_for("invite_codes"))


@bp.route("/admin/invite_codes")
@admin_required
def invite_codes():
    codes = InviteCode.query.order_by(InviteCode.created_at.desc()).all()
    return render_template(
        "admin/invite_codes.html",
        codes=codes,
        user=current_user,
    )


@bp.route("/admin/delete_account", methods=["POST"])
@admin_required
def delete_account():
    user_id = request.form.get("user_id")
    if not user_id:
        return jsonify({"error": "how did u get here bruh"}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "user not found"}), 404

    if user.id == current_user.id:
        return jsonify({"error": "cant delete yo self"}), 403

    if getattr(user, "is_admin", False):
        return jsonify({"error": "fuck you buddy"}), 403

    db.session.delete(user)
    db.session.commit()

    log_action(event="delete_user")

    return jsonify({"success": True, "message": "user gone bye bye"}), 200