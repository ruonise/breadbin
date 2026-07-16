from urllib.parse import urlencode

from flask import redirect, request, url_for
from flask_login import current_user

from models import AuditLog, db


def redirect_with_message(endpoint, message, **values):
    return redirect(f"{url_for(endpoint, **values)}?{urlencode({'message': message})}")


def log_action(event, target_user=None, ip_address=None):
    request_ip = request.remote_addr if request else None
    user_agent = request.headers.get("User-Agent") if request else None

    log = AuditLog(
        event=event,
        actor=current_user if current_user.is_authenticated else None,
        target_user=target_user,
        ip_address=ip_address or request_ip,
        user_agent=user_agent,
    )

    db.session.add(log)
    db.session.commit()
