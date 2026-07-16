import re
from functools import wraps

import bleach
from bleach.css_sanitizer import CSSSanitizer
from flask import (
    Blueprint,
    abort,
    g,
    redirect,
    request,
    session,
    url_for,
)

from models import BannedIP, BannedUser, User
from properties import (
    ALLOWED_CSS_PROPERTIES,
    CURRENT_POLICY_VERSION,
    allowed_attributes,
    allowed_tags,
)

bp = Blueprint("helper", __name__)

css_sanitizer_instance = CSSSanitizer(
    allowed_css_properties=ALLOWED_CSS_PROPERTIES
)

def sanitize_css(css):
    css = re.sub(r"@import[^;]*;", "", css, flags=re.IGNORECASE)
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL)

    lines = []

    for decl in css.split(";"):
        decl = decl.strip()

        if not decl or ":" not in decl:
            continue

        prop, value = decl.split(":", 1)

        prop = prop.strip().lower()
        value = value.strip()

        if prop not in ALLOWED_CSS_PROPERTIES:
            continue
            
        if re.search(r"expression\s*\(", value, re.IGNORECASE):
            continue

        lines.append(f"    {prop}: {value};")

    return "\n".join(lines)


def sanitize_css_block(css):
    css = re.sub(r"@import[^;]*;", "", css, flags=re.IGNORECASE)
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL)

    output = []

    for selector, body in re.findall(r"([^{]+)\{([^}]*)\}", css, re.DOTALL):
        selector = selector.strip()
        if selector.startswith("@"):
            continue

        cleaned = sanitize_css(body)

        if not cleaned:
            continue

        output.append(
            f"{selector} {{\n"
            f"{cleaned}\n"
            f"}}"
        )

    return "\n\n".join(output)


def sanitize_content(content):
    return bleach.clean(
        content,
        tags=allowed_tags,
        attributes=allowed_attributes,
        strip=True,
    )


def is_ip_banned(ip):
    return BannedIP.query.filter_by(ip_address=ip).first() is not None


def is_user_banned(user_id):
    return BannedUser.query.filter_by(user_id=user_id).first() is not None


def get_client_ip():
    if request.headers.getlist("X-Forwarded-For"):
        ip = request.headers.getlist("X-Forwarded-For")[0].split(",")[0]
    else:
        ip = request.remote_addr
    return ip


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "_user_id" not in session:
            return redirect(url_for("user.login"))
        return f(*args, **kwargs)

    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = User.query.get(session.get("_user_id"))
        if not user or not user.is_admin:
            abort(403)  # FORBIDDEEN
        return f(*args, **kwargs)

    return decorated_function


def get_form_value(key):
    value = request.form.get(key)
    return value if value is not None else ""


@bp.context_processor
def utility_processor():
    def is_ip_banned(ip):
        return BannedIP.query.filter_by(ip_address=ip).first() is not None

    def sanitize_content_for_template(content):
        return sanitize_content(content)

    return dict(
        is_ip_banned=is_ip_banned, sanitize_content=sanitize_content_for_template
    )


def get_total_pages(total_items, items_per_page):
    return (total_items + items_per_page - 1) // items_per_page


@bp.before_request
def load_user():
    g.current_user = None
    if "_user_id" in session:
        g.current_user = User.query.get(session["_user_id"])


@bp.before_request
def check_privacy_policy():
    if "_user_id" in session:
        user = User.query.get(session["_user_id"])
        if user and user.privacy_policy != CURRENT_POLICY_VERSION:
            if request.endpoint != "accept_terms":
                return redirect(url_for("accept_terms"))


@bp.context_processor
def inject_user():
    current_user = getattr(g, "current_user", None)
    return dict(current_user=current_user)
