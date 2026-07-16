import secrets
import string
from functools import wraps

from flask import abort
from flask_login import UserMixin, current_user
from werkzeug.security import check_password_hash, generate_password_hash

from db import db


def generate_random_id(length=18):
    characters = string.ascii_letters + string.digits
    return "".join(secrets.choice(characters) for _ in range(length))


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)

    return decorated_function


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    profile_picture = db.Column(db.String(120), nullable=True)
    bio = db.Column(db.String(500), nullable=True)
    is_admin = db.Column(db.Integer, default=0)
    is_banned = db.Column(db.Integer, default=0)
    custom_css = db.Column(db.String(1000), nullable=True)
    privacy_policy = db.Column(db.Integer, nullable=False)

    pastes = db.relationship(
        "Paste",
        backref="user",
        cascade="all, delete",
        passive_deletes=True
    )

    def __init__(self, username, privacy_policy, is_admin):
        self.username = username
        self.privacy_policy = privacy_policy
        self.is_admin = is_admin

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Paste(db.Model):
    id = db.Column(db.String(30), primary_key=True)
    content = db.Column(db.String(5000), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"))
    last_edited_at = db.Column(db.DateTime, nullable=True)
    published_at = db.Column(db.DateTime, nullable=True)
    views = db.Column(db.Integer, default=0)
    meta_description = db.Column(db.String(255), nullable=True)
    meta_image = db.Column(db.String(255), nullable=True)
    theme_color = db.Column(db.String(7), nullable=True)
    page_title = db.Column(db.String(255), nullable=True)
    favicon_url = db.Column(db.String(255), nullable=True)
    password_hash = db.Column(db.String(128), nullable=True)

    def __init__(
    self,
    id=None,
    content=None,
    user_id=None,
    last_edited_at=None,
    published_at=None,
    views=0,
    meta_description=None,
    meta_image=None,
    theme_color=None,
    page_title=None,
    favicon_url=None,
    password_hash=None,
):
        self.id = id
        self.content = content
        self.user_id = user_id
        self.last_edited_at = last_edited_at
        self.published_at = published_at
        self.views = views
        self.meta_description = meta_description
        self.meta_image = meta_image
        self.theme_color = theme_color
        self.page_title = page_title
        self.favicon_url = favicon_url
        self.password_hash = password_hash


class IPLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(128), db.ForeignKey("user.id"), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    user = db.relationship("User", backref="ip_logs")

    def __init__(self, user, ip_address):
        self.user = user
        self.ip_address = ip_address


class BannedIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    reason = db.Column(db.String(255))
    banned_at = db.Column(db.DateTime, default=db.func.now())

    def __init__(self, ip_address, reason):
        self.ip_address = ip_address
        self.reason = reason


class BannedUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), unique=True)
    reason = db.Column(db.String(255))
    banned_at = db.Column(db.DateTime, default=db.func.now())

    def __init__(self, user_id, reason):
        self.user_id = user_id
        self.reason = reason

    user = db.relationship("User", backref="banned")


class InviteCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(32), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.now())
    used = db.Column(db.Boolean, default=False)
    used_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    used_at = db.Column(db.DateTime, nullable=True)

    def __init__(self, code, creator_id):
        self.code = code
        self.creator_id = creator_id

    creator_id = db.Column(db.Integer, db.ForeignKey("user.id"))

    creator = db.relationship(
        "User", foreign_keys=[creator_id], backref="created_invite_codes"
    )
    used_by_user = db.relationship(
        "User", foreign_keys=[used_by], backref="used_invite_codes"
    )


class ClaimLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    claimed_at = db.Column(db.DateTime, default=db.func.now())

    user = db.relationship("User", backref="claim_logs")


class AuditLog(db.Model):
    id = db.Column(db.String(128), primary_key=True)
    event = db.Column(db.String(100), nullable=False)
    target_user_id = db.Column(db.String(128), db.ForeignKey("user.id"), nullable=True)
    actor_id = db.Column(db.String(128), db.ForeignKey("user.id"), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=db.func.now())
    actor = db.relationship("User", foreign_keys=[actor_id], backref="audit_actions")

    target_user = db.relationship(
        "User", foreign_keys=[target_user_id], backref="audit_events"
    )

    def __init__(
        self,
        event,
        actor=None,
        target_user=None,
        ip_address=None,
        user_agent=None,
    ):
        self.id = generate_random_id()
        self.event = event
        self.actor = actor
        self.target_user = target_user
        self.ip_address = ip_address
        self.user_agent = user_agent
