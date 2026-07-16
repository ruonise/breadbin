from flask import Blueprint, render_template

bp = Blueprint("error", __name__)


@bp.errorhandler(400)
def request_failed(e):
    return render_template("errors/400.html"), 400


@bp.errorhandler(401)
def authorization_failed(e):
    return render_template("errors/401.html"), 401


@bp.errorhandler(403)
def access_denied(e):
    return render_template("errors/403.html"), 403


@bp.errorhandler(404)
def page_not_found(e):
    return render_template("errors/404.html"), 404


@bp.errorhandler(500)
def csrf_token(e):
    return render_template("errors/500.html"), 500
