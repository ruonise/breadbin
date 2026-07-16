import os
from datetime import datetime, timedelta

from colorama import Fore, Style
from dotenv import load_dotenv
from flask import Flask, g, render_template, request
from flask_login import LoginManager
from flask_wtf import CSRFProtect
from sqlalchemy import event
from sqlalchemy.engine import Engine

from models import BannedIP, User, db
from routes.admin import bp as admin_bp
from routes.error import bp as error_bp
from routes.helper import bp as helper_bp
from routes.helper import (
    sanitize_content,
)
from routes.paste import bp as paste_bp
from routes.user import bp as user_bp

load_dotenv()
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///pastes.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = "static/profile_pics"
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
app.config["REMEMBER_COOKIE_DURATION"] = timedelta(days=30)
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = timedelta(days=30)
app.jinja_env.finalize = lambda x: x if x is not None else ""
app.jinja_env.globals["sanitize_content"] = sanitize_content
app.register_blueprint(error_bp)
app.register_blueprint(user_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(paste_bp)
app.register_blueprint(helper_bp)

login_manager = LoginManager()
login_manager.init_app(app)
csrf = CSRFProtect(app)


@login_manager.user_loader
def load_user(user_id):
    user = User.query.get(int(user_id))
    return user


@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL;")
    cursor.close()


db.init_app(app)

with app.app_context():
    db.create_all()


@app.before_request
def log_request():
    x_forwarded_for = request.headers.get("X-Forwarded-For")
    if x_forwarded_for:
        user_ip = x_forwarded_for.split(",")[0].strip()
    else:
        user_ip = request.remote_addr

    g.user_ip = user_ip
    route = request.path
    print(
        f"{Fore.GREEN}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]"
        f"{Style.RESET_ALL} Received request from {Fore.CYAN}{user_ip}{Style.RESET_ALL} to {Fore.YELLOW}{route}{Style.RESET_ALL}"
    )


@app.before_request
def block_banned_ips():
    ip = request.remote_addr
    banned = BannedIP.query.filter_by(ip_address=ip).first()
    if banned:
        print(
            f"{Fore.GREEN}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]"
            f"{Style.RESET_ALL}{Fore.RED} Received request from stupid loser {ip}!{Style.RESET_ALL}"
        )
        return render_template("errors/403.html"), 403


@app.template_filter("nice_date")
def nice_date_filter(value):
    from datetime import datetime

    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value)
        except ValueError:
            return value
    elif isinstance(value, datetime):
        dt = value
    else:
        return value
    return dt.strftime("%Y-%m-%d %H:%M UTC")


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5001)
