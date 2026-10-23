import os
from flask import Flask
from .db import init_db

def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "assignment-1-development-key")
    app.config["DATABASE"] = os.path.join(os.path.dirname(app.instance_path), "vault.db")

    os.makedirs(app.instance_path, exist_ok=True)
    os.makedirs(os.path.join(app.root_path, "..", "storage", "encrypted"), exist_ok=True)

    with app.app_context():
        init_db()

    from .routes import bp
    app.register_blueprint(bp)

    return app
