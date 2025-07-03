from flask import Flask


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "your-secret-key-here"  # Change this!

    # Register routes
    from .routes import main

    app.register_blueprint(main)

    return app
