import os
from flask import Flask
from flask_login import LoginManager

def create_app():
    # Create Flask app with correct template and static folders
    app = Flask(__name__, 
                template_folder='../templates',
                static_folder='../static')
    app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-for-development")

    # MongoDB configuration - will be enabled when MongoDB is available
    # app.config["MONGO_URI"] = os.environ.get("MONGO_URI", "mongodb://localhost:27017/secure_messaging")

    # Initialize MongoDB when available
    # from models import mongo, bcrypt, init_db
    # mongo.init_app(app)
    # bcrypt.init_app(app)

    # Initialize Flask-Login
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'

    @login_manager.user_loader
    def load_user(user_id):
        # Temporary user loader for development
        class MockUser:
            def __init__(self):
                self.id = 'dev_user'
                self.username = 'developer'
                self.display_name = 'Developer'
                self.is_authenticated = True
                self.is_active = True
                self.is_anonymous = False

            def get_id(self):
                return self.id

        return MockUser() if user_id == 'dev_user' else None

    # Initialize database indexes
    # Initialize database indexes
    from models import init_db

    with app.app_context():
        init_db()

    # Import and register blueprints
    from app.routes import main
    from app.auth import auth
    app.register_blueprint(main)
    app.register_blueprint(auth, url_prefix='/auth')

    return app

# Create the app instance
app = create_app()