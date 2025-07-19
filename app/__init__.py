import os
from flask import Flask
from flask_login import LoginManager

def create_app():
    # Create Flask app with correct template and static folders
    app = Flask(__name__, 
                template_folder='../templates',
                static_folder='../static')
    app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-for-development")
    
    # MongoDB Atlas configuration  
    app.config["MONGO_URI"] = "mongodb+srv://root:VfhIbcEPBS4UShDS@cryptocluster.rl6cnro.mongodb.net/secure_messaging?retryWrites=true&w=majority&appName=CryptoCluster"
    
    # Try to initialize MongoDB, fallback to in-memory storage if unavailable
    try:
        from models import mongo, bcrypt, init_db
        mongo.init_app(app)
        bcrypt.init_app(app)
        
        # Test connection
        with app.app_context():
            mongo.db.list_collection_names()
        
        db_connected = True
        print("✓ MongoDB Atlas connected successfully")
    except Exception as e:
        print(f"✗ MongoDB Atlas connection failed: {e}")
        print("✓ Using fallback in-memory database for development")
        # Use fallback models
        import models_fallback as models
        from models_fallback import init_db
        db_connected = False
    
    # Store connection status in app config
    app.config['DB_CONNECTED'] = db_connected
    
    # Initialize Flask-Login
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'
    
    @login_manager.user_loader
    def load_user(user_id):
        if db_connected:
            from models import User
        else:
            from models_fallback import User
        return User.find_by_id(user_id)
    
    # Initialize database indexes
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