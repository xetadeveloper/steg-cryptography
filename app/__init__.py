import os
from flask import Flask

def create_app():
    # Create Flask app with correct template and static folders
    app = Flask(__name__, 
                template_folder='../templates',
                static_folder='../static')
    app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key")
    
    # Import routes
    from app.routes import main
    app.register_blueprint(main)
    
    return app

# Create the app instance
app = create_app()
