import os
from flask import Flask

def create_app():
    app = Flask(__name__)
    app.secret_key = os.environ.get("SESSION_SECRET")
    
    # Import routes
    from app.routes import main
    app.register_blueprint(main)
    
    return app

# Create the app instance
app = create_app()
