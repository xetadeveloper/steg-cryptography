import os
import logging
from app import app

# Configure logging for debugging
logging.basicConfig(level=logging.DEBUG)

if __name__ == '__main__':
    # Set default session secret if not provided
    if not os.environ.get("SESSION_SECRET"):
        os.environ["SESSION_SECRET"] = "dev-secret-key-change-in-production"
    
    app.run(host='0.0.0.0', port=5000, debug=True)
