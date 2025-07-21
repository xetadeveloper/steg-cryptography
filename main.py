import os
import logging
import base64
from app import app

# Configure logging for debugging
logging.basicConfig(level=logging.DEBUG)

# Add base64 filter to Jinja2 templates
@app.template_filter('b64encode')
def base64_encode_filter(data):
    """Base64 encode filter for templates."""
    if data is None or str(data) == 'None':
        return ''
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.b64encode(data).decode('utf-8')

if __name__ == '__main__':
    # Set default session secret if not provided
    if not os.environ.get("SESSION_SECRET"):
        os.environ["SESSION_SECRET"] = "dev-secret-key-change-in-production"

    app.run(host='0.0.0.0', port=5000, debug=True)