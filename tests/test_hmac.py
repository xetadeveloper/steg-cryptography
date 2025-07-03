import sys
import os

# Add the project root to sys.path so 'core' module is found
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from core import hmac_module  # Make sure core/ is a module (has __init__.py)

# Add your test function below here and use "python tests/test_hmac.py" to run the test
