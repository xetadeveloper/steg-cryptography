import os
import sys

# Add the project root to sys.path so 'core' module is found
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core import aes_module  # Make sure core/ is a module (has __init__.py)

# Add your test function below here and use "python tests/test_encrypt.py" to run the test