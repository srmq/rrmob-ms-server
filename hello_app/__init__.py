import logging
import sys
from flask import Flask  # Import the Flask class
app = Flask(__name__, static_folder='static/recommender-effects/dist')    # Create an instance of the class for our use

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)