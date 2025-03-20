# config.py
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Flask application settings
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key")
DEBUG = os.getenv("FLASK_DEBUG", "True") == "True"

# MySQL database configuration
MYSQL_CONFIG = {
    'user': os.getenv("DB_USER", "root"),
    'password': os.getenv("DB_PASSWORD", ""),
    'host': os.getenv("DB_HOST", "localhost"),
    'database': os.getenv("DB_NAME", "student_health_manager")
}