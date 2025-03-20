# Vital Health Details Manager

A Flask-based web application for managing student health records at ERC.

## Project Structure

- `app.py`: Main Flask application.
- `config.py`: Configuration settings.
- `static/`: Static files (e.g., CSS, images).
- `templates/`: HTML templates.
- `schema.sql`: Database schema.

## Setup Instructions

1. **Clone the Repository**:
   ```bash
   git clone <repository-url>
   cd dbms_project

python -m venv dbmsvenv
source dbmsvenv/bin/activate  # On Linux/Mac
# OR
dbmsvenv\Scripts\activate  # On Windows

pip install -r requirements.txt

CREATE DATABASE student_health_manager;

mysql -u [username] -p student_health_manager < schema.sql
DB_HOST=localhost
DB_USER=your_username
DB_PASSWORD=your_password
DB_NAME=student_health_manager
SECRET_KEY=your-actual-secret-key
FLASK_DEBUG=True

python app.py
