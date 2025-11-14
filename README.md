# Vital Health Details Manager (I have no clue what's in this repo and don't have enough energy to change anything here. This repo is public cause it's a cllg project.

A Flask-based web application for managing student health records at ERC.

## Project Structure

```
|-- dbms_project/
    |-- app.py          # Main Flask application
    |-- config.py       # Configuration settings
    |-- static/         # Static files (CSS, images, etc.)
    |-- templates/      # HTML templates
    |-- schema.sql      # Database schema
```

## Setup Instructions

### 1. Clone the Repository

```bash
git clone <repository-url>
cd dbms_project
```

### 2. Create and Activate Virtual Environment

On **Linux/Mac**:
```bash
python -m venv dbmsvenv
source dbmsvenv/bin/activate
```

On **Windows**:
```powershell
python -m venv dbmsvenv
dbmsvenv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Set Up the Database

Create a MySQL database:
```sql
CREATE DATABASE student_health_manager;
```

Import the database schema:
```bash
mysql -u [username] -p student_health_manager < schema.sql
```

### 5. Configure Environment Variables
Create a `.env` file in the project root and add:
```
DB_HOST=localhost
DB_USER=your_username
DB_PASSWORD=your_password
DB_NAME=student_health_manager
SECRET_KEY=your-actual-secret-key
FLASK_DEBUG=True
```

### 6. Run the Application
```bash
python app.py
```

## Usage
Visit `http://localhost:5000/` in your browser to access the application.


