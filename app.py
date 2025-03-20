from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import mysql.connector
from config import MYSQL_CONFIG
import bcrypt  # Added bcrypt for password hashing

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Should be a strong, random secret key in production

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username, role, student_id, status):
        self.id = id
        self.username = username
        self.role = role
        self.student_id = student_id
        self.status = status

    def is_active(self):
        return self.status == 'approved'

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, role, student_id, status FROM users WHERE id = %s', (user_id,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return User(user[0], user[1], user[2], user[3], user[4])
    return None

def get_db_connection():
    return mysql.connector.connect(**MYSQL_CONFIG)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')  # Encode to bytes for bcrypt
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, password, role, student_id, status FROM users WHERE username = %s', (username,))
        user = cursor.fetchone()
        conn.close()
        if user and bcrypt.checkpw(password, user[2].encode('utf-8')):  # Check hashed password
            user_obj = User(user[0], user[1], user[3], user[4], user[5])
            if user_obj.status == 'pending':
                flash('Your admin account is awaiting approval. Please wait for an admin to approve your account.')
                return redirect(url_for('login'))
            if user_obj.status == 'rejected':
                flash('Your admin account request was rejected.')
                return redirect(url_for('login'))
            login_user(user_obj)
            if user_obj.role == 'student':
                return redirect(url_for('profile'))
            return redirect(url_for('dashboard'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')  # Encode to bytes
        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())  # Hash the password
        role = request.form['role']
        student_id = request.form.get('student_id')

        # Set status based on role
        status = 'pending' if role == 'admin' else 'approved'

        # Validate student_id for students
        if role == 'student' and not student_id:
            flash('Student ID is required for students.')
            return redirect(url_for('register'))

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('INSERT INTO users (username, password, role, student_id, status) VALUES (%s, %s, %s, %s, %s)',
                           (username, hashed_password.decode('utf-8'), role, student_id, status))  # Store as string
            conn.commit()
        except mysql.connector.Error as err:
            conn.close()
            flash(f"Error: {err}")
            return redirect(url_for('register'))
        conn.close()
        if role == 'admin':
            flash('Admin registration submitted! Awaiting approval from an existing admin.')
        else:
            flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Rest of your routes remain unchanged
@app.route('/')
def index():
    return render_template('index.html', logged_in=current_user.is_authenticated)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if current_user.role != 'admin' or current_user.status != 'approved':
        flash('Admin access only')
        return redirect(url_for('profile' if current_user.role == 'student' else 'index'))
    conn = get_db_connection()
    cursor = conn.cursor()

    # Handle search for health records
    query = request.form.get('search', '') if request.method == 'POST' else ''
    sql = 'SELECT id, student_id, name, blood_type, emergency_contact, medical_conditions FROM student_health WHERE student_id LIKE %s OR name LIKE %s'
    cursor.execute(sql, (f'%{query}%', f'%{query}%'))
    records = cursor.fetchall()

    # Fetch pending admins
    cursor.execute("SELECT id, username FROM users WHERE role = 'admin' AND status = 'pending'")
    pending_admins = cursor.fetchall()

    conn.close()
    return render_template('dashboard.html', records=records, pending_admins=pending_admins)

@app.route('/approve_admin/<int:user_id>', methods=['POST'])
@login_required
def approve_admin(user_id):
    if current_user.role != 'admin' or current_user.status != 'approved':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    action = request.form.get('action')
    if action not in ['approve', 'reject']:
        return jsonify({'success': False, 'message': 'Invalid action'}), 400
    new_status = 'approved' if action == 'approve' else 'rejected'
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE users SET status = %s WHERE id = %s AND role = 'admin'", (new_status, user_id))
        conn.commit()
        if cursor.rowcount == 0:
            return jsonify({'success': False, 'message': 'User not found or not a pending admin'}), 404
        conn.close()
        return jsonify({'success': True, 'message': f'Admin {action}d successfully!'})
    except mysql.connector.Error as err:
        conn.rollback()
        conn.close()
        return jsonify({'success': False, 'message': f"Error: {err}"}), 500

@app.route('/profile')
@login_required
def profile():
    if current_user.role != 'student':
        flash('Student access only')
        return redirect(url_for('dashboard' if current_user.role == 'admin' else 'index'))
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, student_id, name, blood_type, emergency_contact, medical_conditions FROM student_health WHERE student_id = %s',
                   (current_user.student_id,))
    record = cursor.fetchone()
    conn.close()
    return render_template('profile.html', record=record)

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_record():
    if current_user.role != 'student':
        flash('Only students can manage their own records')
        return redirect(url_for('dashboard' if current_user.role == 'admin' else 'index'))
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT id FROM student_health WHERE student_id = %s', (current_user.student_id,))
    existing_record = cursor.fetchone()
    
    if request.method == 'POST':
        student_id = current_user.student_id
        name = request.form['name']
        blood_type = request.form['blood_type']
        emergency_contact = request.form['emergency_contact']
        medical_conditions = request.form.get('medical_conditions', '')
        
        try:
            if existing_record:
                cursor.execute('UPDATE student_health SET name = %s, blood_type = %s, emergency_contact = %s, medical_conditions = %s WHERE student_id = %s',
                               (name, blood_type, emergency_contact, medical_conditions, student_id))
                conn.commit()
                flash('Your existing health record has been updated!')
            else:
                cursor.execute('INSERT INTO student_health (student_id, name, blood_type, emergency_contact, medical_conditions) VALUES (%s, %s, %s, %s, %s)',
                               (student_id, name, blood_type, emergency_contact, medical_conditions))
                conn.commit()
                flash('New health record added successfully!')
        except mysql.connector.Error as err:
            conn.rollback()
            flash(f"Error: {err}")
        conn.close()
        return redirect(url_for('profile'))
    
    conn.close()
    return render_template('add.html')

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_record(id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, student_id, name, blood_type, emergency_contact, medical_conditions FROM student_health WHERE id = %s', (id,))
    record = cursor.fetchone()
    if not record:
        conn.close()
        flash('Record not found')
        return redirect(url_for('dashboard' if current_user.role == 'admin' else 'profile'))
    if current_user.role == 'student' and record[1] != current_user.student_id:
        conn.close()
        flash('You can only edit your own record')
        return redirect(url_for('profile'))
    if request.method == 'POST':
        student_id = request.form['student_id']
        name = request.form['name']
        blood_type = request.form['blood_type']
        emergency_contact = request.form['emergency_contact']
        medical_conditions = request.form.get('medical_conditions', '')
        try:
            cursor.execute('UPDATE student_health SET student_id = %s, name = %s, blood_type = %s, emergency_contact = %s, medical_conditions = %s WHERE id = %s',
                           (student_id, name, blood_type, emergency_contact, medical_conditions, id))
            conn.commit()
            flash('Record updated successfully!')
        except mysql.connector.Error as err:
            conn.close()
            flash(f"Error: {err}")
            return redirect(url_for('edit_record', id=id))
        conn.close()
        return redirect(url_for('dashboard' if current_user.role == 'admin' else 'profile'))
    conn.close()
    return render_template('edit.html', record=record)

@app.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete_record(id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT student_id FROM student_health WHERE id = %s', (id,))
    record = cursor.fetchone()
    if not record:
        conn.close()
        return jsonify({'success': False, 'message': 'Record not found'}), 404
    if current_user.role == 'student' and record[0] != current_user.student_id:
        conn.close()
        return jsonify({'success': False, 'message': 'You can only delete your own record'}), 403
    try:
        cursor.execute('DELETE FROM student_health WHERE id = %s', (id,))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'Record deleted successfully!'})
    except mysql.connector.Error as err:
        conn.rollback()
        conn.close()
        return jsonify({'success': False, 'message': f"Error: {err}"}), 500

if __name__ == '__main__':
    app.run(debug=True)