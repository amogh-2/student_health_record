from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import mysql.connector
from config import MYSQL_CONFIG
import bcrypt

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username, role, student_id, status, address=None, guardian_name=None, guardian_contact=None):
        self.id = id
        self.username = username
        self.role = role
        self.student_id = student_id
        self.status = status
        self.address = address
        self.guardian_name = guardian_name
        self.guardian_contact = guardian_contact

    def is_active(self):
        return self.status == 'approved'

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT u.id, u.username, u.role, u.student_id, u.status, 
               ud.address, ud.guardian_name, ud.guardian_contact 
        FROM users u 
        LEFT JOIN user_details ud ON u.id = ud.user_id 
        WHERE u.id = %s
    ''', (user_id,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return User(user[0], user[1], user[2], user[3], user[4], user[5], user[6], user[7])
    return None

def get_db_connection():
    return mysql.connector.connect(**MYSQL_CONFIG)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, password, role, student_id, status FROM users WHERE username = %s', (username,))
        user = cursor.fetchone()
        conn.close()
        if user and bcrypt.checkpw(password, user[2].encode('utf-8')):
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
        password = request.form.get('password')  # Use .get() to avoid KeyError
        role = request.form['role']
        student_id = request.form.get('student_id')

        # Validate password
        if not password:
            flash('Password is required.')
            return redirect(url_for('register'))

        password = password.encode('utf-8')
        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
        status = 'pending' if role == 'admin' else 'approved'

        if role == 'student' and not student_id:
            flash('Student ID is required for students.')
            return redirect(url_for('register'))

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('INSERT INTO users (username, password, role, student_id, status) VALUES (%s, %s, %s, %s, %s)',
                           (username, hashed_password.decode('utf-8'), role, student_id, status))
            conn.commit()
        except mysql.connector.Error as err:
            conn.rollback()
            if err.errno == 1062:  # Duplicate entry error
                if 'student_id' in str(err):
                    flash('This student ID is already in use.')
                elif 'username' in str(err):
                    flash('This username is already taken.')
                else:
                    flash(f"Error: {err}")
            else:
                flash(f"Error: {err}")
            return redirect(url_for('register'))
        finally:
            conn.close()
        
        if role == 'admin':
            flash('Admin registration submitted! Awaiting approval.')
        else:
            flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

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

    query = request.form.get('search', '') if request.method == 'POST' else ''
    sql = '''
        SELECT sh.id, sh.student_id, sh.name, sh.blood_type, sh.emergency_contact, sh.medical_conditions,
               ud.address, ud.guardian_name, ud.guardian_contact
        FROM student_health sh
        LEFT JOIN user_details ud ON sh.student_id = (SELECT student_id FROM users WHERE id = ud.user_id)
        WHERE sh.student_id LIKE %s OR sh.name LIKE %s
    '''
    cursor.execute(sql, (f'%{query}%', f'%{query}%'))
    records = cursor.fetchall()

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
        return jsonify({'success': True, 'message': f'Admin {action}d successfully!'})
    except mysql.connector.Error as err:
        conn.rollback()
        return jsonify({'success': False, 'message': f"Error: {err}"}), 500
    finally:
        conn.close()

@app.route('/profile')
@login_required
def profile():
    if current_user.role != 'student':
        flash('Student access only')
        return redirect(url_for('dashboard' if current_user.role == 'admin' else 'index'))
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT sh.id, sh.student_id, sh.name, sh.blood_type, sh.emergency_contact, sh.medical_conditions,
               ud.address, ud.guardian_name, ud.guardian_contact
        FROM student_health sh
        LEFT JOIN user_details ud ON sh.student_id = (SELECT student_id FROM users WHERE id = ud.user_id)
        WHERE sh.student_id = %s
    ''', (current_user.student_id,))
    record = cursor.fetchone()
    conn.close()
    return render_template('profile.html', record=record, user=current_user)

@app.route('/manage_profile', methods=['GET', 'POST'])
@login_required
def manage_profile():
    if current_user.role != 'student':
        flash('Only students can manage their own profile')
        return redirect(url_for('dashboard' if current_user.role == 'admin' else 'index'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT sh.id, sh.student_id, sh.name, sh.blood_type, sh.emergency_contact, sh.medical_conditions,
               ud.address, ud.guardian_name, ud.guardian_contact
        FROM student_health sh
        LEFT JOIN user_details ud ON sh.student_id = (SELECT student_id FROM users WHERE id = ud.user_id)
        WHERE sh.student_id = %s
    ''', (current_user.student_id,))
    record = cursor.fetchone()
    
    if request.method == 'POST':
        # Personal details
        address = request.form['address']
        guardian_name = request.form['guardian_name']
        guardian_contact = request.form['guardian_contact']
        
        # Health record details
        name = request.form['name']
        blood_type = request.form['blood_type']
        emergency_contact = request.form['emergency_contact']
        medical_conditions = request.form.get('medical_conditions', '')
        
        try:
            # Update or insert personal details
            cursor.execute('SELECT user_id FROM user_details WHERE user_id = %s', (current_user.id,))
            exists = cursor.fetchone()
            if exists:
                cursor.execute('UPDATE user_details SET address = %s, guardian_name = %s, guardian_contact = %s WHERE user_id = %s',
                              (address, guardian_name, guardian_contact, current_user.id))
            else:
                cursor.execute('INSERT INTO user_details (user_id, address, guardian_name, guardian_contact) VALUES (%s, %s, %s, %s)',
                              (current_user.id, address, guardian_name, guardian_contact))
            
            # Update or insert health record
            if record:
                cursor.execute('UPDATE student_health SET name = %s, blood_type = %s, emergency_contact = %s, medical_conditions = %s WHERE student_id = %s',
                              (name, blood_type, emergency_contact, medical_conditions, current_user.student_id))
                flash('Profile updated successfully!')
            else:
                cursor.execute('INSERT INTO student_health (student_id, name, blood_type, emergency_contact, medical_conditions) VALUES (%s, %s, %s, %s, %s)',
                              (current_user.student_id, name, blood_type, emergency_contact, medical_conditions))
                flash('Profile created successfully!')
            
            conn.commit()
            
            # Update current_user object
            current_user.address = address
            current_user.guardian_name = guardian_name
            current_user.guardian_contact = guardian_contact
            
        except mysql.connector.Error as err:
            conn.rollback()
            flash(f"Error: {err}")
        finally:
            conn.close()
        return redirect(url_for('profile'))
    
    conn.close()
    return render_template('manage_profile.html', record=record, user=current_user)

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
        return jsonify({'success': True, 'message': 'Record deleted successfully!'})
    except mysql.connector.Error as err:
        conn.rollback()
        return jsonify({'success': False, 'message': f"Error: {err}"}), 500
    finally:
        conn.close()

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password'].encode('utf-8')
        new_password = request.form['new_password'].encode('utf-8')
        confirm_password = request.form['confirm_password'].encode('utf-8')

        if new_password != confirm_password:
            flash('New passwords do not match')
            return redirect(url_for('change_password'))

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT password FROM users WHERE id = %s', (current_user.id,))
        stored_password = cursor.fetchone()[0]
        
        if not bcrypt.checkpw(current_password, stored_password.encode('utf-8')):
            conn.close()
            flash('Current password is incorrect')
            return redirect(url_for('change_password'))

        hashed_new_password = bcrypt.hashpw(new_password, bcrypt.gensalt())
        try:
            cursor.execute('UPDATE users SET password = %s WHERE id = %s',
                          (hashed_new_password.decode('utf-8'), current_user.id))
            conn.commit()
            flash('Password updated successfully!')
        except mysql.connector.Error as err:
            conn.rollback()
            flash(f"Error updating password: {err}")
        finally:
            conn.close()
        
        return redirect(url_for('profile' if current_user.role == 'student' else 'dashboard'))
    
    return render_template('change_password.html')

if __name__ == '__main__':
    app.run(debug=True)