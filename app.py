from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import sqlite3
import os
import io
import csv
from datetime import datetime
import bcrypt
import face_recognition
import numpy as np
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from werkzeug.exceptions import BadRequestKeyError
from base64 import b64decode
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
app.secret_key = 'supersecretkey123'  # Ensure secret key is set for session management

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Ensure images directory exists
if not os.path.exists('static/images'):
    os.makedirs('static/images')

# Database connection with timeout
def get_db_connection():
    conn = sqlite3.connect('attendance.db', timeout=10)
    conn.row_factory = sqlite3.Row
    logging.debug("Opened database connection")
    return conn

# Initialize database with schema check
def init_db():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        logging.debug("Initializing database")
        
        # Create tables
        cursor.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                login_id TEXT UNIQUE NOT NULL,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS students (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER UNIQUE NOT NULL,
                login_id TEXT UNIQUE NOT NULL,
                face_encoding BLOB NOT NULL,
                image_path TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            );
            CREATE TABLE IF NOT EXISTS attendance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                login_id TEXT NOT NULL,
                date TEXT NOT NULL,
                time TEXT NOT NULL,
                status TEXT NOT NULL,
                FOREIGN KEY (login_id) REFERENCES students (login_id)
            );
        ''')

        # Check if attendance table has login_id column
        cursor.execute("PRAGMA table_info(attendance)")
        columns = [col['name'] for col in cursor.fetchall()]
        if 'login_id' not in columns and 'student_id' in columns:
            logging.info("Migrating attendance table: replacing student_id with login_id")
            cursor.execute('ALTER TABLE attendance RENAME TO attendance_old')
            cursor.execute('''
                CREATE TABLE attendance (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    login_id TEXT NOT NULL,
                    date TEXT NOT NULL,
                    time TEXT NOT NULL,
                    status TEXT NOT NULL,
                    FOREIGN KEY (login_id) REFERENCES students (login_id)
                )
            ''')
            cursor.execute('INSERT INTO attendance (id, login_id, date, time, status) SELECT id, student_id, date, time, status FROM attendance_old')
            cursor.execute('DROP TABLE attendance_old')
            logging.info("Migration completed")

        # Add default admin
        default_login_id = 'admin1'
        default_username = 'Admin'
        default_password = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt())
        cursor.execute('SELECT * FROM users WHERE login_id = ?', (default_login_id,))
        if not cursor.fetchone():
            cursor.execute('INSERT INTO users (login_id, username, password, role) VALUES (?, ?, ?, ?)',
                           (default_login_id, default_username, default_password, 'admin'))
            logging.info(f"Added default admin: {default_login_id}")

        # Add example student to users table
        student_login_id = '2329122'
        student_username = 'harsh'
        student_password = bcrypt.hashpw('12345'.encode('utf-8'), bcrypt.gensalt())
        cursor.execute('SELECT * FROM users WHERE login_id = ?', (student_login_id,))
        if not cursor.fetchone():
            cursor.execute('INSERT INTO users (login_id, username, password, role) VALUES (?, ?, ?, ?)',
                           (student_login_id, student_username, student_password, 'student'))
            logging.info(f"Added example student: {student_login_id}")

        conn.commit()
        logging.debug("Database initialized successfully")

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, login_id, username, role):
        self.id = id
        self.login_id = login_id
        self.username = username
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    with get_db_connection() as conn:
        user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        logging.debug(f"Loaded user ID: {user_id}")
        if user:
            return User(user['id'], user['login_id'], user['username'], user['role'])
        return None

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            login_id = request.form['login_id']
            password = request.form['password']
            logging.debug(f"Login attempt for login_id: {login_id}")
        except BadRequestKeyError:
            flash('Missing Login ID or password', 'danger')
            logging.error("BadRequestKeyError in login form")
            return render_template('login.html')
        
        with get_db_connection() as conn:
            user = conn.execute('SELECT * FROM users WHERE login_id = ?', (login_id,)).fetchone()
            if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
                login_user(User(user['id'], user['login_id'], user['username'], user['role']))
                logging.info(f"Successful login for {login_id} as {user['role']}")
                if user['role'] == 'admin':
                    return redirect(url_for('admin_dashboard'))
                else:
                    return redirect(url_for('student_dashboard'))
            flash('Invalid login ID or password', 'danger')
            logging.warning(f"Failed login attempt for {login_id}")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    try:
        user_id = current_user.login_id
        logout_user()
        flash('Logged out successfully', 'success')
        logging.info(f"User {user_id} logged out successfully")
        return redirect(url_for('login'))
    except Exception as e:
        logging.error(f"Error during logout: {str(e)}")
        flash(f'Error logging out: {str(e)}', 'danger')
        return redirect(url_for('index'))

@app.route('/register_student', methods=['GET', 'POST'])
@login_required
def register_student():
    if current_user.role != 'admin':
        flash('Unauthorized access', 'danger')
        logging.warning(f"Unauthorized access attempt by {current_user.login_id}")
        return redirect(url_for('login'))
    if request.method == 'POST':
        try:
            login_id = request.form['login_id']
            username = request.form['username']
            password = bcrypt.hashpw(request.form['password'].encode('utf-8'), bcrypt.gensalt())
            image_data = request.form['image'].split(',')[1]
            logging.debug(f"Registering student: {login_id}")
            
            image_bytes = b64decode(image_data)
            image_path = os.path.join('static', 'images', f"{login_id}.jpg")
            with open(image_path, 'wb') as f:
                f.write(image_bytes)

            img = face_recognition.load_image_file(image_path)
            encodings = face_recognition.face_encodings(img)
            if not encodings:
                flash('No face detected in the image', 'danger')
                logging.error(f"No face detected for {login_id}")
                return render_template('register_student.html')
            encoding = encodings[0]

            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('INSERT INTO users (login_id, username, password, role) VALUES (?, ?, ?, ?)',
                               (login_id, username, password, 'student'))
                user_id = cursor.lastrowid
                cursor.execute('INSERT INTO students (user_id, login_id, face_encoding, image_path) VALUES (?, ?, ?, ?)',
                               (user_id, login_id, encoding.tobytes(), image_path))
                conn.commit()
                logging.info(f"Successfully registered student: {login_id}")
            flash('Student registered successfully', 'success')
            return redirect(url_for('admin_dashboard'))
        except sqlite3.OperationalError as e:
            flash(f'Database error: {str(e)}', 'danger')
            logging.error(f"Database error during registration: {str(e)}")
        except sqlite3.IntegrityError:
            flash('Login ID or username already exists', 'danger')
            logging.error(f"IntegrityError: Login ID {login_id} or username {username} already exists")
        except BadRequestKeyError:
            flash('Missing required fields or image', 'danger')
            logging.error("BadRequestKeyError in registration form")
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')
            logging.error(f"Unexpected error during registration: {str(e)}")
    return render_template('register_student.html')

@app.route('/edit_student/<login_id>', methods=['GET', 'POST'])
@login_required
def edit_student(login_id):
    if current_user.role != 'admin':
        flash('Unauthorized access', 'danger')
        logging.warning(f"Unauthorized access attempt by {current_user.login_id}")
        return redirect(url_for('login'))
    with get_db_connection() as conn:
        student = conn.execute('SELECT s.*, u.username FROM students s JOIN users u ON s.user_id = u.id WHERE s.login_id = ?', (login_id,)).fetchone()
        if not student:
            flash('Student not found', 'danger')
            logging.error(f"Student not found: {login_id}")
            return redirect(url_for('admin_dashboard'))
        if request.method == 'POST':
            try:
                username = request.form['username']
                conn.execute('UPDATE users SET username = ? WHERE login_id = ?', (username, login_id))
                conn.commit()
                flash('Student updated successfully', 'success')
                logging.info(f"Updated student: {login_id}")
                return redirect(url_for('admin_dashboard'))
            except BadRequestKeyError:
                flash('Missing required fields', 'danger')
                logging.error("BadRequestKeyError in edit student form")
    return render_template('edit_student.html', student=student)

@app.route('/delete_student/<login_id>')
@login_required
def delete_student(login_id):
    if current_user.role != 'admin':
        flash('Unauthorized access', 'danger')
        logging.warning(f"Unauthorized access attempt by {current_user.login_id}")
        return redirect(url_for('login'))
    with get_db_connection() as conn:
        student = conn.execute('SELECT user_id FROM students WHERE login_id = ?', (login_id,)).fetchone()
        if student:
            conn.execute('DELETE FROM students WHERE login_id = ?', (login_id,))
            conn.execute('DELETE FROM users WHERE id = ?', (student['user_id'],))
            conn.commit()
            flash('Student deleted successfully', 'success')
            logging.info(f"Deleted student: {login_id}")
        else:
            flash('Student not found', 'danger')
            logging.error(f"Student not found for deletion: {login_id}")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Unauthorized access', 'danger')
        logging.warning(f"Unauthorized access attempt by {current_user.login_id}")
        return redirect(url_for('login'))
    with get_db_connection() as conn:
        students = conn.execute('SELECT s.*, u.username FROM students s JOIN users u ON s.user_id = u.id').fetchall()
        today = datetime.now().strftime('%Y-%m-%d')
        try:
            attendance_today = conn.execute('''
                SELECT a.id, a.login_id, a.date, a.time, a.status, u.username
                FROM attendance a
                JOIN users u ON a.login_id = u.login_id
                WHERE a.date = ?
            ''', (today,)).fetchall()
        except sqlite3.OperationalError as e:
            flash(f'Database error: {str(e)}', 'danger')
            logging.error(f"Database error in admin_dashboard: {str(e)}")
            attendance_today = []
    return render_template('admin_dashboard.html', students=students, attendance_today=attendance_today)

@app.route('/student_dashboard')
@login_required
def student_dashboard():
    if current_user.role != 'student':
        flash('Unauthorized access', 'danger')
        logging.warning(f"Unauthorized access attempt by {current_user.login_id}")
        return redirect(url_for('login'))
    with get_db_connection() as conn:
        student = conn.execute('SELECT s.*, u.username FROM students s JOIN users u ON s.user_id = u.id WHERE s.user_id = ?', (current_user.id,)).fetchone()
        attendance = conn.execute('SELECT * FROM attendance a WHERE a.login_id = ? ORDER BY a.date DESC',
                                 (student['login_id'],)).fetchall()
        total_days = len(attendance)
        present_days = len([record for record in attendance if record['status'] == 'Present'])
        attendance_percentage = (present_days / total_days * 100) if total_days > 0 else 0
    return render_template('student_dashboard.html', student=student, attendance=attendance, attendance_percentage=attendance_percentage, total_days=total_days, present_days=present_days)

@app.route('/attendance')
@login_required
def attendance():
    if current_user.role != 'admin':
        flash('Unauthorized access', 'danger')
        logging.warning(f"Unauthorized access attempt by {current_user.login_id}")
        return redirect(url_for('login'))
    return render_template('attendance.html')

@app.route('/recognize', methods=['POST'])
@login_required
def recognize():
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    try:
        image_data = request.form['image'].split(',')[1]
        image_bytes = b64decode(image_data)
        image_path = os.path.join('static', 'images', 'temp.jpg')
        with open(image_path, 'wb') as f:
            f.write(image_bytes)

        image = face_recognition.load_image_file(image_path)
        unknown_encodings = face_recognition.face_encodings(image)
        if not unknown_encodings:
            logging.error("No face detected in recognition image")
            return jsonify({'error': 'No face detected'}), 400
        unknown_encoding = unknown_encodings[0]
        
        with get_db_connection() as conn:
            students = conn.execute('SELECT s.login_id, u.username, s.face_encoding FROM students s JOIN users u ON s.user_id = u.id').fetchall()
            
            known_encodings = [np.frombuffer(student['face_encoding'], dtype=np.float64) for student in students]
            known_ids = [student['login_id'] for student in students]
            known_names = [student['username'] for student in students]
            
            matches = face_recognition.compare_faces(known_encodings, unknown_encoding, tolerance=0.6)
            if True in matches:
                match_index = matches.index(True)
                login_id = known_ids[match_index]
                name = known_names[match_index]
                
                today = datetime.now().strftime('%Y-%m-%d')
                existing = conn.execute('SELECT * FROM attendance a WHERE a.login_id = ? AND a.date = ?',
                                       (login_id, today)).fetchone()
                if not existing:
                    cursor = conn.cursor()
                    cursor.execute('INSERT INTO attendance (login_id, date, time, status) VALUES (?, ?, ?, ?)',
                                  (login_id, today, datetime.now().strftime('%H:%M:%S'), 'Present'))
                    conn.commit()
                    logging.info(f"Marked attendance for {login_id}")
                return jsonify({'login_id': login_id, 'name': name, 'status': 'Attendance marked as Present'})
            logging.warning("Face not recognized")
            return jsonify({'error': 'Face not recognized'}), 404
    except BadRequestKeyError:
        logging.error("BadRequestKeyError in recognize route")
        return jsonify({'error': 'Missing image data'}), 400
    except Exception as e:
        logging.error(f"Unexpected error in recognize: {str(e)}")
        return jsonify({'error': f'Server error: {str(e)}'}), 500

@app.route('/export_attendance')
@login_required
def export_attendance():
    if current_user.role != 'admin':
        flash('Unauthorized access', 'danger')
        logging.warning(f"Unauthorized access attempt by {current_user.login_id}")
        return redirect(url_for('login'))
    with get_db_connection() as conn:
        attendance = conn.execute('SELECT u.username, a.login_id, a.date, a.time, a.status FROM attendance a JOIN users u ON a.login_id = u.login_id ORDER BY a.date DESC').fetchall()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Username', 'Login ID', 'Date', 'Time', 'Status'])
    for record in attendance:
        writer.writerow([record['username'], record['login_id'], record['date'], record['time'], record['status']])
    
    output.seek(0)
    logging.info("Exported attendance CSV")
    return send_file(io.BytesIO(output.getvalue().encode('utf-8')),
                     mimetype='text/csv',
                     as_attachment=True,
                     download_name='attendance_logs.csv')

@app.route('/download_report')
@login_required
def download_report():
    if current_user.role != 'student':
        flash('Unauthorized access', 'danger')
        logging.warning(f"Unauthorized access attempt by {current_user.login_id}")
        return redirect(url_for('login'))
    with get_db_connection() as conn:
        student = conn.execute('SELECT s.*, u.username FROM students s JOIN users u ON s.user_id = u.id WHERE s.user_id = ?', (current_user.id,)).fetchone()
        attendance = conn.execute('SELECT * FROM attendance a WHERE a.login_id = ? ORDER BY a.date DESC',
                                 (student['login_id'],)).fetchall()
        total_days = len(attendance)
        present_days = len([record for record in attendance if record['status'] == 'Present'])
        attendance_percentage = (present_days / total_days * 100) if total_days > 0 else 0
    
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    p.setFont("Helvetica", 12)
    p.drawString(100, 750, f"Attendance Report for {student['username']} ({student['login_id']})")
    p.drawString(100, 730, f"Attendance Percentage: {attendance_percentage:.2f}%")
    y = 710
    for record in attendance:
        p.drawString(100, y, f"{record['date']} - {record['time']} - {record['status']}")
        y -= 20
    p.showPage()
    p.save()
    buffer.seek(0)
    logging.info(f"Generated attendance report for {student['login_id']}")
    return send_file(buffer, as_attachment=True, download_name='attendance_report.pdf', mimetype='application/pdf')

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)