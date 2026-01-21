from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import sqlite3
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

DATABASE = 'career_pathway.db'

def get_db():
    """Get database connection"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database with tables"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL,
            school TEXT,
            venue TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Parent-child relationships table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS parent_child (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            parent_id INTEGER NOT NULL,
            child_name TEXT NOT NULL,
            child_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (parent_id) REFERENCES users(id),
            FOREIGN KEY (child_id) REFERENCES users(id)
        )
    ''')
    
    # Student profiles table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS student_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            school TEXT,
            venue TEXT,
            career_interests TEXT,
            skills TEXT,
            achievements TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    conn.commit()
    conn.close()

def login_required(f):
    """Decorator to require login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_visible_students(user_id, role, school=None, venue=None):
    """Get students visible to the current user based on role"""
    conn = get_db()
    cursor = conn.cursor()
    
    if role == 'Student':
        # Students see only their own profile
        cursor.execute('''
            SELECT u.id, u.name, u.email, u.school, sp.venue, sp.career_interests, sp.skills, sp.achievements
            FROM users u
            LEFT JOIN student_profiles sp ON u.id = sp.user_id
            WHERE u.id = ? AND u.role = 'Student'
        ''', (user_id,))
    
    elif role == 'Teacher':
        # Teachers see students from their school
        cursor.execute('''
            SELECT u.id, u.name, u.email, u.school, sp.venue, sp.career_interests, sp.skills, sp.achievements
            FROM users u
            LEFT JOIN student_profiles sp ON u.id = sp.user_id
            WHERE u.role = 'Student' AND (u.school = ? OR sp.school = ?)
            ORDER BY u.name
        ''', (school, school))
    
    elif role == 'Supervisor' or role == 'Venue':
        # Supervisors/Venue owners see students assigned to their venue
        cursor.execute('''
            SELECT u.id, u.name, u.email, u.school, sp.venue, sp.career_interests, sp.skills, sp.achievements
            FROM users u
            LEFT JOIN student_profiles sp ON u.id = sp.user_id
            WHERE u.role = 'Student' AND sp.venue = ?
            ORDER BY u.name
        ''', (venue,))
    
    elif role == 'Parent':
        # Parents see only their own children
        cursor.execute('''
            SELECT u.id, u.name, u.email, u.school, sp.venue, sp.career_interests, sp.skills, sp.achievements
            FROM users u
            LEFT JOIN student_profiles sp ON u.id = sp.user_id
            INNER JOIN parent_child pc ON u.id = pc.child_id
            WHERE pc.parent_id = ? AND u.role = 'Student'
            ORDER BY u.name
        ''', (user_id,))
    
    else:
        students = []
        conn.close()
        return students
    
    students = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return students

@app.route('/')
def index():
    """Home page"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['name'] = user['name']
            session['role'] = user['role']
            session['school'] = user['school']
            session['venue'] = user['venue'] if 'venue' in user.keys() else None
            flash(f'Welcome back, {user["name"]}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registration page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        name = request.form.get('name')
        email = request.form.get('email')
        role = request.form.get('role')
        school = request.form.get('school')
        venue = request.form.get('venue', '')
        child_name = request.form.get('child_name', '')
        
        # Validate required fields
        if not all([username, password, name, email, role]):
            flash('Please fill in all required fields.', 'error')
            return render_template('register.html')
        
        # Validate password length
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return render_template('register.html')
        
        # For parents, child name is required
        if role == 'Parent' and not child_name:
            flash('Please enter your child\'s name.', 'error')
            return render_template('register.html')
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Check if username already exists
        cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
        if cursor.fetchone():
            flash('Username already exists. Please choose another.', 'error')
            conn.close()
            return render_template('register.html')
        
        # Hash password and insert user
        hashed_password = generate_password_hash(password)
        
        try:
            cursor.execute('''
                INSERT INTO users (username, password, name, email, role, school, venue)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (username, hashed_password, name, email, role, school, venue))
            
            user_id = cursor.lastrowid
            
            # If student, create profile
            if role == 'Student':
                cursor.execute('''
                    INSERT INTO student_profiles (user_id, school, venue)
                    VALUES (?, ?, ?)
                ''', (user_id, school, venue))
            
            # If parent, store child name for later matching
            if role == 'Parent' and child_name:
                # Try to find existing student with matching name
                cursor.execute('''
                    SELECT id FROM users WHERE name = ? AND role = 'Student'
                ''', (child_name,))
                child = cursor.fetchone()
                
                if child:
                    cursor.execute('''
                        INSERT INTO parent_child (parent_id, child_name, child_id)
                        VALUES (?, ?, ?)
                    ''', (user_id, child_name, child['id']))
                else:
                    # Store child name for future matching
                    cursor.execute('''
                        INSERT INTO parent_child (parent_id, child_name)
                        VALUES (?, ?)
                    ''', (user_id, child_name))
            
            conn.commit()
            conn.close()
            
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        
        except Exception as e:
            conn.rollback()
            conn.close()
            flash(f'An error occurred: {str(e)}', 'error')
            return render_template('register.html')
    
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard page - shows students based on role"""
    user_id = session.get('user_id')
    role = session.get('role')
    school = session.get('school')
    venue = session.get('venue')
    
    students = get_visible_students(user_id, role, school, venue)
    
    return render_template('dashboard.html', 
                         students=students,
                         role=role,
                         name=session.get('name'))

@app.route('/profile/<int:student_id>')
@login_required
def student_profile(student_id):
    """View student profile"""
    user_id = session.get('user_id')
    role = session.get('role')
    school = session.get('school')
    venue = session.get('venue')
    
    # Get visible students to check access
    visible_students = get_visible_students(user_id, role, school, venue)
    visible_ids = [s['id'] for s in visible_students]
    
    if student_id not in visible_ids:
        flash('You do not have permission to view this profile.', 'error')
        return redirect(url_for('dashboard'))
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT u.id, u.name, u.email, u.school, sp.venue, sp.career_interests, sp.skills, sp.achievements
        FROM users u
        LEFT JOIN student_profiles sp ON u.id = sp.user_id
        WHERE u.id = ?
    ''', (student_id,))
    student = cursor.fetchone()
    conn.close()
    
    if not student:
        flash('Student not found.', 'error')
        return redirect(url_for('dashboard'))
    
    return render_template('profile.html', student=dict(student))

@app.route('/logout')
def logout():
    """Logout"""
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/forgot-password')
def forgot_password():
    """Forgot password page (placeholder)"""
    flash('Password reset functionality coming soon. Please contact an administrator.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
