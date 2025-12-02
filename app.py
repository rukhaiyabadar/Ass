from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'super_secret_key'  # Weak hardcoded secret for sessions (vulnerable)

# Database file path
DB_FILE = 'database.db'

# Function to get database connection
def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row  # To return rows as dicts
    return conn

# Initialize database (will be called later)
def init_db():
    with get_db_connection() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL  -- Stored as plain text (vulnerable)
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        # Seed a default user (username: admin, password: password - plain text)
        try:
            conn.execute("INSERT INTO users (username, password) VALUES ('admin', 'password')")
            conn.commit()
        except sqlite3.IntegrityError:
            pass  # User already exists

# Run init_db when app starts (for simplicity)
if not os.path.exists(DB_FILE):
    init_db()

# Home route (placeholder for now)
# @app.route('/')
# def index():
#     return 'App is running!'
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))
# Dashboard: Read all records
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Vulnerable: but no injection here yet (fetch all)
    with get_db_connection() as conn:
        records = conn.execute('SELECT * FROM records').fetchall()
    
    return render_template('dashboard.html', records=records)

# Create record
@app.route('/create', methods=['GET', 'POST'])
def create():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        user_id = session['user_id']
        
        # Vulnerable to SQL injection
        query = f"INSERT INTO records (title, description, user_id) VALUES ('{title}', '{description}', {user_id})"
        with get_db_connection() as conn:
            conn.execute(query)
            conn.commit()
        flash('Record created!')
        return redirect(url_for('dashboard'))
    
    return render_template('create.html')

# Update record
@app.route('/update/<int:record_id>', methods=['GET', 'POST'])
def update(record_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        
        # Vulnerable to SQL injection, no ownership check
        query = f"UPDATE records SET title = '{title}', description = '{description}' WHERE id = {record_id}"
        with get_db_connection() as conn:
            conn.execute(query)
            conn.commit()
        flash('Record updated!')
        return redirect(url_for('dashboard'))
    
    # Fetch record (vulnerable via ID, but int cast helps slightly)
    with get_db_connection() as conn:
        record = conn.execute(f'SELECT * FROM records WHERE id = {record_id}').fetchone()
    if not record:
        flash('Record not found')
        return redirect(url_for('dashboard'))
    
    return render_template('update.html', record=record)

# Delete record
@app.route('/delete/<int:record_id>')
def delete(record_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Vulnerable to SQL injection via ID (though int cast), no ownership check
    query = f"DELETE FROM records WHERE id = {record_id}"
    with get_db_connection() as conn:
        conn.execute(query)
        conn.commit()
    flash('Record deleted!')
    return redirect(url_for('dashboard'))
# Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Vulnerable to SQL injection: raw concatenation
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        with get_db_connection() as conn:
            user = conn.execute(query).fetchone()
        
        if user:
            session['user_id'] = user['id']
            flash('Login successful!')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials')
    
    return render_template('login.html')

# Logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out')
    return redirect(url_for('login'))

# Registration (vulnerable similarly, optional but added for completeness)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Vulnerable to SQL injection
        query = f"INSERT INTO users (username, password) VALUES ('{username}', '{password}')"
        try:
            with get_db_connection() as conn:
                conn.execute(query)
                conn.commit()
            flash('Registration successful! Please login.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists')
    
    return render_template('register.html')
if __name__ == '__main__':
    app.run(debug=True)