from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import bcrypt
import os

app = Flask(__name__)
app.secret_key = 'super-secret-key-2025'

DB_FILE = 'database.db'

# ============= Fixed CSRF =============
def csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = os.urandom(24).hex()  # generate once per session
    return session['csrf_token']

app.jinja_env.globals['csrf_token'] = csrf_token  # available as {{ csrf_token() }}
# ===========================================================

def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db_connection() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user'
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

        # Create admin if not exists
        admin = conn.execute("SELECT * FROM users WHERE username = ?", ('admin',)).fetchone()
        if not admin:
            hashed = bcrypt.hashpw('password123'.encode(), bcrypt.gensalt()).decode('utf-8')
            conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                ('admin', hashed, 'admin')
            )
            conn.commit()
        else:
            # Ensure existing admin has correct role
            if admin['role'] != 'admin':
                conn.execute("UPDATE users SET role = 'admin' WHERE username = 'admin'")
                conn.commit()
# Run once
if not os.path.exists(DB_FILE):
    init_db()

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form.get('_csrf_token') != session.get('csrf_token'):
            flash('Invalid request', 'danger')
            return redirect(url_for('login'))

        username = request.form['username']
        password = request.form['password']

        with get_db_connection() as conn:
            user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user:
            stored_hash = user['password_hash']
            # ← FIX 2: if stored_hash is string → encode it, if bytes → use directly
            if isinstance(stored_hash, str):
                stored_hash = stored_hash.encode('utf-8')

            if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
                session['user_id'] = user['id']
                session['username'] = user['username']
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))

        flash('Wrong username or password', 'danger')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        csrf = request.form.get('_csrf_token') or request.form.get('token')
        if csrf != session.get('csrf_token'):
            flash('Invalid CSRF token', 'danger')
            return redirect(url_for('register'))

        username = request.form['username'].strip()
        password = request.form['password']

        if len(username) < 3 or len(password) < 6:
            flash('Username ≥3 and Password ≥6 characters required', 'danger')
            return redirect(url_for('register'))

        # ← FIX 1: convert to string before saving
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode('utf-8')

        try:
            with get_db_connection() as conn:
                conn.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, hashed)
                )
                conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already taken', 'danger')

    return render_template('register.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    username = session['username']

    with get_db_connection() as conn:
        if username == 'admin':
            # Admin sees ALL records with username
            records = conn.execute('''
                SELECT r.id, r.title, r.description, u.username 
                FROM records r
                JOIN users u ON r.user_id = u.id
                ORDER BY r.id DESC
            ''').fetchall()
        else:
            # Regular user sees only own records
            records = conn.execute('''
                SELECT r.id, r.title, r.description, 'You' as username
                FROM records r
                WHERE r.user_id = ?
                ORDER BY r.id DESC
            ''', (user_id,)).fetchall()

    return render_template('dashboard.html', records=records)
    
@app.route('/create', methods=['GET', 'POST'])
def create():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        if request.form.get('_csrf_token') != session.get('csrf_token'):
            flash('Invalid request', 'danger')
            return redirect(url_for('create'))

        title = request.form['title'].strip()
        desc = request.form['description'].strip()

        with get_db_connection() as conn:
            conn.execute("INSERT INTO records (title, description, user_id) VALUES (?, ?, ?)",
                         (title, desc, session['user_id']))
            conn.commit()
        flash('Record created!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('create.html')

@app.route('/update/<int:record_id>', methods=['GET', 'POST'])
def update(record_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    with get_db_connection() as conn:
        record = conn.execute("SELECT * FROM records WHERE id = ? AND user_id = ?",
                              (record_id, session['user_id'])).fetchone()
        if not record:
            flash('Record not found', 'danger')
            return redirect(url_for('dashboard'))

    if request.method == 'POST':
        if request.form.get('_csrf_token') != session.get('csrf_token'):
            flash('Invalid request', 'danger')
            return redirect(url_for('update', record_id=record_id))

        title = request.form['title'].strip()
        desc = request.form['description'].strip()

        with get_db_connection() as conn:
            conn.execute("UPDATE records SET title = ?, description = ? WHERE id = ?",
                         (title, desc, record_id))
            conn.commit()
        flash('Record updated!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('update.html', record=record)

@app.route('/delete/<int:record_id>')
def delete(record_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    with get_db_connection() as conn:
        conn.execute("DELETE FROM records WHERE id = ? AND user_id = ?",
                     (record_id, session['user_id']))
        conn.commit()
    flash('Record deleted!', 'success')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)
