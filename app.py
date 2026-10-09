import os, secrets, sqlite3
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash
from scanner import scan_url

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = os.environ.get('DATABASE_PATH', str(BASE_DIR / 'urlshield.db'))
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', 'dev-only-change-this-secret'),
    MAX_CONTENT_LENGTH=16 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get('COOKIE_SECURE', '0') == '1',
)

def get_db():
    if 'db' not in g:
        Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA foreign_keys = ON')
    return g.db

@app.teardown_appcontext
def close_db(_error=None):
    db = g.pop('db', None)
    if db is not None: db.close()

def init_db():
    db = get_db()
    db.executescript('''
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE COLLATE NOCASE,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS scans (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      url TEXT NOT NULL, verdict TEXT NOT NULL, severity TEXT NOT NULL,
      score INTEGER NOT NULL, reasons TEXT NOT NULL, created_at TEXT NOT NULL
    );
    ''')
    db.commit()

@app.before_request
def prepare_request():
    init_db()
    if 'csrf_token' not in session: session['csrf_token'] = secrets.token_urlsafe(24)

def csrf_ok():
    token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
    return bool(token and secrets.compare_digest(token, session.get('csrf_token', '')))

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get('user_id'):
            if request.path.startswith('/api/'): return jsonify(error='Login required for this feature.'), 401
            flash('Please log in to view risk score, severity, and scan history.', 'info')
            return redirect(url_for('login', next=request.path))
        return fn(*args, **kwargs)
    return wrapper

def current_user():
    if not session.get('user_id'): return None
    return get_db().execute('SELECT id,email FROM users WHERE id=?', (session['user_id'],)).fetchone()

def public_result(result):
    # Unauthenticated users get the basic verdict and explanations, never score/severity.
    return {k: result[k] for k in ('url','verdict','evidence','harm','reasons')}

def save_scan(user_id, result):
    db = get_db()
    db.execute('INSERT INTO scans(user_id,url,verdict,severity,score,reasons,created_at) VALUES(?,?,?,?,?,?,?)',
      (user_id, result['url'], result['verdict'], result['severity'], result['score'], '\n'.join(result['reasons']), datetime.now(timezone.utc).isoformat(timespec='seconds')))
    db.commit()

@app.get('/')
def home():
    return render_template('index.html', result=None, error=None, submitted_url='', user=current_user())

@app.post('/scan')
def scan():
    submitted_url = request.form.get('url', '')
    try:
        result = scan_url(submitted_url)
        user = current_user()
        if user:
            save_scan(user['id'], result)
            shown = result
        else:
            shown = public_result(result)
        return render_template('index.html', result=shown, error=None, submitted_url=submitted_url, user=user)
    except ValueError as exc:
        return render_template('index.html', result=None, error=str(exc), submitted_url=submitted_url, user=current_user()), 400

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        if not csrf_ok(): flash('Form expired. Please try again.', 'error'); return redirect(url_for('register'))
        email = request.form.get('email','').strip().lower(); password = request.form.get('password','')
        if len(email) > 254 or '@' not in email or len(password) < 8:
            flash('Enter a valid email and a password of at least 8 characters.', 'error')
        else:
            try:
                db = get_db(); cur = db.execute('INSERT INTO users(email,password_hash,created_at) VALUES(?,?,?)', (email, generate_password_hash(password), datetime.now(timezone.utc).isoformat(timespec='seconds'))); db.commit()
                session.clear(); session['user_id'] = cur.lastrowid; session['csrf_token'] = secrets.token_urlsafe(24)
                flash('Account created. Your scans can now be saved.', 'success'); return redirect(url_for('home'))
            except sqlite3.IntegrityError: flash('An account with this email already exists.', 'error')
    return render_template('auth.html', mode='register', user=current_user(), csrf_token=session['csrf_token'])

@app.route('/login', methods=['GET','POST'])
def login():
    next_url = request.args.get('next','')
    if request.method == 'POST':
        if not csrf_ok(): flash('Form expired. Please try again.', 'error'); return redirect(url_for('login'))
        email = request.form.get('email','').strip().lower(); password = request.form.get('password','')
        row = get_db().execute('SELECT id,password_hash FROM users WHERE email=?', (email,)).fetchone()
        if row and check_password_hash(row['password_hash'], password):
            session.clear(); session['user_id'] = row['id']; session['csrf_token'] = secrets.token_urlsafe(24)
            target = request.form.get('next','')
            if target.startswith('/') and not target.startswith('//'): return redirect(target)
            return redirect(url_for('home'))
        flash('Email or password is incorrect.', 'error')
    return render_template('auth.html', mode='login', user=current_user(), csrf_token=session['csrf_token'], next_url=next_url)

@app.post('/logout')
def logout():
    if not csrf_ok(): return 'Invalid CSRF token', 400
    session.clear(); return redirect(url_for('home'))

@app.get('/history')
@login_required
def history():
    rows = get_db().execute('SELECT url,verdict,severity,score,reasons,created_at FROM scans WHERE user_id=? ORDER BY id DESC LIMIT 100', (session['user_id'],)).fetchall()
    return render_template('history.html', rows=rows, user=current_user())

@app.post('/api/scan')
def api_scan():
    data = request.get_json(silent=True) or request.form
    try: result = scan_url(data.get('url',''))
    except ValueError as exc: return jsonify(error=str(exc)), 400
    user = current_user()
    if not user: return jsonify(result=public_result(result), login_required_for=['score','severity','history'])
    save_scan(user['id'], result)
    return jsonify(result=result)

@app.get('/api/history')
@login_required
def api_history():
    rows = get_db().execute('SELECT url,verdict,severity,score,reasons,created_at FROM scans WHERE user_id=? ORDER BY id DESC LIMIT 100', (session['user_id'],)).fetchall()
    return jsonify(history=[dict(r) for r in rows])

@app.get('/health')
def health(): return {'status':'ok','service':'URLShield'}, 200

@app.errorhandler(413)
def too_large(_error): return 'Request too large. Please submit a shorter URL.', 413

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT','5000')), debug=False)
