import pusher
from flask import abort
import ssl
import subprocess
from flask_cors import CORS
import secrets
from flask import Flask, send_from_directory, request, session, redirect, url_for, jsonify, render_template, flash
import sqlite3
import os
import secrets
import re
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from time import time
from flask_socketio import SocketIO, emit
from dotenv import load_dotenv
from datetime import timedelta
from cryptography.fernet import Fernet

# Generate a key (you should store this securely and not regenerate each time)
key = Fernet.generate_key()



DATABASE = os.getenv('DATABASE_PATH', 'database.db')




app = Flask(__name__, static_folder='static', static_url_path='')
BADGE_CRITERIA = [
    {"name": "1 Day", "days": 1},
    {"name": "1 Week", "days": 7},
    {"name": "2 Weeks", "days": 14},
    {"name": "3 Weeks", "days": 21},
    {"name": "1 Month", "days": 30},
    {"name": "6 Months", "days": 180},
    {"name": "1 Year", "days": 365},
    {"name": "2 Years", "days": 730},
]

@app.route('/badges', methods=['GET'])
def get_user_badges():
    if 'user' not in session:
        return jsonify({"error": "User not logged in"}), 401

    user_id = session['user_id']
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT created_at FROM users WHERE id = ?", (user_id,))
        user_creation_date = cursor.fetchone()

        if not user_creation_date:
            return jsonify({"error": "User not found"}), 404

        user_creation_date = datetime.strptime(user_creation_date[0], "%Y-%m-%d %H:%M:%S")
        current_date = datetime.now()
        days_since_creation = (current_date - user_creation_date).days

        # Fetch earned badges
        cursor.execute("SELECT badge_name FROM user_badges WHERE user_id = ?", (user_id,))
        earned_badges = {row[0] for row in cursor.fetchall()}

        # Check and update badges
        new_badges = []
        for badge in BADGE_CRITERIA:
            if days_since_creation >= badge["days"] and badge["name"] not in earned_badges:
                new_badges.append(badge["name"])
                cursor.execute("INSERT INTO user_badges (user_id, badge_name, earned_at) VALUES (?, ?, ?)", 
                               (user_id, badge["name"], datetime.now()))
        
        conn.commit()
        earned_badges.update(new_badges)

        return jsonify({"badges": list(earned_badges)})

@app.route('/static/page.html')
def restricted_page():
    """
    Serve 'page.html' if the user is logged in; otherwise, redirect to the registration page.
    """
    if 'user' not in session:
        flash("Please log in to access this page.", "error")
        return redirect(url_for('register'))
    return send_from_directory(app.static_folder, 'page.html')

@app.before_request
def restrict_access():
    """
    Restrict access to sensitive static pages for unauthorized users.
    """
    # Protect `page.html` from unauthorized access
    if request.path.endswith('/page.html') and 'user' not in session:
        flash("Unauthorized access detected. Redirecting to registration.", "error")
        return redirect(url_for('register'))

app.config.update(
    SESSION_COOKIE_SECURE=True,  # Cookies will only be sent over HTTPS
    SESSION_COOKIE_HTTPONLY=True,  # Can't be accessed via JavaScript
    SESSION_COOKIE_SAMESITE='Strict'  # Mitigates CSRF
)

country = "IR"
city = "Tehran"
key_name = "di23n3qd405q"


private_key_file = f"{key_name}_key.pem"
certificate_file = f"{key_name}_cert.pem"


command = [
    "openssl", "req", "-x509", "-nodes", "-days", "365",
    "-newkey", "rsa:2048",
    "-keyout", private_key_file,
    "-out", certificate_file,
    "-subj", f"/C={country}/ST={city}/L={city}/O=MyOrg/OU=MyUnit/CN=localhost"
]

try:
   
    subprocess.run(command, check=True)
    print(f"Certificate and key generated successfully!")
    print(f"Private Key: {private_key_file}")
    print(f"Certificate: {certificate_file}")
except FileNotFoundError:
    print("OpenSSL is not installed or not found in your PATH.")
except subprocess.CalledProcessError as e:
    print(f"An error occurred: {e}")

def handle_request():
    vpn_ip_ranges = ["192.168.0.", "203.0.113."]
    user_ip = request.remote_addr
    if any(user_ip.startswith(vpn_range) for vpn_range in vpn_ip_ranges):
        return redirect("/vpn.html")
    return redirect("/register.html")

app.permanent_session_lifetime = timedelta(minutes=20)

load_dotenv()
app.secret_key = os.getenv('FLASK_SECRET_KEY')

pusher_client = pusher.Pusher(
    app_id=os.getenv('PUSHER_APP_ID'),
    key=os.getenv('PUSHER_KEY'),
    secret=os.getenv('PUSHER_SECRET'),
    cluster=os.getenv('PUSHER_CLUSTER'),
    ssl=True
)

app.secret_key = secrets.token_hex(16)  
CORS(app)


pusher_client = pusher.Pusher(
    app_id='1899623',  
    key='20c9ce999085eb7fa324',  
    secret='21ae289ecee69d077fc8',  
    cluster='ap1', 
    ssl=True
)

@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.get_json()
    username = data.get('username')
    message = data.get('message')

    if username and message:
        try:
           
            pusher_client.trigger('chat-channel', 'message-sent', {
                'username': username,
                'message': message
            })
            return jsonify({'success': True}), 200
        except Exception as e:
            
            print(f"Pusher Error: {e}")
            return jsonify({'error': 'Failed to send message'}), 500
    else:
        return jsonify({'error': 'Invalid data'}), 400


DATABASE = 'database.db'

def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT NOT NULL,
                            email TEXT NOT NULL UNIQUE,
                            password TEXT NOT NULL
                        )''')
        conn.commit()


init_db()


def sanitize_input(input_data):
    return input_data

def validate_username(username):
    return bool(re.match(r"^\w+$", username))

def validate_email(email):
    return bool(re.match(r"[^@]+@[^@]+\.[^@]+", email))

def hash_password(password):
    return generate_password_hash(password)

def verify_password(stored_password, provided_password):
    return check_password_hash(stored_password, provided_password)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif', 'pdf'}

def save_file(file, upload_folder):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(upload_folder, filename)
        file.save(file_path)
        return file_path
    return None


request_log = {}
RATE_LIMIT = 5
RATE_PERIOD = 60

def rate_limit(key, limit=RATE_LIMIT, period=RATE_PERIOD):
    now = time()
    if key not in request_log:
        request_log[key] = []
    request_log[key] = [timestamp for timestamp in request_log[key] if now - timestamp < period]
    if len(request_log[key]) >= limit:
        return False
    request_log[key].append(now)
    return True


@app.route('/')
def index():
    return app.send_static_file('register.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']


        if not username or not email or not password:
            return jsonify({"message": "All fields are required!"}), 400
        if not validate_username(username):
            return jsonify({"message": "Invalid username!"}), 400
        if not validate_email(email):
            return jsonify({"message": "Invalid email!"}), 400

        
        hashed_password = hash_password(password)


        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            try:
                cursor.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', 
                               (username, email, hashed_password))
                conn.commit()
                return jsonify({"message": "Registration successful!"}), 200
            except sqlite3.IntegrityError:
                return jsonify({"message": "Email already exists!"}), 400

    return app.send_static_file('register.html')

@app.route('/login', methods=['POST'])
def login():
    email = request.form['email'] 
    password = request.form['password']
    

    if not email or not password:
        return jsonify({"message": "Both email and password are required!"}), 400
    
   
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT username, password FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        
        if user and verify_password(user[1], password):
            session['user'] = user[0]  
            return jsonify({"message": "Login successful!"}), 200
        return jsonify({"message": "Invalid credentials!"}), 401

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))
@app.route('/dash')
def dash():
    if 'user' not in session:
        flash("Please log in to access the dashboard.", "error")
        return redirect(url_for('login_signup'))
    return send_from_directory(app.static_folder, 'dash.html')

@app.route('/dashboard')
def dashboard():
    return send_from_directory(app.static_folder, 'loader.html')

@app.route('/edu')
def edu():
    return send_from_directory(app.static_folder, 'exam.html')


if not os.path.exists('accounts.db'):
    conn = sqlite3.connect('accounts.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT UNIQUE,
            password TEXT,
            profile_picture TEXT
        )
    ''')
    conn.commit()
    conn.close()

@app.route('/', methods=['GET', 'POST'])
def login_signup():
    if request.method == 'POST':
        action = request.form['action']  
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        conn = sqlite3.connect('accounts.db')
        c = conn.cursor()
        
        if action == 'login':
           
            c.execute("SELECT * FROM accounts WHERE email = ?", (email,))
            account = c.fetchone()
            
            if account:
                if account[3] == password:  
                    flash('Logged in successfully!', 'success')
                    return redirect(url_for('dash', username=account[1], email=account[2], profile_picture=account[4]))
                else:
                    flash('Incorrect password.', 'error')
            else:
                flash('Account does not exist. Please sign up first.', 'error')
        
        elif action == 'signup':
            
            c.execute("SELECT * FROM accounts WHERE email = ?", (email,))
            account = c.fetchone()
            
            if account:
                flash('Account already exists. Please log in.', 'error')
            else:
                try:
                    c.execute("INSERT INTO accounts (username, email, password) VALUES (?, ?, ?)", (username, email, password))
                    conn.commit()
                    flash('Account created successfully!', 'success')
                    return redirect(url_for('dash', username=username, email=email, profile_picture=None))
                except sqlite3.IntegrityError:
                    flash('Username or email already exists.', 'error')
        
        conn.close()
    return render_template('alert.html')

@app.route('/account')
def account():
     return app.send_static_file('/static/account.html')

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'user' not in session:
        return jsonify({"error": "User not logged in"}), 401

    user = session['user']
    profile_picture = request.files.get('profile_picture')
    bio = request.form.get('bio', '')
    resume = request.files.get('resume')

    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()

        # Handle profile picture upload
        if profile_picture and allowed_file(profile_picture.filename):
            picture_filename = secure_filename(f"{user}_profile_{profile_picture.filename}")
            picture_path = os.path.join(app.config['UPLOAD_FOLDER'], picture_filename)
            profile_picture.save(picture_path)
            cursor.execute("UPDATE accounts SET profile_picture = ? WHERE username = ?", (picture_path, user))

      




context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.load_cert_chain(certfile='di23n3qd405q_cert.pem', keyfile='di23n3qd405q_key.pem')


if __name__ == "__main__":  
    from waitress import serve  
    serve(app, host="127.0.0.1", port=5000)
    