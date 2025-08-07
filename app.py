import subprocess
import bcrypt
from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file, session
from io import BytesIO
import random
import os
import string
import time
import socket
import smtplib
import dns.resolver
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine, Column, String, DateTime, Integer
from sqlalchemy.orm import declarative_base, sessionmaker
import pandas as pd
from dotenv import load_dotenv
from functools import wraps

# Try installing requirements
try:
    subprocess.check_call(["pip", "install", "-r", "requirements.txt"])
except subprocess.CalledProcessError as e:
    print("Failed to install dependencies:", e)

load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key')  # Required for sessions

# Status codes for SMTP responses
INVALID_MAILBOX_STATUS = [450, 550, 553]
VALID_MAILBOX_STATUS = [250, 251]

# Database setup
Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    api_key = Column(String, unique=True, nullable=False)
    created_at = Column(DateTime, default=datetime.now)

class AvailableAccount(Base):
    __tablename__ = 'available_accounts'
    username = Column(String, primary_key=True)
    email = Column(String, unique=True)
    password = Column(String)
    check_date = Column(String)

class GeneratedAccount(Base):
    __tablename__ = 'generated_accounts'
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String)
    email = Column(String, unique=True)
    password = Column(String)
    check_date = Column(DateTime, default=datetime.now)

# Initialize database
engine = create_engine('sqlite:///gmail_accounts.db')
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)

def generate_api_key(length=32):
    """Generate a random API key."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_random_password(length=10):
    """Generate a strong random password with uppercase, lowercase, and numbers."""
    while True:
        password = ''.join(random.choices(
            string.ascii_letters + string.digits, k=length
        ))
        if (any(c.islower() for c in password) and
            any(c.isupper() for c in password) and
            any(c.isdigit() for c in password)):
            return password

def generate_random_username(min_length=6, max_length=15):
    """Generate a random username with letters first followed by numbers."""
    length = random.randint(min_length, max_length)
    min_letters = max(1, length // 2)
    num_letters = random.randint(min_letters, length - 1)
    num_digits = length - num_letters
    letters = ''.join(random.choice(string.ascii_lowercase) for _ in range(num_letters))
    digits = ''.join(random.choice(string.digits) for _ in range(num_digits))
    return letters + digits

def get_mx_for_domain(domain="gmail.com"):
    """Retrieve the MX record for Gmail with error handling."""
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        mx_records = sorted((r.preference, str(r.exchange).rstrip('.')) for r in answers)
        return mx_records[0][1] if mx_records else None
    except Exception as e:
        print(f"Error fetching MX for {domain}: {e}")
        return None

def check_email_availability(email, mx_host):
    """Check if a Gmail address is available via SMTP."""
    try:
        with smtplib.SMTP(mx_host, port=25, timeout=3) as smtp:
            smtp.ehlo()
            smtp.mail('asadulhoqk@gmail.com')
            code, response = smtp.rcpt(email)
            if code in VALID_MAILBOX_STATUS:
                return False  # Email exists
            elif code in INVALID_MAILBOX_STATUS:
                return True  # Available
            return None  # Unknown status
    except (smtplib.SMTPException, socket.timeout, ConnectionRefusedError, socket.gaierror) as e:
        print(f"SMTP error checking {email}: {e}")
        return None

def check_email_availability_with_retry(email, mx_host, max_retries=2, delay=2):
    """Try checking email availability with retries."""
    for attempt in range(max_retries):
        result = check_email_availability(email, mx_host)
        if result is not None:
            return result
        if attempt < max_retries - 1:
            print(f"Retrying {email} in {delay} seconds...")
            time.sleep(delay)
    print(f"Giving up on {email} after {max_retries} attempts")
    return None

def try_generate_account(mx_host, session):
    """Try to generate a single available account."""
    max_attempts = 5
    for _ in range(max_attempts):
        username = generate_random_username()
        email = f"{username}@gmail.com"
        if (session.query(AvailableAccount).filter_by(email=email).first() or 
            session.query(GeneratedAccount).filter_by(email=email).first()):
            continue
        is_available = check_email_availability_with_retry(email, mx_host)
        if is_available:
            password = generate_random_password()
            current_date = datetime.now()
            account = {
                'username': username,
                'email': email,
                'password': password,
                'check_date': current_date.strftime("%Y-%m-%d %H:%M:%S")
            }
            db_account = GeneratedAccount(
                username=username,
                email=email,
                password=password,
                check_date=current_date
            )
            session.add(db_account)
            session.commit()
            return account
    return None

# Decorator for protected routes
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def api_key_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({'error': 'API key required'}), 401
        session_db = Session()
        user = session_db.query(User).filter_by(api_key=api_key).first()
        if not user:
            session_db.close()
            return jsonify({'error': 'Invalid API key'}), 401
        session_db.close()
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if 'user_id' in session:
        return render_template('index.html')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    session_db = Session()
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400
        if session_db.query(User).filter_by(username=username).first():
            return jsonify({'error': 'Username already exists'}), 400
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        api_key = generate_api_key()
        user = User(
            username=username,
            password_hash=password_hash.decode('utf-8'),
            api_key=api_key
        )
        session_db.add(user)
        session_db.commit()
        return jsonify({'success': True, 'api_key': api_key})
    except Exception as e:
        session_db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session_db.close()

@app.route('/login', methods=['POST'])
def login():
    session_db = Session()
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        user = session_db.query(User).filter_by(username=username).first()
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
            session['user_id'] = user.id
            return jsonify({'success': True})
        return jsonify({'error': 'Invalid credentials'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        session_db.close()

@app.route('/api_login', methods=['POST'])
def api_login():
    api_key = request.headers.get('X-API-Key')
    if not api_key:
        return jsonify({'error': 'API key required'}), 401
    session_db = Session()
    try:
        user = session_db.query(User).filter_by(api_key=api_key).first()
        if user:
            session['user_id'] = user.id
            return jsonify({'success': True})
        return jsonify({'error': 'Invalid API key'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        session_db.close()

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return jsonify({'success': True})

@app.route('/generate_single', methods=['POST'])
@login_required
@api_key_required
def generate_single():
    session_db = Session()
    mx_host = get_mx_for_domain()
    if not mx_host:
        return jsonify({'error': 'Failed to get MX record for Gmail. Try again later.'}), 500
    account = try_generate_account(mx_host, session_db)
    session_db.close()
    if account:
        return jsonify({'account': account})
    return jsonify({'error': 'Could not find available account after multiple attempts'}), 500

@app.route('/save_account', methods=['POST'])
@login_required
@api_key_required
def save_account():
    session_db = Session()
    try:
        account = request.get_json()
        generated = session_db.query(GeneratedAccount).filter_by(email=account['email']).first()
        if generated:
            session_db.delete(generated)
        db_account = AvailableAccount(
            username=account['username'],
            email=account['email'],
            password=account['password'],
            check_date=account['check_date']
        )
        session_db.add(db_account)
        session_db.commit()
        return jsonify({'success': True})
    except Exception as e:
        session_db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session_db.close()

@app.route('/save', methods=['POST'])
@login_required
@api_key_required
def save():
    session_db = Session()
    try:
        accounts = request.get_json()
        for account in accounts:
            generated = session_db.query(GeneratedAccount).filter_by(email=account['email']).first()
            if generated:
                session_db.delete(generated)
            db_account = AvailableAccount(
                username=account['username'],
                email=account['email'],
                password=account['password'],
                check_date=account['check_date']
            )
            session_db.add(db_account)
        session_db.commit()
        return jsonify({'success': True})
    except Exception as e:
        session_db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session_db.close()

@app.route('/delete/<username>', methods=['DELETE'])
@login_required
@api_key_required
def delete_account(username):
    session_db = Session()
    try:
        account = session_db.query(AvailableAccount).filter_by(username=username).first()
        if account:
            session_db.delete(account)
            session_db.commit()
            return jsonify({'success': True})
        generated = session_db.query(GeneratedAccount).filter_by(username=username).first()
        if generated:
            session_db.delete(generated)
            session_db.commit()
            return jsonify({'success': True})
        return jsonify({'error': 'Account not found'}), 404
    except Exception as e:
        session_db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session_db.close()

@app.route('/download')
@login_required
@api_key_required
def download():
    session_db = Session()
    try:
        saved_accounts = session_db.query(AvailableAccount).all()
        if not saved_accounts:
            return jsonify({'error': 'No accounts found'}), 404
        data = {
            'Email': [account.email for account in saved_accounts],
            'Password': [account.password for account in saved_accounts]
        }
        df = pd.DataFrame(data)
        output = BytesIO()
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            df.to_excel(writer, index=False, sheet_name='Accounts')
            for column in df:
                column_width = max(df[column].astype(str).map(len).max(), len(column))
                col_idx = df.columns.get_loc(column)
                writer.sheets['Accounts'].set_column(col_idx, col_idx, column_width)
        output.seek(0)
        gmt6_time = datetime.now(timezone.utc) + timedelta(hours=6)
        timestamp = gmt6_time.strftime("%I-%M-%S-%p-%d-%m-%Y")
        filename = f"gmail_accounts-{timestamp}.xlsx"
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        session_db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session_db.close()

@app.route('/saved_accounts')
@login_required
@api_key_required
def get_saved_accounts():
    session_db = Session()
    try:
        accounts = session_db.query(AvailableAccount).all()
        accounts_data = [{
            'username': account.username,
            'email': account.email,
            'password': account.password,
            'check_date': account.check_date
        } for account in accounts]
        return jsonify({'accounts': accounts_data})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        session_db.close()

@app.route('/generated_accounts')
@login_required
@api_key_required
def get_generated_accounts():
    session_db = Session()
    try:
        accounts = session_db.query(GeneratedAccount).order_by(desc(GeneratedAccount.check_date)).all()
        accounts_data = [{
            'username': account.username,
            'email': account.email,
            'password': account.password,
            'check_date': account.check_date.strftime("%Y-%m-%d %H:%M:%S")
        } for account in accounts]
        return jsonify({'accounts': accounts_data})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        session_db.close()

@app.route('/cancel_generated', methods=['POST'])
@login_required
@api_key_required
def cancel_generated():
    session_db = Session()
    try:
        data = request.get_json()
        emails_to_delete = data.get('emails', [])
        for email in emails_to_delete:
            account = session_db.query(GeneratedAccount).filter_by(email=email).first()
            if account:
                session_db.delete(account)
        session_db.commit()
        return jsonify({'success': True, 'deleted_count': len(emails_to_delete)})
    except Exception as e:
        session_db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session_db.close()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)