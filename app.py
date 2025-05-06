from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file
from io import BytesIO
import random
import string
import time
import socket
import smtplib
import dns.resolver
from datetime import datetime
from sqlalchemy import create_engine, Column, String, DateTime, Integer
from sqlalchemy.orm import declarative_base, sessionmaker
import pandas as pd
import concurrent.futures
from sqlalchemy import desc
from datetime import datetime, timezone, timedelta

app = Flask(__name__)

# Status codes for SMTP responses
INVALID_MAILBOX_STATUS = [450, 550, 553]
VALID_MAILBOX_STATUS = [250, 251]

# Database setup
Base = declarative_base()

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
engine = create_engine('postgresql://avnadmin:AVNS_Bjzw8QBs1b6ykbit4EU@pg-368de7df-choda7512-9ecd.d.aivencloud.com:22061/defaultdb?sslmode=require'
)
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)

def generate_random_password(length=10):
    """Generate a strong random password with uppercase, lowercase, and numbers."""
    while True:
        password = ''.join(random.choices(
            string.ascii_letters + string.digits, k=length
        ))
        # Ensure password has at least one of each character type
        if (any(c.islower() for c in password) and
            any(c.isupper() for c in password) and
            any(c.isdigit() for c in password)):
            return password

def generate_random_username(min_length=6, max_length=15):
    """Generate a random username with letters first followed by numbers."""
    length = random.randint(min_length, max_length)
    
    # Determine how many letters and numbers to use (at least 1 of each)
    min_letters = max(1, length // 2)
    num_letters = random.randint(min_letters, length - 1)
    num_digits = length - num_letters
    
    # Generate letters part
    letters = ''.join(random.choice(string.ascii_lowercase) for _ in range(num_letters))
    
    # Generate digits part
    digits = ''.join(random.choice(string.digits) for _ in range(num_digits))
    
    # Combine letters first then digits
    username = letters + digits
    
    return username

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
        # Reduced timeout to avoid long waits
        with smtplib.SMTP(mx_host, port=25, timeout=3) as smtp:
            smtp.ehlo()
            # Use a valid sender address
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
        
        # Sleep before retry only if not the last attempt
        if attempt < max_retries - 1:
            print(f"Retrying {email} in {delay} seconds...")
            time.sleep(delay)
    
    print(f"Giving up on {email} after {max_retries} attempts")
    return None  # Give up after retries

def try_generate_account(mx_host, session):
    """Try to generate a single available account."""
    max_attempts = 5
    
    for _ in range(max_attempts):
        username = generate_random_username()
        email = f"{username}@gmail.com"
        
        # Skip if already in database (either saved or generated)
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
            
            # Add to generated accounts table
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

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/generate_single', methods=['POST'])
def generate_single():
    session = Session()
    mx_host = get_mx_for_domain()
    
    if not mx_host:
        return jsonify({'error': 'Failed to get MX record for Gmail. Try again later.'}), 500
    
    # Generate just one account
    account = try_generate_account(mx_host, session)
    
    session.close()
    
    if account:
        return jsonify({'account': account})
    else:
        return jsonify({'error': 'Could not find available account after multiple attempts'}), 500

@app.route('/save_account', methods=['POST'])
def save_account():
    session = Session()
    try:
        account = request.get_json()
        
        # Check if this is a generated account
        generated = session.query(GeneratedAccount).filter_by(email=account['email']).first()
        if generated:
            # Remove from generated accounts if moving to saved
            session.delete(generated)
        
        db_account = AvailableAccount(
            username=account['username'],
            email=account['email'],
            password=account['password'],
            check_date=account['check_date']
        )
        session.add(db_account)
        session.commit()
        return jsonify({'success': True})
    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

@app.route('/save', methods=['POST'])
def save():
    session = Session()
    try:
        accounts = request.get_json()
        for account in accounts:
            # Check if this is a generated account
            generated = session.query(GeneratedAccount).filter_by(email=account['email']).first()
            if generated:
                # Remove from generated accounts if moving to saved
                session.delete(generated)
                
            db_account = AvailableAccount(
                username=account['username'],
                email=account['email'],
                password=account['password'],
                check_date=account['check_date']
            )
            session.add(db_account)
        session.commit()
        return jsonify({'success': True})
    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

@app.route('/delete/<username>', methods=['DELETE'])
def delete_account(username):
    session = Session()
    try:
        # Check in both tables
        account = session.query(AvailableAccount).filter_by(username=username).first()
        if account:
            session.delete(account)
            session.commit()
            return jsonify({'success': True})
            
        generated = session.query(GeneratedAccount).filter_by(username=username).first()
        if generated:
            session.delete(generated)
            session.commit()
            return jsonify({'success': True})
            
        return jsonify({'error': 'Account not found'}), 404
    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

@app.route('/download')
def download():
    session = Session()
    try:
        # Query all accounts
        saved_accounts = session.query(AvailableAccount).all()
        
        if not saved_accounts:
            return jsonify({'error': 'No accounts found'}), 404
        
        # Create DataFrame
        data = {
            'Email': [account.email for account in saved_accounts],
            'Password': [account.password for account in saved_accounts]
        }
        df = pd.DataFrame(data)
        
        # Create Excel file in memory
        output = BytesIO()
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            df.to_excel(writer, index=False, sheet_name='Accounts')
            # Auto-adjust columns' width
            for column in df:
                column_width = max(df[column].astype(str).map(len).max(), len(column))
                col_idx = df.columns.get_loc(column)
                writer.sheets['Accounts'].set_column(col_idx, col_idx, column_width)
        
        output.seek(0)
        
        # Generate filename with current time in GMT+6
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
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

@app.route('/saved_accounts')
def get_saved_accounts():
    session = Session()
    try:
        accounts = session.query(AvailableAccount).all()
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
        session.close()

@app.route('/generated_accounts')
def get_generated_accounts():
    session = Session()
    try:
        accounts = session.query(GeneratedAccount).order_by(desc(GeneratedAccount.check_date)).all()
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
        session.close()
@app.route('/cancel_generated', methods=['POST'])
def cancel_generated():
    session = Session()
    try:
        data = request.get_json()
        emails_to_delete = data.get('emails', [])  # Get list of emails to delete
        
        # Delete only the specified generated accounts
        for email in emails_to_delete:
            account = session.query(GeneratedAccount).filter_by(email=email).first()
            if account:
                session.delete(account)
        
        session.commit()
        return jsonify({'success': True, 'deleted_count': len(emails_to_delete)})
    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()
        
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000, debug=True)
