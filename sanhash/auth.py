import hashlib, secrets, string
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from . import db

def make_otp(): return ''.join(secrets.choice(string.digits) for _ in range(6))
def otp_hash(otp): return hashlib.sha256(otp.encode()).hexdigest()
def expiry(): return (datetime.now().astimezone()+timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S')
def valid_otp(row, otp):
    if not row or row['used']: return False
    try: return datetime.now().astimezone() <= datetime.strptime(row['expires_at'],'%Y-%m-%d %H:%M:%S').astimezone() and secrets.compare_digest(row['otp_hash'],otp_hash(otp))
    except ValueError: return False
def password_hash(password): return generate_password_hash(password)
def password_ok(stored,password): return check_password_hash(stored,password)
