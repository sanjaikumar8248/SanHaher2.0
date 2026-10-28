import sqlite3
from pathlib import Path
from datetime import datetime, timezone
from .paths import data_base

DB_PATH = data_base() / "data" / "sanhash.db"

def now():
    return datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")

def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    c = connect()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS rooms (
        id INTEGER PRIMARY KEY AUTOINCREMENT, room_code TEXT UNIQUE NOT NULL, name TEXT,
        officer_user_id INTEGER NOT NULL, created_at TEXT NOT NULL,
        change_count INTEGER NOT NULL DEFAULT 0, previous_code TEXT, code_changed_at TEXT
    );
    CREATE TABLE IF NOT EXISTS cases (
        id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT UNIQUE NOT NULL, title TEXT,
        analyst TEXT, created_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'OPEN', merkle_root TEXT,
        room_id INTEGER
    );
    CREATE TABLE IF NOT EXISTS evidence (
        id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL, evidence_no INTEGER NOT NULL,
        name TEXT NOT NULL, stored_path TEXT NOT NULL, size INTEGER NOT NULL, mime TEXT,
        sha256 TEXT NOT NULL, added_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'VERIFIED',
        deleted_at TEXT, deleted_by TEXT, UNIQUE(case_id, evidence_no)
    );
    CREATE TABLE IF NOT EXISTS upload_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT UNIQUE NOT NULL, case_id TEXT NOT NULL,
        room_id INTEGER NOT NULL, user_id INTEGER NOT NULL, filename TEXT NOT NULL, stored_path TEXT NOT NULL,
        total_size INTEGER NOT NULL, received_bytes INTEGER NOT NULL DEFAULT 0, notes TEXT,
        status TEXT NOT NULL DEFAULT 'IN_PROGRESS', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS custody (
        id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL, evidence_id INTEGER,
        event_time TEXT NOT NULL, action TEXT NOT NULL, analyst TEXT, notes TEXT
    );
    CREATE TABLE IF NOT EXISTS evidence_versions (
        id INTEGER PRIMARY KEY AUTOINCREMENT, evidence_id INTEGER NOT NULL, version_no INTEGER NOT NULL,
        path TEXT NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL, created_at TEXT NOT NULL,
        created_by TEXT, change_note TEXT, is_current INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
        mobile TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'EXAMINER', verified INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'ACTIVE', profile_view_password_hash TEXT, room_id INTEGER,
        failed_login_attempts INTEGER NOT NULL DEFAULT 0, locked_until TEXT,
        created_at TEXT NOT NULL, last_login TEXT
    );
    CREATE TABLE IF NOT EXISTS password_reset_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, requested_at TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'PENDING', decided_by INTEGER, decided_at TEXT, notes TEXT
    );
    CREATE TABLE IF NOT EXISTS otp_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, name TEXT, email TEXT, mobile TEXT,
        password_hash TEXT, purpose TEXT NOT NULL, otp_hash TEXT NOT NULL, expires_at TEXT NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0, used INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, event_time TEXT NOT NULL,
        action TEXT NOT NULL, ip TEXT, user_agent TEXT, details TEXT
    );
    CREATE TABLE IF NOT EXISTS access_grants (
        id INTEGER PRIMARY KEY AUTOINCREMENT, grant_id TEXT UNIQUE NOT NULL, user_id INTEGER NOT NULL,
        role TEXT NOT NULL, action TEXT NOT NULL, granted_by INTEGER NOT NULL, event_time TEXT NOT NULL,
        notes TEXT, prev_hash TEXT NOT NULL, event_hash TEXT NOT NULL, room_id INTEGER
    );
    CREATE TABLE IF NOT EXISTS case_members (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        case_role TEXT NOT NULL DEFAULT 'MEMBER',
        assigned_by INTEGER NOT NULL,
        assigned_at TEXT NOT NULL,
        UNIQUE(case_id, user_id)
    );
    CREATE TABLE IF NOT EXISTS case_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id TEXT UNIQUE NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        requested_by INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'PENDING',
        decided_by INTEGER,
        created_at TEXT NOT NULL,
        decided_at TEXT
    );
    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, event_time TEXT NOT NULL,
        title TEXT NOT NULL, message TEXT NOT NULL, severity TEXT NOT NULL DEFAULT 'INFO',
        related_case_id TEXT, related_evidence_id INTEGER, read_at TEXT
    );
    """)
    # Migration for databases created by older SanHasher builds.
    for stmt in [
        "ALTER TABLE evidence ADD COLUMN deleted_at TEXT",
        "ALTER TABLE evidence ADD COLUMN deleted_by TEXT",
        "ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'EXAMINER'",
        "ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'ACTIVE'",
        "ALTER TABLE users ADD COLUMN profile_view_password_hash TEXT",
        "ALTER TABLE users ADD COLUMN room_id INTEGER",
        "ALTER TABLE cases ADD COLUMN room_id INTEGER",
        "ALTER TABLE access_grants ADD COLUMN room_id INTEGER",
        "ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE users ADD COLUMN locked_until TEXT",
        "ALTER TABLE rooms ADD COLUMN change_count INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE rooms ADD COLUMN previous_code TEXT",
        "ALTER TABLE rooms ADD COLUMN code_changed_at TEXT",
    ]:
        try: c.execute(stmt)
        except sqlite3.OperationalError: pass
    c.commit(); c.close()

def generate_room_code(mobile):
    """Format: <last 4 digits of the officer's mobile><DDMMYY><HHMMSS>, e.g. 905712092622 3057.
    Built once at room creation from the officer's own mobile number and that exact moment,
    so it is permanent, non-repeating, and tied 1:1 to that mobile number."""
    digits = "".join(ch for ch in mobile if ch.isdigit())
    last4 = digits[-4:] if len(digits) >= 4 else digits.rjust(4, "0")
    ts = datetime.now(timezone.utc).astimezone()
    stamp = ts.strftime("%d%m%y%H%M%S")  # DDMMYY + HHMMSS
    return f"{last4}{stamp}"

def generate_room_code_from_hash(old_code):
    """Format for the 2nd and every later manual Room-ID change:
    first 4 hex characters of SHA-256(old room code) + DDMMYY + HHMMSS at the moment of change."""
    import hashlib
    prefix = hashlib.sha256(old_code.encode()).hexdigest()[:4].upper()
    ts = datetime.now(timezone.utc).astimezone()
    stamp = ts.strftime("%d%m%y%H%M%S")
    return f"{prefix}{stamp}"

def regenerate_room_code(room_id, mobile):
    """Officer-triggered Room ID change.
    - 1st manual change: same mobile-based formula as the original ID (fresh date/time).
    - 2nd manual change and every one after: first 4 chars come from SHA-256(previous code) instead of the mobile.
    The room's primary key never changes, so every existing member/case tied to this room stays put;
    only the code newcomers must enter to request to join changes."""
    import time
    c=connect()
    room=c.execute("SELECT * FROM rooms WHERE id=?",(room_id,)).fetchone()
    if not room:
        c.close(); raise ValueError("Room not found.")
    room=dict(room)
    next_change_no = room["change_count"] + 1
    tries=0
    while True:
        if next_change_no <= 1:
            new_code = generate_room_code(mobile)
        else:
            new_code = generate_room_code_from_hash(room["room_code"])
        # The format only has 1-second resolution, so a collision (most often with the very code
        # we're replacing, if this is called twice within the same second) just means "wait for
        # the clock to tick" rather than a real exhaustion of the ID space.
        if new_code != room["room_code"] and not c.execute("SELECT 1 FROM rooms WHERE room_code=?",(new_code,)).fetchone():
            break
        tries+=1
        if tries>5:
            c.close(); raise RuntimeError("Could not generate a unique Room ID. Please wait a moment and retry.")
        time.sleep(1.05)
    c.execute("UPDATE rooms SET previous_code=?, room_code=?, change_count=?, code_changed_at=? WHERE id=?",
               (room["room_code"], new_code, next_change_no, now(), room_id))
    c.commit(); c.close()
    return new_code, next_change_no

def create_authority_account(name,email,mobile,password_hash,room_name=None):
    """Atomically create the first Authority account and its permanent room."""
    c=connect()
    try:
        if c.execute("SELECT 1 FROM users WHERE mobile=? OR lower(email)=lower(?)",(mobile.strip(),email.strip())).fetchone():
            raise ValueError("That mobile or email is already registered.")
        cur=c.execute(
            "INSERT INTO users(name,email,mobile,password_hash,role,verified,status,created_at,room_id) VALUES(?,?,?,?,?,?,?,?,NULL)",
            (name.strip(),email.lower().strip(),mobile.strip(),password_hash,"HIGHER_AUTHORITY",1,"ACTIVE",now())
        )
        uid=cur.lastrowid
        import time
        code=generate_room_code(mobile)
        tries=0
        while c.execute("SELECT 1 FROM rooms WHERE room_code=?",(code,)).fetchone():
            tries+=1
            if tries>5: raise RuntimeError("Could not generate a unique Room ID. Please wait a moment and retry.")
            time.sleep(1.05)
            code=generate_room_code(mobile)
        room_name = room_name or f"{name.strip()}'s Room"
        cur=c.execute("INSERT INTO rooms(room_code,name,officer_user_id,created_at) VALUES(?,?,?,?)",(code,room_name,uid,now()))
        rid=cur.lastrowid
        c.execute("UPDATE users SET room_id=? WHERE id=?",(rid,uid))
        c.commit()
        return uid,rid,code
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()

def create_room(officer_user_id, mobile, name=None):
    import time
    c=connect(); code=generate_room_code(mobile)
    # Extremely unlikely, but guard against a same-second collision for the same last-4 digits.
    tries=0
    while c.execute("SELECT 1 FROM rooms WHERE room_code=?",(code,)).fetchone():
        tries+=1
        if tries>5: c.close(); raise RuntimeError("Could not generate a unique Room ID, please wait a moment and retry.")
        time.sleep(1.05)
        code=generate_room_code(mobile)
    cur=c.execute("INSERT INTO rooms(room_code,name,officer_user_id,created_at) VALUES(?,?,?,?)",(code,name,officer_user_id,now()))
    rid=cur.lastrowid; c.commit(); c.close(); return rid, code

def get_room(room_id):
    c=connect(); r=c.execute("SELECT * FROM rooms WHERE id=?",(room_id,)).fetchone(); c.close(); return dict(r) if r else None

def get_room_by_code(room_code):
    c=connect(); r=c.execute("SELECT * FROM rooms WHERE room_code=?",(room_code.strip().upper(),)).fetchone(); c.close(); return dict(r) if r else None

def create_case(case_id, title, analyst, room_id):
    c=connect(); c.execute("INSERT INTO cases(case_id,title,analyst,created_at,room_id) VALUES(?,?,?,?,?)",(case_id,title,analyst,now(),room_id)); c.commit(); c.close()
def list_cases(room_id=None):
    c=connect()
    if room_id is not None: rows=c.execute("SELECT * FROM cases WHERE room_id=? ORDER BY id DESC",(room_id,)).fetchall()
    else: rows=c.execute("SELECT * FROM cases ORDER BY id DESC").fetchall()
    c.close(); return [dict(r) for r in rows]
def list_cases_for_user(room_id,user_id,is_authority=False):
    if is_authority:
        return list_cases(room_id)
    c=connect()
    rows=c.execute("""SELECT c.* FROM cases c JOIN case_members cm ON cm.case_id=c.case_id
                      WHERE c.room_id=? AND cm.user_id=? ORDER BY c.id DESC""",(room_id,user_id)).fetchall()
    c.close(); return [dict(r) for r in rows]

def get_case(case_id, room_id=None):
    c=connect()
    if room_id is not None: r=c.execute("SELECT * FROM cases WHERE case_id=? AND room_id=?",(case_id,room_id)).fetchone()
    else: r=c.execute("SELECT * FROM cases WHERE case_id=?",(case_id,)).fetchone()
    c.close(); return dict(r) if r else None

def add_evidence(case_id,name,stored_path,size,mime,sha256):
    c=connect(); n=c.execute("SELECT COALESCE(MAX(evidence_no),0)+1 FROM evidence WHERE case_id=?",(case_id,)).fetchone()[0]
    cur=c.execute("INSERT INTO evidence(case_id,evidence_no,name,stored_path,size,mime,sha256,added_at) VALUES(?,?,?,?,?,?,?,?)",(case_id,n,name,stored_path,size,mime,sha256,now()))
    eid=cur.lastrowid
    c.execute("INSERT INTO evidence_versions(evidence_id,version_no,path,sha256,size,created_at,created_by,change_note,is_current) VALUES(?,?,?,?,?,?,?,?,1)",(eid,1,stored_path,sha256,size,now(),"system","Original registered evidence"))
    c.execute("INSERT INTO custody(case_id,evidence_id,event_time,action,analyst,notes) VALUES(?,?,?,?,?,?)",(case_id,eid,now(),"Evidence Added","SanHasher Analyst","Original evidence registered; immutable baseline created"))
    c.commit(); c.close(); return eid

def create_upload_session(session_id,case_id,room_id,user_id,filename,stored_path,total_size,notes=""):
    c=connect(); t=now()
    c.execute("INSERT INTO upload_sessions(session_id,case_id,room_id,user_id,filename,stored_path,total_size,received_bytes,notes,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,0,?, 'IN_PROGRESS',?,?)",
              (session_id,case_id,room_id,user_id,filename,stored_path,total_size,notes,t,t))
    c.commit(); c.close()
def get_upload_session(session_id):
    c=connect(); r=c.execute("SELECT * FROM upload_sessions WHERE session_id=?",(session_id,)).fetchone(); c.close(); return dict(r) if r else None
def advance_upload_session(session_id,received_bytes):
    c=connect(); c.execute("UPDATE upload_sessions SET received_bytes=?, updated_at=? WHERE session_id=?",(received_bytes,now(),session_id)); c.commit(); c.close()
def set_upload_session_status(session_id,status):
    c=connect(); c.execute("UPDATE upload_sessions SET status=?, updated_at=? WHERE session_id=?",(status,now(),session_id)); c.commit(); c.close()
def list_upload_sessions(case_id,room_id,status=None):
    c=connect()
    if status: rows=c.execute("SELECT * FROM upload_sessions WHERE case_id=? AND room_id=? AND status=? ORDER BY id DESC",(case_id,room_id,status)).fetchall()
    else: rows=c.execute("SELECT * FROM upload_sessions WHERE case_id=? AND room_id=? ORDER BY id DESC",(case_id,room_id)).fetchall()
    c.close(); return [dict(r) for r in rows]

def list_evidence(case_id, include_deleted=True):
    c=connect(); rows=c.execute("SELECT * FROM evidence WHERE case_id=? {} ORDER BY evidence_no".format("" if include_deleted else "AND deleted_at IS NULL"),(case_id,)).fetchall(); c.close(); return [dict(r) for r in rows]
def get_evidence(evidence_id):
    c=connect(); r=c.execute("SELECT * FROM evidence WHERE id=?",(evidence_id,)).fetchone(); c.close(); return dict(r) if r else None
def update_evidence_status(evidence_id,status):
    c=connect(); c.execute("UPDATE evidence SET status=? WHERE id=?",(status,evidence_id)); c.commit(); c.close()
def add_custody(case_id,evidence_id,action,analyst,notes):
    c=connect(); c.execute("INSERT INTO custody(case_id,evidence_id,event_time,action,analyst,notes) VALUES(?,?,?,?,?,?)",(case_id,evidence_id,now(),action,analyst,notes)); c.commit(); c.close()
def list_custody(case_id):
    c=connect(); rows=c.execute("SELECT c.*,e.name AS evidence_name FROM custody c LEFT JOIN evidence e ON c.evidence_id=e.id WHERE c.case_id=? ORDER BY c.id DESC",(case_id,)).fetchall(); c.close(); return [dict(r) for r in rows]
def update_case_root(case_id,root):
    c=connect(); c.execute("UPDATE cases SET merkle_root=? WHERE case_id=?",(root,case_id)); c.commit(); c.close()
def update_case_status(case_id,status):
    c=connect(); c.execute("UPDATE cases SET status=? WHERE case_id=?",(status,case_id)); c.commit(); c.close()

def add_version(evidence_id,path,sha256,size,created_by,change_note):
    c=connect(); current=c.execute("SELECT COALESCE(MAX(version_no),0)+1 FROM evidence_versions WHERE evidence_id=?",(evidence_id,)).fetchone()[0]
    c.execute("UPDATE evidence_versions SET is_current=0 WHERE evidence_id=?",(evidence_id,))
    c.execute("INSERT INTO evidence_versions(evidence_id,version_no,path,sha256,size,created_at,created_by,change_note,is_current) VALUES(?,?,?,?,?,?,?,?,1)",(evidence_id,current,path,sha256,size,now(),created_by,change_note))
    c.execute("UPDATE evidence SET stored_path=?,size=?,status=? WHERE id=?",(path,size,"MODIFIED" if current>1 else "VERIFIED",evidence_id))
    c.commit(); c.close(); return current

def list_versions(evidence_id):
    c=connect(); rows=c.execute("SELECT * FROM evidence_versions WHERE evidence_id=? ORDER BY version_no DESC",(evidence_id,)).fetchall(); c.close(); return [dict(r) for r in rows]
def get_version(evidence_id,version_no):
    c=connect(); r=c.execute("SELECT * FROM evidence_versions WHERE evidence_id=? AND version_no=?",(evidence_id,version_no)).fetchone(); c.close(); return dict(r) if r else None

def soft_delete_evidence(evidence_id,deleted_by):
    c=connect(); c.execute("UPDATE evidence SET deleted_at=?,deleted_by=?,status='DELETED' WHERE id=? AND deleted_at IS NULL",(now(),deleted_by,evidence_id)); c.commit(); c.close()
def restore_evidence(evidence_id):
    c=connect(); c.execute("UPDATE evidence SET deleted_at=NULL,deleted_by=NULL,status='VERIFIED' WHERE id=? AND deleted_at IS NOT NULL",(evidence_id,)); c.commit(); c.close()
def expire_deleted_evidence():
    # 30-day Recently Deleted is a recovery window. After that, evidence is
    # archived/expired but is NEVER physically or permanently deleted.
    c=connect(); c.execute("UPDATE evidence SET status='ARCHIVED_30D_EXPIRED' WHERE deleted_at IS NOT NULL AND status='DELETED' AND datetime(deleted_at) <= datetime('now','-30 days')"); c.commit(); c.close()

def next_grant_id(c):
    n=c.execute("SELECT COALESCE(MAX(id),0)+1 FROM access_grants").fetchone()[0]
    return f"AG-{n:06d}"

def record_access_grant(user_id, role, action, granted_by, notes='', room_id=None):
    c=connect(); prev=c.execute("SELECT event_hash FROM access_grants ORDER BY id DESC LIMIT 1").fetchone(); prev_hash=prev[0] if prev else 'GENESIS'
    gid=next_grant_id(c); event_time=now()
    import hashlib, json
    payload=json.dumps({'grant_id':gid,'user_id':user_id,'role':role,'action':action,'granted_by':granted_by,'event_time':event_time,'notes':notes,'prev_hash':prev_hash},sort_keys=True,separators=(',',':'))
    event_hash=hashlib.sha256(payload.encode()).hexdigest()
    c.execute("INSERT INTO access_grants(grant_id,user_id,role,action,granted_by,event_time,notes,prev_hash,event_hash,room_id) VALUES(?,?,?,?,?,?,?,?,?,?)",(gid,user_id,role,action,granted_by,event_time,notes,prev_hash,event_hash,room_id)); c.commit(); c.close(); return gid

def list_access_grants(limit=500, room_id=None):
    c=connect()
    q="SELECT g.*,u.name AS user_name,u.email,u.mobile,a.name AS authority_name FROM access_grants g LEFT JOIN users u ON g.user_id=u.id LEFT JOIN users a ON g.granted_by=a.id"
    if room_id is not None:
        rows=c.execute(q+" WHERE g.room_id=? ORDER BY g.id DESC LIMIT ?",(room_id,limit)).fetchall()
    else:
        rows=c.execute(q+" ORDER BY g.id DESC LIMIT ?",(limit,)).fetchall()
    c.close(); return [dict(r) for r in rows]

def verify_access_grants():
    c=connect(); rows=c.execute("SELECT * FROM access_grants ORDER BY id ASC").fetchall(); import hashlib, json; prev='GENESIS'
    for r in rows:
        payload=json.dumps({'grant_id':r['grant_id'],'user_id':r['user_id'],'role':r['role'],'action':r['action'],'granted_by':r['granted_by'],'event_time':r['event_time'],'notes':r['notes'] or '','prev_hash':prev},sort_keys=True,separators=(',',':'))
        expected=hashlib.sha256(payload.encode()).hexdigest()
        if r['prev_hash']!=prev or r['event_hash']!=expected: c.close(); return False
        prev=r['event_hash']
    c.close(); return True


def add_case_member(case_id, user_id, case_role, assigned_by):
    c=connect()
    c.execute("""INSERT INTO case_members(case_id,user_id,case_role,assigned_by,assigned_at)
                VALUES(?,?,?,?,?)
                ON CONFLICT(case_id,user_id) DO UPDATE SET case_role=excluded.case_role,
                assigned_by=excluded.assigned_by, assigned_at=excluded.assigned_at""",
              (case_id,user_id,case_role.upper(),assigned_by,now()))
    c.commit(); c.close()

def remove_case_member(case_id,user_id):
    c=connect(); c.execute("DELETE FROM case_members WHERE case_id=? AND user_id=?",(case_id,user_id)); c.commit(); c.close()

def list_case_members(case_id):
    c=connect()
    rows=c.execute("""SELECT cm.*,u.name,u.email,u.mobile,u.role AS room_role,u.status,u.verified
                      FROM case_members cm JOIN users u ON u.id=cm.user_id
                      WHERE cm.case_id=? ORDER BY CASE cm.case_role WHEN 'TEAM_LEAD' THEN 0 ELSE 1 END,u.name""",(case_id,)).fetchall()
    c.close(); return [dict(r) for r in rows]

def get_case_membership(case_id,user_id):
    c=connect(); r=c.execute("SELECT * FROM case_members WHERE case_id=? AND user_id=?",(case_id,user_id)).fetchone(); c.close(); return dict(r) if r else None

def user_can_access_case(case_id,user_id):
    u=get_user(user_id)
    if not u: return False
    case=get_case(case_id, room_id=u.get("room_id"))
    if not case: return False
    if u.get("role")=="HIGHER_AUTHORITY": return True
    return bool(get_case_membership(case_id,user_id))

def create_case_request(case_id,title,description,requested_by):
    c=connect(); c.execute("INSERT INTO case_requests(case_id,title,description,requested_by,created_at) VALUES(?,?,?,?,?)",
                           (case_id,title,description,requested_by,now())); c.commit(); c.close()

def list_case_requests(room_id,status="PENDING"):
    c=connect()
    rows=c.execute("""SELECT cr.*,u.name AS requester_name,u.email AS requester_email,u.mobile AS requester_mobile
                      FROM case_requests cr JOIN users u ON u.id=cr.requested_by
                      WHERE u.room_id=? AND cr.status=? ORDER BY cr.id DESC""",(room_id,status)).fetchall()
    c.close(); return [dict(r) for r in rows]

def get_case_request(request_id):
    c=connect(); r=c.execute("SELECT * FROM case_requests WHERE id=?",(request_id,)).fetchone(); c.close(); return dict(r) if r else None

def decide_case_request(request_id,status,decided_by):
    c=connect(); c.execute("UPDATE case_requests SET status=?,decided_by=?,decided_at=? WHERE id=?",(status,decided_by,now(),request_id)); c.commit(); c.close()

def create_case_with_owner(case_id,title,created_by,room_id):
    create_case(case_id,title,"",room_id)
    add_case_member(case_id,created_by,"TEAM_LEAD",created_by)

def add_notification(user_id,title,message,severity='INFO',case_id=None,evidence_id=None):
    c=connect(); c.execute("INSERT INTO notifications(user_id,event_time,title,message,severity,related_case_id,related_evidence_id) VALUES(?,?,?,?,?,?,?)",(user_id,now(),title,message,severity,case_id,evidence_id)); c.commit(); c.close()

def notify_room(room_id,title,message,severity='INFO',case_id=None,evidence_id=None):
    c=connect(); users=c.execute("SELECT id FROM users WHERE verified=1 AND room_id=?",(room_id,)).fetchall(); t=now()
    c.executemany("INSERT INTO notifications(user_id,event_time,title,message,severity,related_case_id,related_evidence_id) VALUES(?,?,?,?,?,?,?)",[(u['id'],t,title,message,severity,case_id,evidence_id) for u in users]); c.commit(); c.close()

def list_notifications(user_id,limit=100):
    c=connect(); rows=c.execute("SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT ?",(user_id,limit)).fetchall(); c.close(); return [dict(r) for r in rows]

def unread_notification_count(user_id):
    c=connect(); n=c.execute("SELECT COUNT(*) FROM notifications WHERE user_id=? AND read_at IS NULL",(user_id,)).fetchone()[0]; c.close(); return n

def mark_notification_read(notification_id,user_id):
    c=connect(); c.execute("UPDATE notifications SET read_at=? WHERE id=? AND user_id=? AND read_at IS NULL",(now(),notification_id,user_id)); c.commit(); c.close()

def list_users(room_id):
    c=connect(); rows=c.execute("SELECT id,name,email,mobile,role,verified,status,created_at,last_login FROM users WHERE room_id=? ORDER BY id DESC",(room_id,)).fetchall(); c.close(); return [dict(r) for r in rows]

def set_user_role(user_id,role):
    c=connect(); c.execute("UPDATE users SET role=? WHERE id=?",(role.upper(),user_id)); c.commit(); c.close()

def set_user_verified(user_id,verified):
    c=connect(); c.execute("UPDATE users SET verified=? WHERE id=?",(1 if verified else 0,user_id)); c.commit(); c.close()

def create_user(name,email,mobile,password_hash,role="EXAMINER",verified=True,status="ACTIVE",room_id=None):
    c=connect(); cur=c.execute(
        "INSERT INTO users(name,email,mobile,password_hash,role,verified,status,created_at,room_id) VALUES(?,?,?,?,?,?,?,?,?)",
        (name,email.lower().strip(),mobile.strip(),password_hash,role.upper().strip(),1 if verified else 0,status,now(),room_id)
    ); uid=cur.lastrowid; c.commit(); c.close(); return uid
def set_user_room(user_id,room_id):
    c=connect(); c.execute("UPDATE users SET room_id=? WHERE id=?",(room_id,user_id)); c.commit(); c.close()
def get_user_by_email(email):
    c=connect(); r=c.execute("SELECT * FROM users WHERE lower(email)=lower(?)",(email,)).fetchone(); c.close(); return dict(r) if r else None
def get_user_by_mobile(mobile):
    c=connect(); r=c.execute("SELECT * FROM users WHERE mobile=?",(mobile,)).fetchone(); c.close(); return dict(r) if r else None
def get_user_by_identifier(identifier):
    identifier=(identifier or "").strip()
    c=connect()
    r=c.execute("SELECT * FROM users WHERE lower(email)=lower(?) OR mobile=?",(identifier,identifier)).fetchone()
    c.close(); return dict(r) if r else None
def list_pending_registrations(room_id):
    c=connect(); rows=c.execute("SELECT * FROM users WHERE status='PENDING' AND room_id=? ORDER BY id DESC",(room_id,)).fetchall(); c.close(); return [dict(r) for r in rows]
def approve_registration(user_id):
    c=connect(); c.execute("UPDATE users SET status='ACTIVE',verified=1 WHERE id=?",(user_id,)); c.commit(); c.close()
def reject_registration(user_id):
    c=connect(); c.execute("UPDATE users SET status='REJECTED',verified=0 WHERE id=?",(user_id,)); c.commit(); c.close()
def set_profile_view_password(user_id,pw_hash):
    c=connect(); c.execute("UPDATE users SET profile_view_password_hash=? WHERE id=?",(pw_hash,user_id)); c.commit(); c.close()
def set_user_password(user_id,pw_hash):
    c=connect(); c.execute("UPDATE users SET password_hash=? WHERE id=?",(pw_hash,user_id)); c.commit(); c.close()
def create_password_reset_request(user_id):
    c=connect(); c.execute("UPDATE password_reset_requests SET status='SUPERSEDED' WHERE user_id=? AND status='PENDING'",(user_id,))
    cur=c.execute("INSERT INTO password_reset_requests(user_id,requested_at,status) VALUES(?,?,?)",(user_id,now(),"PENDING"))
    rid=cur.lastrowid; c.commit(); c.close(); return rid
def list_password_reset_requests(status=None, room_id=None):
    c=connect()
    q="SELECT r.*,u.name,u.email,u.mobile,u.room_id FROM password_reset_requests r JOIN users u ON r.user_id=u.id WHERE 1=1"
    params=[]
    if status: q+=" AND r.status=?"; params.append(status)
    if room_id is not None: q+=" AND u.room_id=?"; params.append(room_id)
    q+=" ORDER BY r.id DESC"
    rows=c.execute(q,params).fetchall(); c.close(); return [dict(r) for r in rows]
def decide_password_reset(request_id,status,decided_by,notes=""):
    c=connect(); c.execute("UPDATE password_reset_requests SET status=?,decided_by=?,decided_at=?,notes=? WHERE id=?",(status,decided_by,now(),notes,request_id)); c.commit(); c.close()
def get_password_reset_request(request_id):
    c=connect(); r=c.execute("SELECT * FROM password_reset_requests WHERE id=?",(request_id,)).fetchone(); c.close(); return dict(r) if r else None
def get_user(user_id):
    c=connect(); r=c.execute("SELECT * FROM users WHERE id=?",(user_id,)).fetchone(); c.close(); return dict(r) if r else None
def verify_user(user_id):
    c=connect(); c.execute("UPDATE users SET verified=1 WHERE id=?",(user_id,)); c.commit(); c.close()
def set_last_login(user_id):
    c=connect(); c.execute("UPDATE users SET last_login=? WHERE id=?",(now(),user_id)); c.commit(); c.close()

MAX_LOGIN_ATTEMPTS = 10
LOCKOUT_MINUTES = 30
MAX_OTP_ATTEMPTS = 2

def is_locked(user):
    lu = user.get("locked_until") if user else None
    if not lu: return False
    try:
        return datetime.now(timezone.utc).astimezone() < datetime.strptime(lu, "%Y-%m-%d %H:%M:%S").astimezone()
    except ValueError:
        return False

def register_failed_login(user_id):
    """Count a bad password attempt. On exceeding MAX_LOGIN_ATTEMPTS, suspend the account for LOCKOUT_MINUTES."""
    from datetime import timedelta
    c=connect()
    row=c.execute("SELECT failed_login_attempts FROM users WHERE id=?",(user_id,)).fetchone()
    count=(row[0] if row else 0)+1
    if count > MAX_LOGIN_ATTEMPTS:
        locked_until=(datetime.now(timezone.utc).astimezone()+timedelta(minutes=LOCKOUT_MINUTES)).strftime("%Y-%m-%d %H:%M:%S")
        c.execute("UPDATE users SET failed_login_attempts=0, locked_until=? WHERE id=?",(locked_until,user_id))
        c.commit(); c.close(); return True, locked_until
    c.execute("UPDATE users SET failed_login_attempts=? WHERE id=?",(count,user_id)); c.commit(); c.close()
    return False, None

def reset_failed_login(user_id):
    c=connect(); c.execute("UPDATE users SET failed_login_attempts=0, locked_until=NULL WHERE id=?",(user_id,)); c.commit(); c.close()

def create_otp(user_id,name,email,mobile,password_hash,purpose,otp_hash,expires_at):
    c=connect(); c.execute("UPDATE otp_tokens SET used=1 WHERE (email=? OR mobile=?) AND purpose=? AND used=0",(email,mobile,purpose)); cur=c.execute("INSERT INTO otp_tokens(user_id,name,email,mobile,password_hash,purpose,otp_hash,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?,?)",(user_id,name,email,mobile,password_hash,purpose,otp_hash,expires_at,now())); oid=cur.lastrowid; c.commit(); c.close(); return oid
def get_latest_otp(email,mobile,purpose):
    c=connect(); r=c.execute("SELECT * FROM otp_tokens WHERE (email=? OR mobile=?) AND purpose=? AND used=0 ORDER BY id DESC LIMIT 1",(email,mobile,purpose)).fetchone(); c.close(); return dict(r) if r else None
def consume_otp(otp_id):
    c=connect(); c.execute("UPDATE otp_tokens SET used=1 WHERE id=?",(otp_id,)); c.commit(); c.close()
def register_failed_otp(otp_id):
    """Count a wrong OTP entry. Returns the new attempt count. At MAX_OTP_ATTEMPTS the OTP is burned (marked used)."""
    c=connect()
    row=c.execute("SELECT attempts FROM otp_tokens WHERE id=?",(otp_id,)).fetchone()
    count=(row[0] if row else 0)+1
    if count >= MAX_OTP_ATTEMPTS:
        c.execute("UPDATE otp_tokens SET attempts=?, used=1 WHERE id=?",(count,otp_id))
    else:
        c.execute("UPDATE otp_tokens SET attempts=? WHERE id=?",(count,otp_id))
    c.commit(); c.close(); return count
def audit(user_id,action,ip,user_agent,details=""):
    c=connect(); c.execute("INSERT INTO audit_log(user_id,event_time,action,ip,user_agent,details) VALUES(?,?,?,?,?,?)",(user_id,now(),action,ip,user_agent[:300],details)); c.commit(); c.close()
def list_audit(limit=200, room_id=None):
    c=connect()
    if room_id is not None:
        rows=c.execute("SELECT a.*,u.name FROM audit_log a LEFT JOIN users u ON a.user_id=u.id WHERE u.room_id=? ORDER BY a.id DESC LIMIT ?",(room_id,limit)).fetchall()
    else:
        rows=c.execute("SELECT a.*,u.name FROM audit_log a LEFT JOIN users u ON a.user_id=u.id ORDER BY a.id DESC LIMIT ?",(limit,)).fetchall()
    c.close(); return [dict(r) for r in rows]
