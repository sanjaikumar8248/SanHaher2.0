"""Account provisioning utility (optional).

Normal account creation happens on the website at /register for every role,
including Higher Authority, which creates its own independent room there.
This CLI remains available as an alternate way to create a Higher Authority
account (and its room) from a trusted administrator machine, or to directly
add an already-approved member into an existing room by its Room ID.
"""
from getpass import getpass
from . import db
from .auth import password_hash


def provision_user():
    db.init_db()
    name = input("Full name: ").strip()
    email = input("Email: ").strip().lower()
    mobile = input("Mobile: ").strip()
    role = input("Role [EXAMINER]: ").strip().upper() or "EXAMINER"
    if db.get_user_by_mobile(mobile):
        raise SystemExit("A user with that mobile number is already registered to a room. One mobile number may hold only one account.")
    if db.get_user_by_email(email):
        raise SystemExit("A user with that email already exists.")
    password = getpass("Login password (required; used with OTP to log in): ")
    if not password or len(password) < 8:
        raise SystemExit("Login password must be at least 8 characters.")

    room_id = None
    if role == "HIGHER_AUTHORITY":
        pv1 = getpass("Profile-view password (must differ from login password, min 8 chars): ")
        pv2 = getpass("Confirm profile-view password: ")
        if not pv1 or len(pv1) < 8 or pv1 != pv2 or pv1 == password:
            raise SystemExit("Profile-view password is missing, too short, mismatched, or identical to the login password.")
    else:
        room_code = input("Room / Registration ID to add this member to: ").strip().upper()
        room = db.get_room_by_code(room_code)
        if not room:
            raise SystemExit("No room matches that Registration ID.")
        room_id = room["id"]

    uid = db.create_user(name, email, mobile, password_hash(password), role=role, verified=True, status="ACTIVE", room_id=room_id)

    if role == "HIGHER_AUTHORITY":
        rid, code = db.create_room(uid, mobile, f"{name}'s Room")
        db.set_user_room(uid, rid)
        db.set_profile_view_password(uid, password_hash(pv1))
        db.record_access_grant(uid, role, "ACCESS_GRANTED", uid, "Room created via CLI provisioning; officer self-activated", room_id=rid)
        print(f"Provisioned Higher Authority #{uid}: {name} | {mobile} | {email}")
        print(f"Room ID (share with members, permanent): {code}")
    else:
        db.record_access_grant(uid, role, "ACCESS_GRANTED", uid, "Member provisioned directly via CLI into an existing room", room_id=room_id)
        print(f"Provisioned user #{uid}: {name} | {mobile} | {email} | {role} | joined room {room['room_code']}")

if __name__ == "__main__":
    provision_user()
