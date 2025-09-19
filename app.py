# app.py
import streamlit as st
import pandas as pd
from datetime import datetime, date, time, timedelta
import hashlib, secrets, binascii
import smtplib
from email.message import EmailMessage
from st_supabase_connection import SupabaseConnection

# ---------------------------
# Connect to Supabase
# ---------------------------
conn = st.connection("supabase", type=SupabaseConnection)

# ---------------------------
# Password hashing (PBKDF2)
# ---------------------------
def hash_password(password: str):
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 200_000)
    return binascii.hexlify(salt).decode(), binascii.hexlify(dk).decode()

def verify_password(password: str, salt_hex: str, hash_hex: str):
    salt = binascii.unhexlify(salt_hex)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 200_000)
    return binascii.hexlify(dk).decode() == hash_hex

# ---------------------------
# User functions
# ---------------------------
def create_user(name, email, password, is_admin=False):
    salt, pw_hash = hash_password(password)
    try:
        conn.table("users").insert({
            "name": name,
            "email": email,
            "salt": salt,
            "pw_hash": pw_hash,
            "is_admin": is_admin
        }).execute()
        return True, "User created"
    except Exception as e:
        return False, f"Error: {e}"

def get_user_by_email(email):
    res = conn.table("users").select("*").eq("email", email).execute()
    if not res.data:
        return None
    row = res.data[0]
    return {
        "id": row["id"],
        "name": row["name"],
        "email": row["email"],
        "salt": row["salt"],
        "pw_hash": row["pw_hash"],
        "is_admin": row["is_admin"]
    }

def authenticate_user(email, password):
    user = get_user_by_email(email)
    if not user:
        return None
    if verify_password(password, user['salt'], user['pw_hash']):
        return user
    return None

def user_count():
    res = conn.table("users").select("id", count="exact").execute()
    return res.count or 0

# ---------------------------
# Settings
# ---------------------------
def set_setting(key, value):
    conn.table("settings").upsert({"key": key, "value": value}).execute()

def get_setting(key, default=None):
    res = conn.table("settings").select("value").eq("key", key).execute()
    return res.data[0]["value"] if res.data else default

# ---------------------------
# Slots & bookings
# ---------------------------
def create_slot(start_dt, end_dt, capacity, created_by):
    conn.table("slots").insert({
        "start_ts": start_dt.isoformat(),
        "end_ts": end_dt.isoformat(),
        "capacity": capacity,
        "created_by": created_by
    }).execute()

def get_slots_by_date(d: date):
    start_day = datetime.combine(d, time.min).isoformat()
    end_day = datetime.combine(d, time.max).isoformat()
    res = conn.table("slots").select("*").gte("start_ts", start_day).lte("end_ts", end_day).order("start_ts").execute()

    slots = []
    for r in res.data:
        slots.append({
            "id": r["id"],
            "start": datetime.fromisoformat(r["start_ts"]),
            "end": datetime.fromisoformat(r["end_ts"]),
            "capacity": r["capacity"],
            "created_by": r["created_by"],
            "available": slot_available_seats(r["id"], r["capacity"])
        })
    return slots

def slot_available_seats(slot_id, capacity):
    res = conn.table("bookings").select("id", count="exact").eq("slot_id", slot_id).eq("status", "booked").execute()
    booked = res.count or 0
    return max(0, capacity - booked)

def remove_slot(slot_id):
    conn.table("bookings").delete().eq("slot_id", slot_id).execute()
    conn.table("slots").delete().eq("id", slot_id).execute()

def book_slot(slot_id, user_id, name, email, phone, notes):
    # Check capacity
    slot_res = conn.table("slots").select("capacity").eq("id", slot_id).execute()
    if not slot_res.data:
        return False, "Slot not found"
    capacity = slot_res.data[0]["capacity"]

    booked_res = conn.table("bookings").select("id", count="exact").eq("slot_id", slot_id).eq("status", "booked").execute()
    booked = booked_res.count or 0
    if booked >= capacity:
        return False, "Slot is full"

    # Prevent same user booking same slot twice
    dup = conn.table("bookings").select("id").eq("slot_id", slot_id).eq("user_id", user_id).eq("status", "booked").execute()
    if dup.data:
        return False, "You already booked this slot"

    conn.table("bookings").insert({
        "slot_id": slot_id,
        "user_id": user_id,
        "name": name,
        "email": email,
        "phone": phone,
        "notes": notes,
        "status": "booked"
    }).execute()
    return True, "Booked"

def list_bookings(admin_only=False, admin_id=None):
    q = """
    select b.id, b.slot_id, s.start_ts, s.end_ts, b.name, b.email, b.phone, b.notes, b.status, b.created_at
    from bookings b
    join slots s on b.slot_id = s.id
    """
    if admin_only and admin_id:
        q += f" where s.created_by = {admin_id}"
    q += " order by s.start_ts"
    res = conn.query(q).execute()
    # convert start/end to datetime
    for r in res.data:
        r['start'] = datetime.fromisoformat(r.pop('start_ts'))
        r['end'] = datetime.fromisoformat(r.pop('end_ts'))
    return res.data

def cancel_booking(booking_id):
    conn.table("bookings").update({"status": "canceled"}).eq("id", booking_id).execute()

# ---------------------------
# Email
# ---------------------------
def send_email_smtp(subject, body, to_email):
    host = get_setting("smtp_host")
    port = get_setting("smtp_port")
    username = get_setting("smtp_user")
    password = get_setting("smtp_pass")
    from_addr = get_setting("from_email")
    if not (host and port and username and password and from_addr):
        return False, "SMTP not configured"
    try:
        msg = EmailMessage()
        msg["From"] = from_addr
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.set_content(body)
        server = smtplib.SMTP(host, int(port))
        server.starttls()
        server.login(username, password)
        server.send_message(msg)
        server.quit()
        return True, "Email sent"
    except Exception as e:
        return False, str(e)

# ---------------------------
# Streamlit UI
# ---------------------------
st.set_page_config(page_title="Appointment Booking", layout="wide")
if 'user' not in st.session_state:
    st.session_state['user'] = None

def show_login_register():
    st.sidebar.title("Account")
    if st.session_state['user']:
        st.sidebar.write(f"Logged in as **{st.session_state['user']['name']}**")
        if st.sidebar.button("Logout"):
            st.session_state['user'] = None
            st.success("Logged out")
        return

    tab = st.sidebar.radio("Choose", ["Login", "Register"], index=0)
    if tab == "Login":
        st.sidebar.subheader("Login")
        le = st.sidebar.text_input("Email")
        lp = st.sidebar.text_input("Password", type="password")
        if st.sidebar.button("Log in"):
            user = authenticate_user(le.strip().lower(), lp)
            if user:
                st.session_state['user'] = user
                st.success("Logged in")
            else:
                st.sidebar.error("Invalid credentials")
    else:
        st.sidebar.subheader("Create account")
        rn = st.sidebar.text_input("Your name")
        re = st.sidebar.text_input("Email (will be login)")
        rp = st.sidebar.text_input("Password", type="password")
        if st.sidebar.button("Create account"):
            ok, msg = create_user(rn.strip(), re.strip().lower(), rp, is_admin=False)
            if ok:
                st.success("Account created — please log in from the Login tab")
            else:
                st.error(msg)

# ---------------------------
# First-time admin setup
# ---------------------------
if user_count() == 0:
    st.title("First-time setup — create admin account")
    st.write("No users found. Please create the admin account.")
    with st.form("admin_setup"):
        admin_name = st.text_input("Admin name")
        admin_email = st.text_input("Admin email")
        admin_pw = st.text_input("Admin password", type="password")
        submitted = st.form_submit_button("Create admin")
        if submitted:
            if not (admin_name and admin_email and admin_pw):
                st.error("Fill everything")
            else:
                ok, msg = create_user(admin_name.strip(), admin_email.strip().lower(), admin_pw, is_admin=True)
                if ok:
                    st.success("Admin created — please log in using the sidebar")
                    st.rerun()
                else:
                    st.error(msg)
    st.stop()

show_login_register()

user = st.session_state['user']

if user:  # logged-in
    if user['is_admin']:
        st.header("Admin dashboard")
        tabs = st.tabs(["Manage Availability", "Bookings", "Settings"])

        with tabs[0]:
            st.subheader("Create availability slots")
            # Add your slot creation form here

        with tabs[1]:
            st.subheader("Bookings")
            # List bookings (use list_bookings(admin_only=True, admin_id=user['id']))

        with tabs[2]:
            st.subheader("Settings")
            # Show SMTP settings form if needed

    else:
        st.header("Book an appointment")
        for i in range(7):
            d = date.today() + timedelta(days=i)
            slots = get_slots_by_date(d)
            if slots:
                st.markdown(f"**{d.isoformat()}**")
                for s in slots:
                    if s['available'] > 0:
                        if st.button(f"Book {s['start'].time().strftime('%H:%M')} — {s['end'].time().strftime('%H:%M')}", key=f"slot_{s['id']}"):
                            ok, msg = book_slot(s['id'], user['id'], user['name'], user['email'], "", "")
                            if ok:
                                st.success(msg)
                            else:
                                st.error(msg)
                    else:
                        st.write(f"{s['start'].time().strftime('%H:%M')} — {s['end'].time().strftime('%H:%M')} (Full)")
            else:
                st.markdown(f"**{d.isoformat()}** — _No slots_")
else:
    # Public availability for visitors (not logged in)
    st.subheader("Public availability (next 7 days)")
    for i in range(7):
        d = date.today() + timedelta(days=i)
        slots = get_slots_by_date(d)
        if slots:
            st.markdown(f"**{d.isoformat()}**")
            for s in slots:
                st.write(f"- {s['start'].time().strftime('%H:%M')} — {s['end'].time().strftime('%H:%M')} (available: {s['available']})")
        else:
            st.markdown(f"**{d.isoformat()}** — _No slots_")
    st.info("Log in to book a slot.")


# Main app content
st.title("Appointments & Booking")
st.markdown("Use the sidebar to log in or register. Once logged in you can book appointments. If you're the admin, you can create availability and export bookings.")

# ---------------------------
# Public availability
# ---------------------------
if not st.session_state['user']:
    st.subheader("Public availability (next 7 days)")
    for i in range(7):
        d = date.today() + timedelta(days=i)
        slots = get_slots_by_date(d)
        if slots:
            st.markdown(f"**{d.isoformat()}**")
            for s in slots:
                st.write(f"- {s['start'].time().strftime('%H:%M')} — {s['end'].time().strftime('%H:%M')} (available: {s['available']})")
        else:
            st.markdown(f"**{d.isoformat()}** — _No slots_")
    st.info("Log in to book a slot.")
    st.stop()
