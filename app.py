# app.py
import streamlit as st
import sqlite3
import pandas as pd
from datetime import datetime, date, time, timedelta
import hashlib, secrets, binascii
import smtplib
from email.message import EmailMessage

# ---------------------------
# Database & helper functions
# ---------------------------
DB_PATH = "appointments.db"
conn = sqlite3.connect(DB_PATH, check_same_thread=False)
c = conn.cursor()

def init_db():
    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT UNIQUE,
        salt TEXT,
        pw_hash TEXT,
        is_admin INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );''')

    c.execute('''
    CREATE TABLE IF NOT EXISTS slots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        start_ts TEXT,
        end_ts TEXT,
        capacity INTEGER DEFAULT 1,
        created_by INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );''')

    c.execute('''
    CREATE TABLE IF NOT EXISTS bookings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        slot_id INTEGER,
        user_id INTEGER,
        name TEXT,
        email TEXT,
        phone TEXT,
        notes TEXT,
        status TEXT DEFAULT 'booked',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );''')

    c.execute('''
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    );''')

    conn.commit()

init_db()

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
        c.execute("INSERT INTO users (name,email,salt,pw_hash,is_admin) VALUES (?,?,?,?,?)",
                  (name, email, salt, pw_hash, 1 if is_admin else 0))
        conn.commit()
        return True, "User created"
    except sqlite3.IntegrityError:
        return False, "Email already registered"

def get_user_by_email(email):
    c.execute("SELECT id,name,email,salt,pw_hash,is_admin FROM users WHERE email=?", (email,))
    row = c.fetchone()
    if not row:
        return None
    return {"id": row[0], "name": row[1], "email": row[2], "salt": row[3], "pw_hash": row[4], "is_admin": bool(row[5])}

def authenticate_user(email, password):
    user = get_user_by_email(email)
    if not user:
        return None
    if verify_password(password, user['salt'], user['pw_hash']):
        return user
    return None

def user_count():
    c.execute("SELECT COUNT(*) FROM users")
    return c.fetchone()[0]

# ---------------------------
# Settings
# ---------------------------
def set_setting(key, value):
    c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?,?)", (key, value))
    conn.commit()

def get_setting(key, default=None):
    c.execute("SELECT value FROM settings WHERE key=?", (key,))
    row = c.fetchone()
    return row[0] if row else default

# ---------------------------
# Slots & bookings
# ---------------------------
def create_slot(start_dt: datetime, end_dt: datetime, capacity: int, created_by):
    c.execute("INSERT INTO slots (start_ts,end_ts,capacity,created_by) VALUES (?,?,?,?)",
              (start_dt.isoformat(), end_dt.isoformat(), capacity, created_by))
    conn.commit()

def get_slots_by_date(d: date):
    start_day = datetime.combine(d, time.min).isoformat()
    end_day = datetime.combine(d, time.max).isoformat()
    c.execute("SELECT id,start_ts,end_ts,capacity,created_by FROM slots WHERE start_ts BETWEEN ? AND ? ORDER BY start_ts", (start_day, end_day))
    rows = c.fetchall()
    slots = []
    for r in rows:
        slots.append({
            "id": r[0],
            "start": datetime.fromisoformat(r[1]),
            "end": datetime.fromisoformat(r[2]),
            "capacity": r[3],
            "created_by": r[4],
            "available": slot_available_seats(r[0], r[3])
        })
    return slots

def slot_available_seats(slot_id, capacity):
    c.execute("SELECT COUNT(*) FROM bookings WHERE slot_id=? AND status='booked'", (slot_id,))
    cnt = c.fetchone()[0]
    return max(0, capacity - cnt)

def remove_slot(slot_id):
    c.execute("DELETE FROM bookings WHERE slot_id=?", (slot_id,))
    c.execute("DELETE FROM slots WHERE id=?", (slot_id,))
    conn.commit()

def book_slot(slot_id, user_id, name, email, phone, notes):
    # Check capacity
    c.execute("SELECT capacity FROM slots WHERE id=?", (slot_id,))
    row = c.fetchone()
    if not row:
        return False, "Slot not found"
    capacity = row[0]
    c.execute("SELECT COUNT(*) FROM bookings WHERE slot_id=? AND status='booked'", (slot_id,))
    booked = c.fetchone()[0]
    if booked >= capacity:
        return False, "Slot is full"

    # Prevent same user booking same slot twice (optional)
    c.execute("SELECT COUNT(*) FROM bookings WHERE slot_id=? AND user_id=? AND status='booked'", (slot_id, user_id))
    if c.fetchone()[0] > 0:
        return False, "You already have a booking for this slot"

    c.execute("""INSERT INTO bookings
                 (slot_id,user_id,name,email,phone,notes,status)
                 VALUES (?,?,?,?,?,?,?)""",
              (slot_id, user_id, name, email, phone, notes, 'booked'))
    conn.commit()
    return True, "Booked"

def list_bookings(admin_only=False, admin_id=None):
    # returns joined table of bookings + slot times
    q = """SELECT b.id, b.slot_id, s.start_ts, s.end_ts, b.name, b.email, b.phone, b.notes, b.status, b.created_at
           FROM bookings b JOIN slots s ON b.slot_id = s.id"""
    params = ()
    if admin_only and admin_id is not None:
        q += " WHERE s.created_by = ?"
        params = (admin_id,)
    q += " ORDER BY s.start_ts"
    c.execute(q, params)
    rows = c.fetchall()
    items = []
    for r in rows:
        items.append({
            "booking_id": r[0],
            "slot_id": r[1],
            "start": datetime.fromisoformat(r[2]),
            "end": datetime.fromisoformat(r[3]),
            "name": r[4],
            "email": r[5],
            "phone": r[6],
            "notes": r[7],
            "status": r[8],
            "created_at": r[9]
        })
    return items

def cancel_booking(booking_id):
    c.execute("UPDATE bookings SET status='canceled' WHERE id=?", (booking_id,))
    conn.commit()

# ---------------------------
# Email (optional)
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
# Streamlit UI pieces
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

# If no users exist, show admin-setup on first run
if user_count() == 0:
    st.title("First-time setup — create admin account")
    st.write("No users found. Please create the admin  account.")
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

# Main app content
st.title("Appointments & Booking with Khaled Al-Muraisi")

# Simple landing info
st.markdown("Use the sidebar to log in or register. Once logged in you can book appointments. If you're the admin, you can create availability and export bookings.")

# If user not logged in, show public read-only calendar for next 7 days
if not st.session_state['user']:
    st.subheader("Public availability (next 7 days)")
    days = [date.today() + timedelta(days=i) for i in range(0, 7)]
    for d in days:
        slots = get_slots_by_date(d)
        if slots:
            st.markdown(f"**{d.isoformat()}**")
            for s in slots:
                st.write(f"- {s['start'].time().strftime('%H:%M')} — {s['end'].time().strftime('%H:%M')} (available: {s['available']})")
        else:
            st.markdown(f"**{d.isoformat()}** — _No slots_")
    st.info("Log in to book a slot.")
    st.stop()

user = st.session_state['user']

# Admin dashboard
if user['is_admin']:
    st.header("Admin dashboard")
    tabs = st.tabs(["Manage Availability", "Bookings", "Settings"])

    with tabs[0]:
        st.subheader("Create repeating availability slots")
        with st.form("create_slots"):
            start_date = st.date_input("Start date", date.today())
            end_date = st.date_input("End date", date.today() + timedelta(days=7))
            row = st.columns(2)
            start_time = row[0].time_input("Daily start time", time(hour=9, minute=0))
            end_time = row[1].time_input("Daily end time", time(hour=17, minute=0))
            duration = st.number_input("Slot duration (minutes)", min_value=5, max_value=480, value=30)
            capacity = st.number_input("Capacity per slot", min_value=1, value=1)
            days_of_week = st.multiselect("Days of week (leave empty for all days)", ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"], default=["Mon","Tue","Wed","Thu","Fri"])
            submit_slots = st.form_submit_button("Create slots")
            if submit_slots:
                if end_date < start_date:
                    st.error("End date must be >= start date")
                else:
                    created = 0
                    dow_map = {"Mon":0,"Tue":1,"Wed":2,"Thu":3,"Fri":4,"Sat":5,"Sun":6}
                    allowed = set(dow_map[d] for d in days_of_week) if days_of_week else set(range(7))
                    cur_date = start_date
                    while cur_date <= end_date:
                        if cur_date.weekday() in allowed:
                            dt_cursor = datetime.combine(cur_date, start_time)
                            dt_end_of_day = datetime.combine(cur_date, end_time)
                            while dt_cursor + timedelta(minutes=duration) <= dt_end_of_day:
                                create_slot(dt_cursor, dt_cursor + timedelta(minutes=duration), int(capacity), user['id'])
                                created += 1
                                dt_cursor += timedelta(minutes=duration)
                        cur_date += timedelta(days=1)
                    st.success(f"Created {created} slots")

        st.markdown("---")
        st.subheader("Existing slots (next 30 days)")
        today = date.today()
        rows = []
        for i in range(0, 30):
            d = today + timedelta(days=i)
            for s in get_slots_by_date(d):
                rows.append({
                    "id": s['id'],
                    "date": s['start'].date().isoformat(),
                    "start": s['start'].time().strftime("%H:%M"),
                    "end": s['end'].time().strftime("%H:%M"),
                    "capacity": s['capacity'],
                    "available": s['available']
                })
        if rows:
            df = pd.DataFrame(rows)
            st.dataframe(df)
            sel = st.number_input("Enter slot id to delete (deletes any bookings for that slot)", min_value=0, step=1)
            if st.button("Delete slot"):
                if sel > 0:
                    remove_slot(int(sel))
                    st.success(f"Deleted slot {sel}")
                    st.rerun()
        else:
            st.write("No upcoming slots")

    with tabs[1]:
        st.subheader("Bookings")
        bookings = list_bookings(admin_only=True, admin_id=user['id'])
        if bookings:
            dfb = pd.DataFrame(bookings)
            dfb_display = dfb.copy()
            dfb_display['start'] = dfb_display['start'].dt.strftime("%Y-%m-%d %H:%M")
            dfb_display['end']   = dfb_display['end'].dt.strftime("%Y-%m-%d %H:%M")
            st.dataframe(dfb_display)
            # Download CSV
            csv = dfb.to_csv(index=False)
            st.download_button("Download bookings CSV", csv, file_name="bookings.csv", mime="text/csv")
            # Cancel a booking
            bid = st.number_input("Enter booking id to cancel", min_value=0, step=1)
            if st.button("Cancel booking"):
                if bid > 0:
                    cancel_booking(int(bid))
                    st.success(f"Canceled booking {bid}")
                    st.experimental_rerun()
        else:
            st.write("No bookings yet")

    with tabs[2]:
        st.subheader("Settings (email confirmations)")
        st.info("If you want the app to email confirmations set SMTP details below. Leave blank to skip email.")
        with st.form("smtp"):
            smtp_host = st.text_input("SMTP host", value=get_setting("smtp_host") or "")
            smtp_port = st.text_input("SMTP port", value=get_setting("smtp_port") or "587")
            smtp_user = st.text_input("SMTP username", value=get_setting("smtp_user") or "")
            smtp_pass = st.text_input("SMTP password", type="password", value=get_setting("smtp_pass") or "")
            from_email = st.text_input("From email", value=get_setting("from_email") or "")
            if st.form_submit_button("Save SMTP settings"):
                set_setting("smtp_host", smtp_host)
                set_setting("smtp_port", smtp_port)
                set_setting("smtp_user", smtp_user)
                set_setting("smtp_pass", smtp_pass)
                set_setting("from_email", from_email)
                st.success("Settings saved")

    st.stop()

# ---------------------------
# Booking UI for normal users
# ---------------------------
st.header("Book an appointment")
st.write(f"Hello, **{user['name']}** — pick a date and choose a free slot.")

col1, col2 = st.columns([1,2])
with col1:
    chosen_date = st.date_input("Pick a date", date.today())
    slots = get_slots_by_date(chosen_date)
    if not slots:
        st.info("No slots on that date")
    else:
        st.write("Available slots:")
        slot_options = [f"{s['id']} — {s['start'].time().strftime('%H:%M')} to {s['end'].time().strftime('%H:%M')} (available: {s['available']})" for s in slots]
        selection = st.selectbox("Choose a slot", slot_options)
        chosen_index = slot_options.index(selection)
        chosen_slot = slots[chosen_index] if slots else None

with col2:
    if slots:
        st.subheader("Booking details")
        b_name = st.text_input("Your name", value=user['name'])
        b_email = st.text_input("Email", value=user['email'])
        b_phone = st.text_input("Phone (optional)")
        b_notes = st.text_area("Notes (optional)")
        if st.button("Book now"):
            if not chosen_slot:
                st.error("Pick a slot first")
            else:
                success, msg = book_slot(chosen_slot['id'], user['id'], b_name.strip(), b_email.strip().lower(), b_phone.strip(), b_notes.strip())
                if success:
                    st.success("Booked! ✅")
                    # Optionally send email
                    smtp_ok, smtp_msg = send_email_smtp(
                        f"Booking confirmation for {chosen_slot['start'].strftime('%Y-%m-%d %H:%M')}",
                        f"Hi {b_name},\n\nYour booking for {chosen_slot['start'].strftime('%Y-%m-%d %H:%M')} - {chosen_slot['end'].strftime('%H:%M')} is confirmed.\n\nThanks!",
                        b_email
                    )
                    if smtp_ok:
                        st.info("Confirmation email sent")
                    else:
                        # only show message if smtp configured (msg contains reason)
                        if get_setting("smtp_host"):
                            st.warning(f"Could not send email: {smtp_msg}")
                    st.experimental_rerun()
                else:
                    st.error(msg)

st.markdown("---")
st.subheader("My bookings")
my_bookings = [b for b in list_bookings() if b['email'] == user['email'] or b.get('user_id') == user['id']]
if my_bookings:
    mydf = pd.DataFrame(my_bookings)
    mydf['start'] = mydf['start'].dt.strftime("%Y-%m-%d %H:%M")
    mydf['end'] = mydf['end'].dt.strftime("%Y-%m-%d %H:%M")
    st.dataframe(mydf)
    bid = st.number_input("Enter booking id to cancel", min_value=0, step=1, key="cancel_input")
    if st.button("Cancel my booking"):
        if bid > 0:
            cancel_booking(int(bid))
            st.success("Canceled")
            st.experimental_rerun()
else:
    st.write("You have no bookings yet.")
