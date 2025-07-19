import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, get_flashed_messages
from flask_mail import Mail, Message
import MySQLdb
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime, timedelta
import logging
from config import *
from dotenv import load_dotenv
load_dotenv()


app = Flask(__name__)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False
app.secret_key = os.environ.get('SECRET_KEY')  # ✅ Get from env

# Mail config
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')  # ✅
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')  # ✅
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')  # Optional

mail = Mail(app)

# MySQL config
db = MySQLdb.connect(
    host=os.environ.get('MYSQL_HOST'),
    user=os.environ.get('MYSQL_USER'),
    passwd=os.environ.get('MYSQL_PASSWORD'),
    db=os.environ.get('MYSQL_DB'),
    charset='utf8mb4'
)
cursor = db.cursor()

# Logging
logging.basicConfig(level=logging.INFO)

# Scheduler
scheduler = BackgroundScheduler()

# MySQL Connection (single global connection and cursor)
db = MySQLdb.connect(
    host=MYSQL_HOST,
    user=MYSQL_USER,
    passwd=MYSQL_PASSWORD,
    db=MYSQL_DB,
    charset='utf8mb4'
)
cursor = db.cursor()

mail = Mail(app)  # Setup Flask-Mail if needed

# Home route redirects to login
@app.route('/')
def home():
    return redirect('/login')

# Signup route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        department = request.form['department']
        role = request.form['role']
        secret_key = request.form.get('secret_key', '').strip()
        
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template('signup.html')
        hashed_password = generate_password_hash(password)  # ✅ hash after check

        # Validate role and secret key for head/admin
        if role in ['admin', 'head']:
            if role == 'admin' and secret_key != ADMIN_SECRET_KEY:
                flash("Invalid Admin Secret Key.", "danger")
                return render_template('signup.html')
            if role == 'head' and secret_key != HEAD_SECRET_KEY:
                flash("Invalid Head Secret Key.", "danger")
                return render_template('signup.html')
        elif role == 'user':
            # No secret key needed for normal users
            pass
        else:
            flash("Invalid role selected.", "danger")
            return render_template('signup.html')

        # Set is_admin boolean flag in DB for admin role only
        is_admin = True if role == 'admin' else False

        try:
            cursor.execute("""
                INSERT INTO users (name, email, password, department, is_admin, role)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (name, email, hashed_password, department, is_admin, role))
            db.commit()
            flash("Signup successful! Please login.", "success")
            print("Flashed messages:", get_flashed_messages(with_categories=True))

            return redirect('/login')
        except Exception as e:
            db.rollback()
            print("Error:", e)
            flash("Email already exists or invalid input.", "danger")

    return render_template('signup.html')


# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password'].strip()
        
        # Fetch hashed password as well
        cursor.execute("SELECT id, name, password, role FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['name'] = user[1]
            session['role'] = user[3]

            if user[3] == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user[3] == 'head':
                return redirect(url_for('head_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            flash("Invalid credentials", "danger")

    return render_template("login.html")

# Logout route
@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect('/login')


@app.route('/user_dashboard')
def user_dashboard():
    if 'user_id' not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for('login'))

    user_id = session['user_id']
    name = session.get('name')

    cursor.execute(
        "SELECT id, title, status, priority, created_at FROM tickets WHERE created_by = %s",
        (user_id,)
    )
    tickets = cursor.fetchall()

    return render_template('user_dashboard.html', name=name, tickets=tickets)



@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user:
            reset_token = str(uuid.uuid4())
            cursor.execute("UPDATE users SET reset_token = %s WHERE id = %s", (reset_token, user[0]))
            db.commit()

            reset_link = url_for('reset_password', token=reset_token, _external=True)
            send_email(email, "Password Reset", f"Click to reset: {reset_link}")
            flash("Reset link sent to your email.", "info")
        else:
            flash("Email not found.", "danger")
    print("Flashed messages:", get_flashed_messages(with_categories=True))
    return render_template('forgot_password.html')
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    cursor.execute("ALTER TABLE users ADD COLUMN reset_token VARCHAR(255)")
    db.commit()

    if request.method == 'POST':
        new_pass = request.form['password']
        confirm = request.form['confirm_password']

        if new_pass != confirm:
            flash("Passwords do not match.", "danger")
            print("Flashed messages:", get_flashed_messages(with_categories=True))

            return render_template('reset_password.html')

        hashed = generate_password_hash(new_pass)
        cursor.execute("UPDATE users SET password = %s, reset_token = NULL WHERE reset_token = %s", (hashed, token))
        db.commit()
        flash("Password reset successful! Please login.", "success")
        print("Flashed messages:", get_flashed_messages(with_categories=True))

        return redirect('/login')

    # Check if token is valid
    cursor.execute("SELECT id FROM users WHERE reset_token = %s", (token,))
    if not cursor.fetchone():
        flash("Invalid or expired reset token.", "danger")
        return redirect('/login')
    print("Flashed messages:", get_flashed_messages(with_categories=True))
    return render_template('reset_password.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))

    user_id = session['user_id']

    # Fetch only tickets assigned to the logged-in admin
    query = """
        SELECT t.id, t.title, u.name, t.priority, t.status, t.created_at, t.ticket_type
        FROM tickets t
        LEFT JOIN users u ON t.created_by = u.id
        WHERE t.assigned_to = %s
        ORDER BY t.created_at DESC
    """

    cursor.execute(query, (user_id,))
    tickets = cursor.fetchall()

    return render_template(
        'admin_dashboard.html',
        tickets=tickets,
        name=session.get('name')
    )

@app.route('/submit_ticket', methods=['GET', 'POST'])
def submit_ticket():
    if 'user_id' not in session:
        return redirect('/login')
    
    # ✅ Fetch all admins to show in dropdown
    cursor.execute("SELECT id, name FROM users WHERE role = 'admin'")
    admins = cursor.fetchall()

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        priority = request.form['priority']
        ticket_type = request.form['ticket_type']
        assigned_to = request.form['assigned_to'] or None
        created_by = session['user_id']

        try:
            # ✅ Insert the ticket
            cursor.execute("""
                INSERT INTO tickets (title, description, priority, status, created_by, ticket_type, assigned_to)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (title, description, priority, 'Open', created_by, ticket_type, assigned_to))
            db.commit()

            # ✅ Send email to assigned admin
            if assigned_to:
                cursor.execute("SELECT name, email FROM users WHERE id = %s", (assigned_to,))
                result = cursor.fetchone()
                if result:
                    admin_name, admin_email = result
                    # Fetch current user's name (who is submitting the ticket)
                    cursor.execute("SELECT name FROM users WHERE id = %s", (created_by,))
                    creator_name = cursor.fetchone()[0]
                    subject = "New Ticket Assigned to You"
                    body = f"""Hello {admin_name},

A new ticket has been submitted by {creator_name}.

Title     : {title}
Priority  : {priority}
Type      : {ticket_type}

Please log in to the system to review the ticket.

Thanks & Regards,
CrossPoint Technologies,
Tickets Master-Team.
"""
                    send_email(admin_email, subject, body)

            flash("Ticket submitted successfully.", "success")
            #print("Flashed messages:", get_flashed_messages(with_categories=True))

            return redirect('/user_dashboard')
        except Exception as e:
            db.rollback()
            print("Error:", e)
            flash("Failed to submit ticket.", "danger")
            #print("Flashed messages:", get_flashed_messages(with_categories=True))

    return render_template('submit_ticket.html', admins=admins)

# --- Update status route ---
@app.route('/update_status/<int:ticket_id>', methods=['POST'])
def update_status(ticket_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized access.', 'danger')
        print("Flashed messages:", get_flashed_messages(with_categories=True))

        return redirect(url_for('login'))

    new_status = request.form.get('status')
    if not new_status:
        flash('Status is required.', 'danger')
        print("Flashed messages:", get_flashed_messages(with_categories=True))

        return redirect(url_for('view_ticket', ticket_id=ticket_id))

    # ✅ Update the status
    cursor.execute("UPDATE tickets SET status = %s WHERE id = %s", (new_status, ticket_id))
    db.commit()
    flash('Ticket status updated successfully.', 'success')
    print("Flashed messages:", get_flashed_messages(with_categories=True))


    # ✅ Fetch user's email and ticket info for email
    cursor.execute("""
        SELECT u.email, u.name, t.title
        FROM tickets t
        JOIN users u ON t.created_by = u.id
        WHERE t.id = %s
    """, (ticket_id,))
    result = cursor.fetchone()

    if result:
        user_email, raised_by_name, ticket_title = result

        subject = f"Your Ticket #{ticket_id} Status Updated"
        body = f"""Hello {raised_by_name},

Your ticket (ID: {ticket_id}, "{ticket_title}") status has been updated to: {new_status}.

You can log in to view the details.

Thanks & Regards,
CrossPoint Technologies,
Tickets Master-Team.

"""

        send_email(user_email, subject, body)

    return redirect(url_for('view_ticket', ticket_id=ticket_id))


# --- Forward ticket to head ---
@app.route('/forward_to_head/<int:ticket_id>', methods=['POST'])
def forward_to_head(ticket_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))
    
    # ✅ Get the admin name
    cursor.execute("SELECT name FROM users WHERE id = %s", (session['user_id'],))
    admin_name = cursor.fetchone()[0]

    # Check if already forwarded
    cursor.execute("SELECT forwarded_to_head FROM tickets WHERE id = %s", (ticket_id,))
    result = cursor.fetchone()
    if not result:
        flash('Ticket not found.', 'danger')
        print("Flashed messages:", get_flashed_messages(with_categories=True))

        return redirect(url_for('admin_dashboard'))

    if result[0]:
        print("Flashed messages:", get_flashed_messages(with_categories=True))

        flash('Ticket already forwarded to head.', 'info')
    else:
        # ✅ Mark as forwarded
        cursor.execute("UPDATE tickets SET forwarded_to_head = 1 WHERE id = %s", (ticket_id,))
        db.commit()
        print("Flashed messages:", get_flashed_messages(with_categories=True))

        flash('Ticket forwarded to head.', 'success')

        # ✅ Fetch title for email
        cursor.execute("SELECT title FROM tickets WHERE id = %s", (ticket_id,))
        ticket_title = cursor.fetchone()[0]

        # ✅ Send email to all heads
        cursor.execute("SELECT name, email FROM users WHERE role = 'head'")
        heads = cursor.fetchall()
        for ( head_name, head_email,) in heads:
            subject = f"Ticket #{ticket_id} Forwarded to You"
            body = f"""Hello {head_name},

Ticket ID: {ticket_id} ("{ticket_title}") has been forwarded to you for review 
by {admin_name}.

Please log in to assign it to an appropriate admin.

Thanks & Regards,
CrossPoint Technologies,
Tickets Master-Team.
"""
            send_email(head_email, subject, body)

    return redirect(url_for('view_ticket', ticket_id=ticket_id))

# --- Dashboards ---
@app.route('/head_dashboard')
def head_dashboard():
    if 'user_id' not in session or session.get('role') != 'head':
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))

    cursor.execute("""
    SELECT t.id, t.title, t.status, t.priority, t.status, a.name, t.ticket_type
    FROM tickets t
    LEFT JOIN users a ON t.assigned_to = a.id
    WHERE t.forwarded_to_head = 1
    ORDER BY t.id DESC
""")

    tickets = cursor.fetchall()
    return render_template('head_dashboard.html', tickets=tickets, name=session.get('name'))

@app.route('/ticket/<int:ticket_id>', methods=['GET', 'POST'])
def view_ticket(ticket_id):
    if 'user_id' not in session:
        flash("You must be logged in", "warning")
        return redirect(url_for('login'))

    user_id = session['user_id']
    role = session.get('role')

    # Get sender's name for email use
    cursor.execute("SELECT name FROM users WHERE id = %s", (user_id,))
    sender_name = cursor.fetchone()[0]

    # Fetch ticket details
    cursor.execute("""
        SELECT t.id, t.title, t.description, t.status, t.priority, u.name, t.created_at, t.ticket_type,
               a.name, t.assigned_to, t.forwarded_to_head, t.created_by, t.is_acknowledged_by_admin, t.closed_at
        FROM tickets t
        LEFT JOIN users u ON t.created_by = u.id
        LEFT JOIN users a ON t.assigned_to = a.id
        WHERE t.id = %s
    """, (ticket_id,))
    ticket = cursor.fetchone()

    if not ticket:
        flash("Ticket not found.", "danger")
        return redirect(url_for(f'{role}_dashboard'))

    ticket_data = {
        'id': ticket[0],
        'title': ticket[1],
        'description': ticket[2],
        'status': ticket[3],
        'priority': ticket[4],
        'raised_by': ticket[5],
        'created_at': ticket[6],
        'ticket_type': ticket[7],
        'assigned_admin': ticket[8],
        'assigned_to': ticket[9],
        'forwarded_to_head': ticket[10],
        'created_by': ticket[11],
        'is_acknowledged_by_admin': ticket[12],
        'closed_at': ticket[13]
    }

    # Check role-based access
    if role == 'user':
        if ticket_data['created_by'] != user_id:
            flash("Access denied: This is not your ticket.", "danger")
            return redirect(url_for('user_dashboard'))
        is_assigned = False
    elif role == 'admin':
        is_assigned = (ticket_data['assigned_to'] == user_id)
    elif role == 'head':
        is_assigned = False
    else:
        flash("Access denied.", "danger")
        return redirect(url_for('login'))

    # POST Logic (Acknowledge, Update, Assign, Comment, Forward)
    if request.method == 'POST':

        # ✅ Acknowledge Ticket
        if role == 'admin' and 'acknowledge_ticket' in request.form:
            cursor.execute("UPDATE tickets SET is_acknowledged_by_admin = 1 WHERE id = %s", (ticket_id,))
            db.commit()

            # Notify user
            cursor.execute("SELECT email, name FROM users WHERE id = %s", (ticket_data['created_by'],))
            user_email, creator_name = cursor.fetchone()
            send_email(
                user_email,
                f"Your Ticket #{ticket_id} Has Been Acknowledged",
                f"Hello {creator_name},\n\nYour ticket has been acknowledged by Admin {sender_name}."
            )
            flash("Ticket acknowledged and user notified.", "success")
            return redirect(url_for('view_ticket', ticket_id=ticket_id))

        # ✅ Add Comment
        if 'comment' in request.form:
            comment_text = request.form['comment'].strip()
            if comment_text:
                cursor.execute("""
                    INSERT INTO comments (ticket_id, comment, created_at, commented_by)
                    VALUES (%s, %s, NOW(), %s)
                """, (ticket_id, comment_text, user_id))
                db.commit()
                flash("Comment added.", "success")
            return redirect(url_for('view_ticket', ticket_id=ticket_id))

        # ✅ Assign Ticket (Head Only)
        if role == 'head' and 'dept_admin' in request.form:
            assigned_id = request.form['dept_admin']
            cursor.execute("UPDATE tickets SET assigned_to = %s WHERE id = %s", (assigned_id, ticket_id))
            db.commit()

            # Email the assigned admin
            cursor.execute("SELECT name, email FROM users WHERE id = %s", (assigned_id,))
            admin_name, admin_email = cursor.fetchone()
            send_email(
                admin_email,
                f"Ticket #{ticket_id} Assigned to You",
                f"Hello {admin_name},\n\nTicket \"{ticket_data['title']}\" has been assigned to you by Head {sender_name}."
            )

            flash("Ticket assigned to admin.", "success")
            return redirect(url_for('view_ticket', ticket_id=ticket_id))

        # ✅ Update Status (Admin)
        if role == 'admin' and 'status' in request.form:
            new_status = request.form['status']

            # If status is changed to 'Resolved', set closed_at timestamp
            if new_status == 'Resolved':
                cursor.execute("""
                UPDATE tickets 
                SET status = %s, closed_at = NOW() 
                WHERE id = %s
                 """, (new_status, ticket_id))
            else:
                cursor.execute("""
                UPDATE tickets 
                SET status = %s 
                WHERE id = %s
            """, (new_status, ticket_id))

            db.commit()

            # Notify user
            cursor.execute("SELECT email, name FROM users WHERE id = %s", (ticket_data['created_by'],))
            user_email, creator_name = cursor.fetchone()

            send_email(
            user_email,
            f"Ticket #{ticket_id} Status Updated",
            f"Hello {creator_name},\n\nYour ticket status has been updated to: {new_status} by {sender_name}."
     )

            flash("Status updated.", "success")
            return redirect(url_for('view_ticket', ticket_id=ticket_id))


        # ✅ Forward to Head
        if role == 'admin' and 'forward_to_head' in request.form:
            cursor.execute("UPDATE tickets SET forwarded_to_head = 1 WHERE id = %s", (ticket_id,))
            db.commit()

            # Email all heads
            cursor.execute("SELECT name, email FROM users WHERE role = 'head'")
            for head_name, head_email in cursor.fetchall():
                send_email(
                    head_email,
                    f"Ticket #{ticket_id} Forwarded to You",
                    f"Hello {head_name},\n\nAdmin {sender_name} has forwarded ticket #{ticket_id} to you."
                )

            flash("Ticket forwarded to head.", "info")
            return redirect(url_for('view_ticket', ticket_id=ticket_id))

    # Get comments
    cursor.execute("""
        SELECT c.comment, c.created_at, u.name
        FROM comments c
        LEFT JOIN users u ON c.commented_by = u.id
        WHERE c.ticket_id = %s
        ORDER BY c.created_at DESC
    """, (ticket_id,))
    comments = cursor.fetchall()

    # Admins for head assignment
    admins = []
    if role == 'head':
        cursor.execute("SELECT id, name, email FROM users WHERE role = 'admin'")
        admins = cursor.fetchall()

    return render_template(
        'view_ticket.html',
        ticket=ticket_data,
        comments=comments,
        role=role,
        admins=admins,
        is_assigned=is_assigned
    )
# Assign ticket to admin (POST only)
@app.route('/assign_ticket/<int:ticket_id>', methods=['POST'])
def assign_ticket(ticket_id):
    if 'user_id' not in session or session.get('role') != 'head':
        flash("You do not have permission to assign this ticket.", "danger")
        return redirect('/head_dashboard')

    admin_id = request.form.get('dept_admin')
    if not admin_id:
        flash("Please select an admin to assign.", "danger")
        return redirect(f'/ticket/{ticket_id}')

    try:
        cursor.execute("UPDATE tickets SET assigned_to = %s WHERE id = %s", (admin_id, ticket_id))
        db.commit()

        cursor.execute("SELECT name FROM users WHERE id = %s", (admin_id,))
        admin_name = cursor.fetchone()[0]

        flash(f"Ticket assigned to {admin_name} successfully.", "success")
    except Exception as e:
        db.rollback()
        flash("Failed to assign the ticket. Please try again.", "danger")
        print("Error:", e)

    return redirect(f'/ticket/{ticket_id}')

def send_email(to, subject, body):
    try:
        msg = Message(subject, recipients=[to], body=body)
        mail.send(msg)
        print(f"[MAIL SENT] To: {to}")
    except Exception as e:
        print(f"[MAIL ERROR] {e}")

def check_unacknowledged_tickets():
    with app.app_context():
        threshold = datetime.now() - timedelta(hours=24)
        cursor.execute("""
            SELECT t.id, t.title, t.created_at, u.name, u.email
            FROM tickets t
            JOIN users u ON u.role = 'head'
            WHERE t.is_acknowledged_by_admin = 0
              AND t.assigned_to IS NOT NULL
              AND t.created_at < %s
        """, (threshold,))
        tickets = cursor.fetchall()

        for tid, title, created_at, head_name, head_email in tickets:
            subject = f"⚠️ Ticket #{tid} Unacknowledged for 24+ hrs"
            body = f"""Dear {head_name},

The ticket below has not been acknowledged in over 24 hours:

Ticket ID: {tid}
Title: {title}
Created At: {created_at.strftime('%Y-%m-%d %H:%M')}

Please review this on your dashboard.

Thanks & Regards,
CrossPoint Technologies,
Tickets Master-Team
"""
            send_email(head_email, subject, body)
            logging.info(f"Email sent to {head_email} for Ticket #{tid}")

# Start scheduler
scheduler.add_job(check_unacknowledged_tickets, 'interval', hours=1)
scheduler.start()

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
    app.run(debug=True)
