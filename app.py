from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from flask_socketio import SocketIO, emit, join_room
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash # For password hashing
from functools import wraps # For login_required decorator
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'flaskchatitsasecretkey')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///chat.db')
app.config['SESSION_TYPE'] = 'filesystem'

db = SQLAlchemy(app)
Session(app)
# socketio = SocketIO(app, manage_session=False) # Original
# Simpler setup, SocketIO will use Flask's session if available
socketio = SocketIO(app)

# MODELS
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False) # Store hash, not plain password

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Optional: Relationships for easier data access if needed elsewhere
    # sender = db.relationship('User', foreign_keys=[sender_id], backref=db.backref('sent_messages_rel', lazy='dynamic'))
    # receiver = db.relationship('User', foreign_keys=[receiver_id], backref=db.backref('received_messages_rel', lazy='dynamic'))

# ROUTES
@app.route('/')
def home():
    return render_template('index.html')
  
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        # Check if user exists and then verify the password using the check_password method
        if user and user.check_password(request.form['password']):
            session['user_id'] = user.id
            session['username'] = user.username # Store username for convenience
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('chat'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Username and password are required.', 'warning')
            return render_template('register.html')

        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose a different one.', 'warning')
            return render_template('register.html')

        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        try:
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error during registration: {e}")
            flash('An error occurred during registration. Please try again.', 'danger')

    return render_template('register.html')

# DECORATORS
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/chat')
@login_required
def chat():
    users = User.query.filter(User.id != session['user_id']).all()
    return render_template('chat.html', users=users, user_id=session['user_id'], current_username=session.get('username'))

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/messages/<int:receiver_id>')
@login_required
def get_messages(receiver_id):
    user_id = session['user_id']
    messages = Message.query.filter(
        ((Message.sender_id == user_id) & (Message.receiver_id == receiver_id)) |
        ((Message.sender_id == receiver_id) & (Message.receiver_id == user_id))
    ).order_by(Message.timestamp.asc()).all()

    return jsonify({
        "messages": [
            {
                "id": m.id,
                "content": m.content,
                "sender_id": m.sender_id,
                "timestamp": m.timestamp.strftime('%H:%M')
            } for m in messages
        ]
    })

@app.route('/delete/<int:message_id>', methods=['POST'])
@login_required
def delete_message(message_id):
    message = Message.query.get_or_404(message_id)
    if message.sender_id != session['user_id']:
        flash('You are not authorized to delete this message.', 'danger')
        return redirect(url_for('chat')) # Or return jsonify({"error": "Unauthorized"}), 403

    db.session.delete(message)
    db.session.commit()
    flash('Message deleted successfully.', 'success')
    return redirect(url_for('chat'))

# SOCKET EVENTS
@socketio.on('send_message')
def handle_send_message(data):
    if 'user_id' not in session:
        emit('error', {'message': 'User not authenticated. Please log in.'})
        return

    sender_id = session['user_id']
    receiver_id = data.get('receiver_id')
    content = data.get('content')

    if not receiver_id or not content or not content.strip():
        emit('error', {'message': 'Receiver ID and content are required.'})
        return

    # Ensure receiver exists
    if not User.query.get(receiver_id):
        emit('error', {'message': 'Receiver user does not exist.'})
        return

    msg = Message(sender_id=sender_id, receiver_id=receiver_id, content=content)
    db.session.add(msg)
    db.session.commit()
    sender_user = User.query.get(sender_id)
    message_data = {
        'id': msg.id,
        'content': msg.content,
        'sender_id': sender_id,
        'receiver_id': receiver_id,
        'sender_username': sender_user.username,
        'timestamp': msg.timestamp.strftime('%H:%M') # Consistent format
    }
    # Emit to the receiver's specific room
    socketio.emit('receive_message', message_data, room=str(receiver_id))
    # Emit back to the sender's specific room (for UI update on sender's side, e.g., multiple tabs)
    socketio.emit('receive_message', message_data, room=str(sender_id))

@socketio.on('join')
def on_join(data):
    if 'user_id' in session:
        user_id = session['user_id']
        join_room(str(user_id)) # User joins a room named after their ID
        print(f"User {user_id} ({session.get('username')}) joined room {str(user_id)}")
    else:
        # This case should ideally be prevented by client-side logic
        # (i.e., only emit 'join' after successful login)
        print("Unauthenticated user tried to join.")

@socketio.on('connect')
def on_connect():
    if 'user_id' in session:
        # User is already logged in via Flask session, they can emit 'join'
        print(f"User {session['user_id']} ({session.get('username')}) connected via SocketIO.")
    else:
        print("Anonymous user connected via SocketIO. Waiting for login and 'join' event.")

@socketio.on('disconnect')
def on_disconnect():
    user_id = session.get('user_id', 'Unknown user')
    username = session.get('username', '')
    print(f"User {user_id} ({username}) disconnected.")
    # Flask-SocketIO handles leaving rooms automatically on disconnect by default.

def create_db_and_tables():
    """Creates database tables if they don't exist."""
    with app.app_context():
        db.create_all()
    print("Database tables checked/created.")

if __name__ == '__main__':
    create_db_and_tables()
    socketio.run(
        app,
        debug=bool(os.environ.get("DEBUG", False)),
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 10000))
    )
