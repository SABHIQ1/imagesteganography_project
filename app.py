from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, login_required, logout_user, LoginManager, current_user
from PIL import Image
import io
import os
import hashlib

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


# User model for database
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)


# LSB-based encoding function (used for steganography)
def steganography_encode(image, message):
    message_binary = ''.join(format(ord(c), '08b') for c in message) + '1111111111111110'
    pixels = image.load()

    data_index = 0
    for y in range(image.height):
        for x in range(image.width):
            r, g, b = pixels[x, y]
            if data_index < len(message_binary):
                r = (r & 0xFE) | int(message_binary[data_index])
                data_index += 1
            if data_index < len(message_binary):
                g = (g & 0xFE) | int(message_binary[data_index])
                data_index += 1
            if data_index < len(message_binary):
                b = (b & 0xFE) | int(message_binary[data_index])
                data_index += 1
            pixels[x, y] = (r, g, b)
            if data_index >= len(message_binary):
                break
    return image


# LSB-based decoding function
def steganography_decode(image):
    pixels = image.load()
    message_binary = ''

    for y in range(image.height):
        for x in range(image.width):
            r, g, b = pixels[x, y]
            message_binary += str(r & 1)
            message_binary += str(g & 1)
            message_binary += str(b & 1)

    message = ''
    for i in range(0, len(message_binary), 8):
        byte = message_binary[i:i + 8]
        if len(byte) == 8:
            char = chr(int(byte, 2))
            if char == '\u00fe':  # End marker
                break
            message += char
    return message


# Load user from the database
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Root Route - Home page or login redirect
@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))  # Redirect to dashboard if logged in
    return redirect(url_for('login'))  # Otherwise, redirect to login page


# Registration Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'error')
            return redirect(url_for('register'))

        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        user = User.query.filter_by(username=username).first()
        if user and user.password == hashed_password:
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Check your username and/or password.', 'error')
    return render_template('login.html')


# Dashboard Route (Image Upload and Steganography)
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        image_file = request.files['image']
        message = request.form['message']

        if image_file and message:
            image = Image.open(image_file)
            encoded_image = steganography_encode(image, message)
            encoded_image_path = os.path.join('static', 'encoded_image.png')
            encoded_image.save(encoded_image_path)
            return render_template('dashboard.html', encoded_image_path=encoded_image_path)

    return render_template('dashboard.html')


# Logout Route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# Ensure database is created within app context
if __name__ == '__main__':
    with app.app_context():  # Ensure app context is set
        db.create_all()  # Create the database
    app.run(debug=True)

