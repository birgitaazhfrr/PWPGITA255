from flask import Flask, render_template, request, redirect, session, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    role = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password_hash = db.Column(db.String(200), nullable=False)

@app.before_first_request
def create_tables():
    db.create_all()

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        role = request.form['role']
        email = request.form['email']
        password = request.form['password']

        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, role=role, email=email, password_hash=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except:
            flash('Registration failed. Email or username already exists.', 'danger')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Check your email and password.', 'danger')

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('You need to login first.', 'warning')
        return redirect(url_for('login'))

    users = User.query.all()
    return render_template('dashboard.html', users=users, role=session.get('role'))

@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    if 'user_id' not in session:
        flash('You need to login first.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        username = request.form['username']
        role = request.form['role']
        email = request.form['email']
        password = request.form['password']

        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, role=role, email=email, password_hash=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('User added successfully!', 'success')
            return redirect(url_for('dashboard'))
        except:
            flash('Failed to add user. Email or username might already exist.', 'danger')

    return render_template('add_user.html')

@app.route('/edit_user/<int:id>', methods=['GET', 'POST'])
def edit_user(id):
    if 'user_id' not in session:
        flash('You need to login first.', 'warning')
        return redirect(url_for('login'))

    user = User.query.get_or_404(id)
    if request.method == 'POST':
        user.username = request.form['username']
        user.role = request.form['role']
        user.email = request.form['email']

        try:
            db.session.commit()
            flash('User updated successfully!', 'success')
            return redirect(url_for('dashboard'))
        except:
            flash('Failed to update user.', 'danger')

    return render_template('edit_user.html', user=user)

@app.route('/delete_user/<int:id>', methods=['POST'])
def delete_user(id):
    if 'user_id' not in session:
        flash('You need to login first.', 'warning')
        return redirect(url_for('login'))

    user = User.query.get_or_404(id)
    try:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully!', 'success')
    except:
        flash('Failed to delete user.', 'danger')

    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    if not os.path.exists('users.db'):
        db.create_all()
    app.run(debug=True)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('You need to login first.', 'warning')
        return redirect(url_for('login'))

    users = User.query.all()
    return render_template('dashboard.html', users=users, role=session.get('role'))
