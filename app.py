# app.py
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from passlib.hash import pbkdf2_sha256

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'razdwatrzyrazdwatrzy'  # secret key

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    note = db.Column(db.Text)  # Dodane pole dla notatek

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']

        existing_user = User.query.filter_by(email=email).first()

        if existing_user:
            flash('Email w użyciu, proszę użyj innego.', 'error')
            return redirect(url_for('register'))

        hashed_password = pbkdf2_sha256.hash(password)

        new_user = User(first_name=first_name, last_name=last_name, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('profile', username=email))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user and pbkdf2_sha256.verify(password, user.password):
            session['user_id'] = user.id
            return redirect(url_for('profile', username=user.email))
        else:
            flash('Błędne dane logowania. Spróbuj ponownie.', 'error')

    return render_template('login.html')

@app.route('/profile/<username>', methods=['GET', 'POST'])
def profile(username):
    user = User.query.filter_by(email=username).first()

    if not user:
        return redirect(url_for('index'))

    if request.method == 'POST':
        user.first_name = request.form['first_name']
        user.last_name = request.form['last_name']
        new_email = request.form['email']
        user.note = request.form['note']  # Dodanie notatki do bazy danych

        existing_user = User.query.filter_by(email=new_email).first()
        if existing_user and existing_user.id != user.id:
            flash('Email już w użyciu proszę wybierz inny.', 'error')
        else:
            user.email = new_email
            db.session.commit()
            flash('Profil zaktualizowany!', 'success')

        new_password = request.form['password']
        if new_password:
            hashed_password = pbkdf2_sha256.hash(new_password)
            user.password = hashed_password
            db.session.commit()
            flash('Hasło zaktualizowane!', 'success')

    return render_template('profile.html', user=user)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        users = User.query.all()
        for user in users:
            print(f"ID: {user.id}, Email: {user.email}")
    app.run(debug=True)
