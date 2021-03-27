from flask import Flask, render_template, session, redirect, url_for, flash, request
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os

basedir = os.path.abspath(os.path.dirname(__file__))


app = Flask(__name__)
app.config['SECRET_KEY'] = "secretKey"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'data.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(64), index = True)
    email = db.Column(db.String(30), unique = True, index = True)
    password = db.Column(db.String(50))

class SignUp(FlaskForm):
    name = StringField('What is your name?', validators=[DataRequired()])
    email = StringField('Enter your email-id', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

class Login(FlaskForm):
    email = StringField('Enter your email-id', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    name = None
    email = None
    pasword = None
    form = SignUp()
    if form.validate_on_submit():
        user = User.query.filter_by(email = form.email.data).first()
        if user is None:
            user = User(name = form.name.data,
            email = form.email.data,
            password = generate_password_hash(form.password.data, method = 'sha256'))
            db.session.add(user)
            db.session.commit()
        else:
            flash("You have already signed up, go to the login page!")
        session['name'] = form.name.data
        session['email'] = form.email.data
        session['password'] = form.password.data
        form.name.data = ""
        form.email.data = ""
        form.password.data = ""
    return render_template('signup.html', 
    form = form, 
    name = session.get('name'), 
    email = session.get('email'),
    password = session.get('password'))

@app.route('/login', methods = ['GET', 'POST'])
def login():
    email = None
    pasword = None
    form = Login()
    if form.validate_on_submit():
        email = request.form.get('email')
        password = request.form.get('password')
        user =  User.query.filter_by(email = email).first()
        if not user or not check_password_hash(user.password, password):
            flash('Please check your login details and try again.')
            return redirect(url_for('login'))
        else:
            return render_template('profile.html', name = user.name)
        session['email'] = form.email.data
        session['password'] = form.password.data
        form.email.data = ""
        form.password.data = ""
    return render_template('login.html', 
    form = form,
    email = session.get('email'),
    password = session.get('password'))
