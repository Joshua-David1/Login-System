from flask import Flask, render_template, url_for, redirect, session, g, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, EmailField
from wtforms.validators import DataRequired, InputRequired,ValidationError, Regexp, EqualTo, Email
from flask_login import LoginManager, login_user, UserMixin, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from datetime import timedelta
from random import randrange
import smtplib, ssl
from decouple import config

email_pass = config('password')
from_email = config('from_email')


app = Flask(__name__)
app.config['SECRET_KEY'] = "Don't Care"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user-data-collection.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

otp_requested = False
otp = None
fp_username = None

@login_manager.user_loader
def load_user(user_id):
	return User.query.get(user_id)

class User(UserMixin, db.Model):
	id = db.Column(db.Integer, primary_key = True)
	username = db.Column(db.String(50), unique=True, nullable=False)
	email = db.Column(db.String(50), unique=True, nullable=False)
	password = db.Column(db.String(50), nullable = False)

db.create_all()

def otp_check(form, field):
	print(str(otp))
	print(field.data)
	if str(otp) != field.data:
		raise ValidationError("[-]OTP is wrong")

def min_char_check(form, field):
    if len(field.data) < 6:
        raise ValidationError('Minimum 6 characters required[!]')

class Email_check(object):
	def __init__(self):
		self.message = "[-]Email Already taken"

	def __call__(self, form, field):
		user = User.query.filter_by(email = field.data).first()
		if user:
			raise ValidationError(self.message)

email_check = Email_check

class User_check(object):
    def __init__(self, register = False):
        self.register = register
        self.login_message = "user unavailable[!]"
        self.register_message = "user already exists[!]"

    def __call__(self, form, field):
        if self.register:
            user = User.query.filter_by(username = field.data).first()
            if user:
                raise ValidationError(self.register_message)
        else:
            user = User.query.filter_by(username = field.data).first()
            if user == None:
                    raise ValidationError(self.login_message)


user_check = User_check

class Pass_check(object):
    def __init__(self):
        self.error_message = "Incorrect Password[-]"

    def __call__(self, form, field):
        user = User.query.filter_by(username = form.username.data).first()
        if user is None or field.data != user.password:
            raise ValidationError('Password Incorrect[-]')
                    

pass_check = Pass_check

class LoginForm(FlaskForm):
	username = StringField('username', render_kw={"placeholder":"Username","maxlength":25} ,validators=[DataRequired(message="[!] Enter username"), user_check()])
	password = PasswordField('password', render_kw={"placeholder":"Password", "maxlength":20},validators=[DataRequired(message="[!] Enter password"), min_char_check, pass_check()])

class RegisterForm(FlaskForm):
	email = EmailField('email',render_kw={"placeholder":"Email","maxlength":40}, validators=[DataRequired(message="Enter email"),min_char_check, email_check(),Email("Enter a vail email")])
	username = StringField('username', render_kw={"placeholder":"Username","maxlength":25},validators=[InputRequired(message="[!] Enter username"), min_char_check,user_check(register = True), Regexp("^[\w]*$", message="Only letter, numbers and underscore."),Regexp("^[a-z\_0-9]*$", message="Only small letters"), Regexp("^[a-z\_]+[a-z\_0-9]*$", message="Cannot begin with numbers") ])
	password = PasswordField('password',render_kw={"placeholder":"Password","maxlength":20},validators=[InputRequired(message="[!] Enter password[!]"),min_char_check])

class ChangePasswordForm(FlaskForm):
    new_password = PasswordField('new_password', render_kw={"placeholder":"Enter new password","maxlength":20}, validators = [InputRequired(message="Enter new password"), min_char_check, EqualTo('confirm_password', message="Passwords must match")])
    confirm_password = PasswordField('confirm_password', render_kw={"placeholder":"Re-type password"})

class ForgetPassForm(FlaskForm):
	username = StringField('usernane', render_kw={"placeholder":"Username","maxlength":25}, validators=[InputRequired(message="[!] Enter username"), user_check()])

class OTPForm(FlaskForm):
	otp = StringField('otp', render_kw={"placeholder":"Enter OTP","maxlength":4}, validators=[InputRequired(message="Enter OTP"), otp_check])


@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(hours=10)
    session.modified = True
    g.user = current_user

@app.route("/")
def home_page():
	return redirect(url_for('login_page'))

@app.route("/login", methods=["GET","POST"])
def login_page():
	if not current_user.is_authenticated:
		form = LoginForm()
		if form.validate_on_submit():
			user = User.query.filter_by(username=form.username.data).first()
			login_user(user)
			return redirect(url_for('welcome_page'))
		return render_template('login.html',form=form)
	return redirect(url_for('welcome_page'))

@app.route("/register", methods=["GET","POST"])
def register_page():
	if not current_user.is_authenticated:
		form = RegisterForm()
		if form.validate_on_submit():
			email = form.email.data
			username = form.username.data
			password = form.password.data
			new_user = User(email = email, username = username, password = password)
			db.session.add(new_user)
			db.session.commit()
			login_user(new_user)
			return redirect(url_for('welcome_page'))
		return render_template('register.html',form = form)
	return redirect(url_for('welcome_page'))

@app.route("/welcome")
def welcome_page():
	if current_user.is_authenticated:
		return render_template('welcome.html')
	return redirect(url_for('home_page'))

@app.route("/forget-password", methods = ["POST","GET"])
def forget_password_page():
	global otp_requested
	global fp_username
	form = ForgetPassForm()
	if form.validate_on_submit():
		username = form.username.data
		user = User.query.filter_by(username = username).first()
		if user == None:
			return render_template('forget-pass.html', form=form)
		otp_requested = True
		fp_username = username
		return redirect(url_for('otp_page'))
	return render_template('forget-pass.html', form = form)

@app.route("/otp", methods=["POST","GET"])
def otp_page():
	global otp
	if otp_requested:
		form = OTPForm()
		if form.validate_on_submit():
			change_pass_form = ChangePasswordForm()
			return redirect(url_for('change_pass_page'))
		otp = randrange(1000,9999)
		to_email = User.query.filter_by(username=fp_username).first().email
		with smtplib.SMTP("smtp.gmail.com") as connection:
			connection.starttls()
			connection.login(user=from_email,password=email_pass)
			connection.sendmail(from_addr=from_email,to_addrs=to_email,msg=f"Subject:OTP\n\nYour OTP is :{otp}")
			return render_template('otp.html',form = form)
	return redirect(url_for('home_page'))


@app.route("/change_password", methods=["POST","GET"])
def change_pass_page():
	global fp_username, otp, otp_requested
	if fp_username != None:
		form = ChangePasswordForm()
		if form.validate_on_submit():
			new_password = form.new_password.data
			user = User.query.filter_by(username=fp_username).first()
			user.password = new_password
			db.session.commit()
			login_user(user)
			fp_username = None
			otp = None
			otp_requested = False
			return redirect(url_for('welcome_page'))
		return render_template('change-pass.html',form=form)
	return redirect(url_for('home_page'))


@app.route("/logout",methods=["POST","GET"])
def logout_page():
	if current_user.is_authenticated:
		if request.method == "POST":
			logout_user()
			return redirect(url_for('home_page'))
		return redirect(url_for('home_page'))
	return redirect(url_for('home_page'))

if __name__ == "__main__":
	app.run(debug=True)