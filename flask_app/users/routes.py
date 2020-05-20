# 3rd-party packages
from flask import render_template, request, redirect, url_for, flash, Response, send_file, Blueprint, session
from flask_mongoengine import MongoEngine
from flask_login import LoginManager, current_user, login_user, logout_user, login_required
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename

from PIL import Image
from flask_mail import Message
from io import BytesIO
import pyotp
import qrcode
<<<<<<< HEAD
import qrcode.image.svg as svg
=======
import qrcode.image.svg
>>>>>>> 355574fe8419f2b04cf8e8cd79b7776472b759c5

# stdlib
import io
import base64
import sys
from io import BytesIO

# local
from flask_app import app, bcrypt, client, mail
from flask_app.forms import (RegistrationForm, LoginForm,
                             UpdateUsernameForm, UpdateProfilePicForm,
                             UpdatePasswordForm)
from flask_app.models import User, load_user

from flask import session


users = Blueprint('users', __name__)
<<<<<<< HEAD
=======

>>>>>>> 355574fe8419f2b04cf8e8cd79b7776472b759c5
""" ************ User Management views ************ """


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = RegistrationForm()
    if form.validate_on_submit():

        msg = Message('Thanks for Registering!', sender = 'catwiki388j@gmail.com', recipients = [str(form.email.data)])
        msg.body = "Hi there! Thanks for registering to Cat Wiki!\n\nYour username is: "+str(form.username.data)+"\n\nThank you for using our website, we hope you have an excellent day!"
        mail.send(msg)
        session['new_username'] = form.username.data

        hashed = bcrypt.generate_password_hash(form.password.data).decode("utf-8")

        user = User(username=form.username.data, email=form.email.data, password=hashed)
        user.save()
<<<<<<< HEAD
        session['new_username'] = user.username
        return redirect(url_for('users.tfa'))
=======

        return redirect(url_for('tfa'))
>>>>>>> 355574fe8419f2b04cf8e8cd79b7776472b759c5

    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.objects(username=form.username.data).first()
        print(user.password, file=sys.stdout)
        if user is not None and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('account'))
        else:
            flash('Login failed. Check your username and/or password')
            return redirect(url_for('login'))

    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    username_form = UpdateUsernameForm()
    password_form = UpdatePasswordForm()
    profile_pic_form = UpdateProfilePicForm()

    if password_form.validate_on_submit():
        hashed = bcrypt.generate_password_hash(password_form.new_password.data).decode("utf-8")
        
        msg = Message('Password Change', sender = 'catwiki388j@gmail.com', recipients = [str(temp.email)])
        msg.body = "Your password has been updated! Please reply to this e-mail if you did not request this change."
        mail.send(msg)

        current_user.modify(password=hashed)
        current_user.save()

        return redirect(url_for('account'))

    if username_form.validate_on_submit():
        temp = User.objects(username=current_user.username).first()
        current_user.username = username_form.username.data

        msg = Message('Username Change', sender = 'catwiki388j@gmail.com', recipients = [str(temp.email)])
        msg.body = "Your username has been updated!\nYour new username is: "+str(username_form.username.data)
        mail.send(msg)

        current_user.modify(username=username_form.username.data)
        current_user.save()

        return redirect(url_for('account'))

    if profile_pic_form.validate_on_submit():
        img = profile_pic_form.propic.data
        filename = secure_filename(img.filename)

        if current_user.profile_pic.get() is None:
            current_user.profile_pic.put(img.stream, content_type='images/png')
        else:
            current_user.profile_pic.replace(img.stream, content_type='images/png')
        current_user.save()

        return redirect(url_for('account'))

    image = images(current_user.username)

    return render_template("account.html", title="Account", username_form=username_form, password_form=password_form, profile_pic_form=profile_pic_form, image=image)

<<<<<<< HEAD
def images(username):
    user = User.objects(username=username).first()
    bytes_im = io.BytesIO(user.profile_pic.read())
    image = base64.b64encode(bytes_im.getvalue()).decode()
    return image

@users.route("/qr_code")
=======
@app.route("/qr_code")
>>>>>>> 355574fe8419f2b04cf8e8cd79b7776472b759c5
def qr_code():
    if 'new_username' not in session:
        return redirect(url_for('register'))
    
<<<<<<< HEAD
    user = User.objects(username=session['new_username']).first()    
=======
    user = User.objects(username=session['new_username']).first()
>>>>>>> 355574fe8419f2b04cf8e8cd79b7776472b759c5
    session.pop('new_username')

    uri = pyotp.totp.TOTP(user.otp_secret).provisioning_uri(name=user.username, issuer_name='CMSC388J-2FA')
    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
    stream = BytesIO()
    img.save(stream)

    headers = {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0' # Expire immediately, so browser has to reverify everytime
    }

    return stream.getvalue(), headers

<<<<<<< HEAD
@users.route("/tfa")
=======

@app.route("/tfa")
>>>>>>> 355574fe8419f2b04cf8e8cd79b7776472b759c5
def tfa():
    if 'new_username' not in session:
        return redirect(url_for('main.index'))

    headers = {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0' # Expire immediately, so browser has to reverify everytime
    }

<<<<<<< HEAD
    return render_template('tfa.html'), headers
=======
    return render_template('tfa.html'), headers

def images(username):
    user = User.objects(username=username).first()
    bytes_im = io.BytesIO(user.profile_pic.read())
    image = base64.b64encode(bytes_im.getvalue()).decode()
    return image
>>>>>>> 355574fe8419f2b04cf8e8cd79b7776472b759c5
