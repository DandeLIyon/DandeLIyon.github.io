from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login.utils import login_required
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, logout_user, current_user


auth = Blueprint('auth', __name__)

@auth.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        passwd = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, passwd):
                flash('Logged in success!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Wrong Password!', category='error')
        else: 
            flash('Email does not exist', category='error')
    return render_template("login.html", user=current_user)

@auth.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route("signup", methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        name = request.form.get('name')
        pass1 = request.form.get('password1')
        pass2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exist!', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 4 character', category='error')
        elif len(name) < 2:
            flash('Name must be greater than 1 character', category='error')
        elif pass1 != pass2:
            flash('Password don\'t match', category='error')
        elif len(pass1) < 7:
            flash('Password must be at least 7 characters', category='error')
        else: 
            new_user = User(email=email, name=name, password=generate_password_hash(pass1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(user, remember=True)
            flash('Account created', category='success')
            return redirect(url_for('views.home'))

    return render_template("sign_up.html", user=current_user)