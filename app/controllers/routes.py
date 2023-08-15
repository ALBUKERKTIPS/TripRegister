from sqlalchemy.exc import IntegrityError

from app import app, database
from flask import render_template, flash, redirect, url_for, abort
from flask_login import login_user, logout_user, current_user, login_required
from app.models.tables_db import User  # To create instance inside the route Login
from app.models.forms import LoginForm, CreateForm  # To create instance inside the route Login
from werkzeug.security import check_password_hash


@app.route('/start-services', methods=['GET'])
@login_required  # Verify if user is Login
def start_services():
    return render_template("start_services.html", user=current_user)  # Render the html with all data


@app.route('/login', methods=['GET', 'POST'])
@app.route('/', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated and current_user.position == "ADM":  # If user is authenticated , don't need login
        redirect(url_for('administration'))
    else:
        redirect(url_for('start_services'))

    form = LoginForm()
    if form.validate_on_submit():  # Before receive the information, check the fields
        find_user = User.query.filter_by(user=form.username.data).first()  # Asking about username in database
        if find_user and check_password_hash(find_user.password, form.password.data):  # Verify Data User and Pass is in User Data
            login_user(find_user)  # Start Session
            if find_user.position == 'ADM':
                return redirect(url_for('administration'))
            else:
                return redirect(url_for('start_services'))
        else:
            flash('Invalid Login', 'error')
            return redirect(url_for('login'))
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/services')
@login_required  # Verify if user is Login
def service():
    render_template("services.html")


@app.route('/create-account', methods=['GET', 'POST'])
@login_required  # Verify if user is Login
def create_account():
    create_form = CreateForm()
    if create_form.validate_on_submit():
        try:  # Verify and save if exist the same, user, email,contact or nif before save in DB
            duplicate_user = User.query.filter_by(user=create_form.user.data).first()
            duplicate_email = User.query.filter_by(email=create_form.email.data).first()
            duplicate_contact = User.query.filter_by(contact=create_form.contact.data).first()
            duplicate_nif = User.query.filter_by(nif=create_form.nif.data).first()

            if duplicate_user:
                flash('User que você escolheu já está cadastrado.', 'error')
            if duplicate_email:
                flash('Email que você escolheu já está cadastrado.', 'error')
            if duplicate_contact:
                flash('Contact que você escolheu já está cadastrado.', 'error')
            if duplicate_nif:
                flash('NIF que você escolheu já está cadastrado.', 'error')

            if not(duplicate_user or duplicate_contact or duplicate_email or duplicate_nif):
                new_user = User(nif=create_form.nif.data,
                                name=create_form.name.data,
                                position=create_form.position.data,
                                contact=create_form.contact.data,
                                email=create_form.email.data,
                                user=create_form.user.data
                                )
                new_user.set_password(create_form.password.data)  # Making Hash
                database.session.add(new_user)
                database.session.commit()
                print('SAVE IN DB!')
                flash('Account Created Successfully', 'success')
        except IntegrityError as e:
            database.session.rollback()  # revert the process in case error ( hash or something)
            print('DON T SAVE IN DB')
            flash('Failed to create account. Please try again', 'error')
    return render_template('register.html', create_form=create_form)


@app.route('/see-all-users')
@login_required  # Verify if user is Login
def see_all_users():
    users = User.query.all()
    return render_template('all_users.html', users=users)


@app.route('/adm')
@login_required  # Verify if user is Login
def administration():
    return render_template('adm.html', user=current_user)


@app.errorhandler(401)  # Capture the 401 error
def unauthorized(error):
    return render_template('not_authorized.html', message="Voçê não tem permissão. Obrigatório fazer login"), 401
