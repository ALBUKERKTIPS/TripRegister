from app import app, database
from flask import render_template, flash, redirect, url_for
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
    if current_user.is_authenticated:  # If user is authenticated , don't need login
        return redirect(url_for('start_services'))

    form = LoginForm()
    if form.validate_on_submit():  # Before receive the information, check the fields
        find_user = User.query.filter_by(user=form.username.data).first()  # Asking about username in database
        if find_user and check_password_hash(find_user.password, form.password.data):  # Verify Data User and Pass is in User Data
            login_user(find_user)  # Start Session
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
def service():
    render_template("services.html")


@app.route('/create-account', methods=['GET', 'POST'])
def create_account():
    create_form = CreateForm()
    if create_form.validate_on_submit():
        with database.session.begin():
            try:
                new_user = User(nif=create_form.nif.data,
                                name=create_form.name.data,
                                position=create_form.position.data,
                                contact=create_form.contact.data,
                                email=create_form.email.data,
                                user=create_form.user.data
                                )
                new_user.set_password(create_form.password.data)  # Making Hash
                database.session.add(new_user)
                print('salvou no banco!')
                flash('Account Created Successfully', 'success')
                return redirect(url_for('login'))  # After create, go to login page
            except Exception as e:
                database.session.rollback()  # revert the process in case error ( hash or something)
                print('deu erro!')
                flash('Failed to create account. Please try again', 'error')
    return render_template('register.html', create_form=create_form)
