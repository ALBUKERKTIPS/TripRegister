from app import app
from flask import render_template, flash, redirect, url_for
from flask_login import login_user, logout_user
from app.models.tables_db import User  # To create instance inside the route Login
from app.models.forms import LoginForm  # To create instance inside the route Login


@app.route('/start-services', methods=['GET', 'POST'])
def start_services():
    return render_template("start_services.html")  # Render the html with all data


@app.route('/login', methods=['GET', 'POST'])
@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():  # Before receive the information, check the fields
        find_user = User.query.filter_by(user=form.username.data).first()  # Asking about username in database
        if find_user and find_user.password == form.password.data:  # Verify Data User and Pass is in User Data
            # print('Worked!')
            login_user(find_user)  # Start Session
            return redirect(url_for('start_services', username=form.username.data))
        else:
            # print('Login not Valid')
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
