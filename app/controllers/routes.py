from functools import wraps

from flask_mail import Message
from sqlalchemy.exc import IntegrityError

from app import app, database, mail
from flask import render_template, flash, redirect, url_for, request
from flask_login import login_user, logout_user, current_user, login_required
from app.models.tables_db import User, Trip  # To create instance inside the route Login
from app.models.forms import LoginForm, CreateForm, ServicesCheckinCheckout  # To create instance inside the route Login
from werkzeug.security import check_password_hash


def adm_required(func):
    @wraps(func)
    def decorate_view(*args, **kwargs):
        if current_user.is_authenticated and current_user.position == "ADM":
            return func(*args, **kwargs)
        else:
            return unauthorized(401)
    return decorate_view


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


@app.route('/services', methods=['GET', 'POST'])
@login_required  # Verify if user is Login
def service():
    services_form = ServicesCheckinCheckout()
    if services_form.validate_on_submit():
        try:  # Verify and save if exist the same
            new_service = Trip(plate=services_form.plate.data,
                               departure_place=services_form.departure_place.data,
                               arrive_place=services_form.arrive_place.data,
                               departure_time=services_form.departure_time.data,
                               arrive_time=services_form.arrive_time.data,
                               departure_miles=services_form.departure_miles.data,
                               arrive_miles=services_form.arrive_miles.data,
                               departure_fuel=services_form.departure_fuel.data,
                               arrive_fuel=services_form.arrive_fuel.data,
                               service=services_form.service.data,
                               user=current_user.user)
            database.session.add(new_service)
            database.session.commit()
            flash('Service Save Successfully', 'success')
            # Clear form data and flash messages after successful submission
            return redirect(url_for('service'))
        except IntegrityError as e:
            database.session.rollback()  # revert the process in case error
            flash('Failed Save Service. Please try again', 'error')
    return render_template('services.html', services_form=services_form)


@app.route('/create-account', methods=['GET', 'POST'])
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

                msg = Message('Cadastrado Com Sucesso', recipients=[new_user.email])
                msg.html = render_template('email/create_notification.html', user=new_user)
                mail.send(msg)

                flash('Account Created Successfully', 'success')
                # Clear the form fields after successful submission
                create_form.nif.data = None
                create_form.name.data = ''
                create_form.position.data = ''
                create_form.contact.data = None
                create_form.email.data = ''
                create_form.user.data = ''
                create_form.password.data = ''
                create_form.confirm_password.data = ''
        except IntegrityError as e:
            database.session.rollback()  # revert the process in case error ( hash or something)
            print('DON T SAVE IN DB')
            flash('Failed to create account. Please try again', 'error')
    return render_template('register.html', create_form=create_form)


@app.route('/edit-user/<user>', methods=['GET', 'POST'])
@login_required
@adm_required
def edit_user(user):
    user_to_edit = User.query.filter_by(user=user).first()

    if user_to_edit is None:
        flash('User not found', 'error')
        return redirect(url_for('see_all_users'))

    edit_form = CreateForm(obj=user_to_edit)

    if edit_form.validate_on_submit():
        try:
            edit_form.populate_obj(user_to_edit)

            if edit_form.password.data:
                user_to_edit.set_password(edit_form.password.data)

            database.session.commit()

            msg = Message('Dados Cadastrais Atualizados', recipients=[user_to_edit.email])
            msg.html = render_template('email/update_notification.html', user=user_to_edit)
            mail.send(msg)

            flash('User data updated successfully', 'success')
        except IntegrityError as e:
            database.session.rollback()
            flash('Failed to update user data. Please try again', 'error')

    return render_template('edit_user.html', edit_form=edit_form, user_to_edit=user_to_edit)


@app.route('/delete-user/<user>', methods=['GET', 'POST'])
@login_required
@adm_required
def delete_user(user):
    user_to_delete = User.query.filter_by(user=user).first()

    if user_to_delete is None:
        flash('User not Found', 'error')
    else:
        try:
            database.session.delete(user_to_delete)
            database.session.commit()
            flash('User Deleted Successfully', 'success')
        except:
            database.session.rollback()
            flash('Failed to delete user. Please try again', 'error')

    return redirect(url_for('see_all_users'))


@app.route('/see-all-users')
@login_required  # Verify if user is Login
@adm_required
def see_all_users():
    users = User.query.all()
    return render_template('all_users.html', users=users)


@app.route('/see-all-trips')
@login_required  # Verify if user is Login
@adm_required
def see_all_trips():
    search_query = request.args.get('search_query', '').strip()
    user_filter = 'search_by_user' in request.args
    plate_filter = 'search_by_plate' in request.args
    all_filter = 'search_all' in request.args

    trips_query = Trip.query

    if search_query:
        if not user_filter and not plate_filter and not all_filter:
            flash('Please select at last one filter option', 'error')
        else:
            if user_filter:
                users = User.query.filter(User.user.contains(search_query)).all()
                trips_query = trips_query.filter(Trip.user.in_([username.user for username in users]))
            elif plate_filter:
                try:
                    plate_query = int(search_query)
                    trips_query = trips_query.filter(Trip.plate == int(search_query))
                except ValueError:
                    flash('Invalid input for plate filter(ONLY NUMBERS)', 'error')
                    return redirect(url_for('see_all_trips'))
    else:
        if all_filter:
            trips = trips_query.all()

    trips = trips_query.all()
    return render_template('all_trips.html', trips=trips)


@app.route('/adm')
@login_required  # Verify if user is Login
@adm_required
def administration():
    return render_template('adm.html', user=current_user)


@app.errorhandler(401)  # Capture the 401 error
def unauthorized(error):
    return render_template('not_authorized.html', message="Voçê não tem permissão. Obrigatório fazer login"), 401
