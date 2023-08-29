from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, EmailField, SelectField, TimeField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Regexp, ValidationError
import pycountry


def nif_and_contact_length_check(form, field):
    data = str(field.data)
    if len(data) != 9 or not data.isdigit():
        raise ValidationError('Must contain 9 valid numbers')


class LoginForm(FlaskForm):
    username = StringField("username", validators=[DataRequired()])
    password = PasswordField("password", validators=[DataRequired()])


class CreateForm(FlaskForm):
    nif = IntegerField("NIF", validators=[DataRequired(), nif_and_contact_length_check])
    name = StringField("Name", validators=[DataRequired()])
    position_choices = [("ADM", "Administration"),
                        ("TRANSFER", "Transfer"),
                        ("WASHER", "Washer"),
                        ("ALL", "Do Everything")]
    position = SelectField("Position", choices=position_choices, validators=[DataRequired()])
    country_code_choices = [(f"+{country.alpha_2}", f"{country.name}(+{country.alpha_2})")
                            for country in pycountry.countries]
    country_code = SelectField("Contact", choices=country_code_choices, validators=[DataRequired()])
    contact = IntegerField("Phone Number", validators=[DataRequired(), nif_and_contact_length_check])
    email = EmailField("Email", validators=[DataRequired(), Email()])
    confirm_email = EmailField("Confirm Email",
                               validators=[DataRequired(), EqualTo('email', message='Emails are different')])
    user = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password",
                             validators=[DataRequired(),
                                         Length(min=8, message="Password must be at least 8 characters long"),
                                         Regexp(r'^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$',
                                                message="Password must contain at least 1 UPPERCASE LETTER, "
                                                        "at least 1 NUMBER, "
                                                        "and at least 1 ESPECIAL CHARACTER")])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(),
                                                 EqualTo('password', message='Passwords are different')])
    submit = SubmitField('Create')


class ServicesCheckinCheckout(FlaskForm):
    plate = IntegerField("Plate", validators=[DataRequired()])
    places = [("TURISCAR CARNAXIDE", "Turiscar Carnaxide"),
              ("TURISCAR PRIOR-VELHO", "Turiscar Prior-Velho"),
              ("TURISCAR CACÉM", "Turiscar Cacém"),
              ("TURISCAR ESTORIL", "Turiscar Estoril"),
              ("TURISCAR SINTRA", "Turiscar Sintra")]
    departure_place = SelectField("Check In", choices=places, validators=[DataRequired()])
    departure_time = TimeField("Check In Time", validators=[DataRequired()])
    departure_miles = IntegerField("Check In Miles", validators=[DataRequired()])
    fuel = [("Na Reserva", "Low"),
            ("Pouco", "1/4"),
            ("Metade", "2/4"),
            ("Mais da Metade", "3/4"),
            ("Tanque Cheio", "4/4")]
    departure_fuel = SelectField("Check In Fuel", choices=fuel, validators=[DataRequired()])
    arrive_place = SelectField("CheckOut", choices=places, validators=[DataRequired()])
    arrive_time = TimeField("CheckOut Time", validators=[DataRequired()])
    arrive_miles = IntegerField("CheckOut Miles", validators=[DataRequired()])
    arrive_fuel = SelectField("CheckOut Fuel", choices=fuel, validators=[DataRequired()])
    services = [("Colocação", "Colocação"),
                ("Levantamento", "Levantamento"),
                ("Apoio", "Apoio")]
    service = SelectField("Service ?", choices=services, validators=[DataRequired()])
    employee = StringField()
    submit = SubmitField('Done')
