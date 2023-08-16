from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, EmailField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Regexp, ValidationError
import re


def nif_and_contact_length_check(form, field):
    if field.data is not None and len(str(field.data)) < 9:
        raise ValidationError('Deve conter pelo menos 9 números VÁLIDOS')


class LoginForm(FlaskForm):
    username = StringField("username", validators=[DataRequired()])
    password = PasswordField("password", validators=[DataRequired()])


class CreateForm(FlaskForm):
    nif = IntegerField("NIF", validators=[DataRequired(), nif_and_contact_length_check])
    name = StringField("Full Name", validators=[DataRequired()])
    position_choices = [("ADM", "Administration"),
                        ("TRANSFER", "Transfer"),
                        ("WASHER", "Washer"),
                        ("ALL", "Do Everything")]
    position = SelectField("Position", choices=position_choices, validators=[DataRequired()])
    contact = IntegerField("Phone Number", validators=[DataRequired(), nif_and_contact_length_check])
    email = EmailField("Email", validators=[DataRequired(), Email()])
    user = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired(),
                                                     Length(min=8, message="Password must be at least 6 characters long"),
                                                     Regexp(r'^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$',
                                                            message="Senha deve conter pelo menos 1 LETRA MAIUSCULA, "
                                                                    "pelo menos 1 NÚMERO, e pelo menos 1 CARACTERE ESPECIAL")])
    confirm_password = PasswordField('Confirm your password', validators=[DataRequired(),
                                                                          EqualTo('password',
                                                                                  message='As senhas não são iguais')])
    submit = SubmitField('Create')
