from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, EmailField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError
import re


class LoginForm(FlaskForm):
    username = StringField("username", validators=[DataRequired()])
    password = PasswordField("password", validators=[DataRequired()])


class CreateForm(FlaskForm):
    nif = IntegerField("NIF", validators=[DataRequired()])
    name = StringField("Full Name", validators=[DataRequired()])
    position_choices = [("ADM", "Administration"),
                        ("TRANSFER", "Transfer"),
                        ("WASHER", "Washer"),
                        ("ALL", "Do Everything")]
    position = SelectField("Position", choices=position_choices, validators=[DataRequired()])
    contact = IntegerField("Phone Number", validators=[DataRequired()])
    email = EmailField("Email", validators=[DataRequired(), Email()])
    user = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    confirm_password = PasswordField('Confirm your password', validators=[DataRequired(), EqualTo('password', message='As senhas não são iguais')])
    print('submeteu a senha')
    submit = SubmitField('Create')
