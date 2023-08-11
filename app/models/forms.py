from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, IntegerField, EmailField
from wtforms.validators import DataRequired, Email, EqualTo


class LoginForm(FlaskForm):
    username = StringField("username", validators=[DataRequired()])
    password = PasswordField("password", validators=[DataRequired()])


class CreateForm(FlaskForm):
    nif = IntegerField("NIF", validators=[DataRequired()])
    name = StringField("Full Name", validators=[DataRequired()])
    position = StringField("Position", validators=[DataRequired()])
    contact = IntegerField("Phone Number", validators=[DataRequired()])
    email = EmailField("Email", validators=[DataRequired(), Email()])
    user = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    confirm_password = PasswordField('Confirm your password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Create')
