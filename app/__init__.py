from flask import Flask
from flask_sqlalchemy import SQLAlchemy  # Tools to use the Database, using objects Python
from flask_login import LoginManager  # Help to manager the user authentication
from flask_mail import Mail


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///../database/storage_trips.db'  # The route to storage our data
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = 'VidaLok@123'

app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Your email provider's SMTP server
app.config['MAIL_PORT'] = 587  # SMTP port
app.config['MAIL_USE_TLS'] = True  # Use TLS
app.config['MAIL_USERNAME'] = 'taguscompany@gmail.com'
app.config['MAIL_PASSWORD'] = 'nsljqhzyeoegtuhn'
app.config['MAIL_DEFAULT_SENDER'] = ('Albukerk Company', 'taguscompany@gmail.com')  # Default sender for emails

database = SQLAlchemy(app)
login_manager = LoginManager(app)
mail = Mail(app)

from app.controllers import routes

from app.models.tables_db import User


@login_manager.user_loader
def load_user(user_nif):
    return User.query.get(int(user_nif))
