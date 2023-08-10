from flask import Flask
from flask_sqlalchemy import SQLAlchemy  # Tools to use the Database, using objects Python
from flask_login import LoginManager, UserMixin  # Help to manager the user authentication, implement methods # and property for a user model


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///../database/storage_trips.db'  # The route to storage our data
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = 'VidaLok@123'
database = SQLAlchemy(app)
login_manager = LoginManager(app)

from app.controllers import routes

from app.models.tables_db import User


@login_manager.user_loader
def load_user(user_nif):
    return User.query.get(int(user_nif))
