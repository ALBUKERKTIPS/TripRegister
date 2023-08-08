from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin


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
