from app import database
from flask_login import UserMixin
from werkzeug.security import generate_password_hash


class User(database.Model, UserMixin):
    __tablename__ = "users"

    nif = database.Column(database.Integer, primary_key=True)
    name = database.Column(database.String, nullable=True)
    position = database.Column(database.String, nullable=True)
    contact = database.Column(database.Integer, nullable=True)
    email = database.Column(database.String, nullable=True, unique=True)
    user = database.Column(database.String, nullable=True, unique=True)
    password = database.Column(database.String, nullable=True)

    def get_id(self):
        return str(self.nif)

    def set_password(self, password):  # Function to register and make hash password
        self.password = generate_password_hash(password)

    def __init__(self, nif, name, position, contact, email, user):
        self.nif = nif
        self.name = name
        self.position = position
        self.contact = contact
        self.email = email
        self.user = user
        self.password = None


class Trip(database.Model):
    __tablename__ = "trips"

    id = database.Column(database.Integer, primary_key=True)
    plate = database.Column(database.Integer, nullable=True)
    departure_place = database.Column(database.String, nullable=True)
    arrive_place = database.Column(database.String, nullable=True)
    departure_time = database.Column(database.Time, nullable=True)
    arrive_time = database.Column(database.Time, nullable=True)
    departure_miles = database.Column(database.Integer, nullable=True)
    arrive_miles = database.Column(database.Integer, nullable=True)
    departure_fuel = database.Column(database.String, nullable=True)
    arrive_fuel = database.Column(database.String, nullable=True)
    service = database.Column(database.String, nullable=True)
    user = database.Column(database.String, nullable=True)
