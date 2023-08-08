from app import database
from flask_login import UserMixin


class User(database.Model, UserMixin):
    __tablename__ = "users"

    nif = database.Column(database.Integer, primary_key=True)
    name = database.Column(database.String, nullable=True)
    position = database.Column(database.String, nullable=True)
    contact = database.Column(database.Integer, nullable=True)
    email = database.Column(database.String, nullable=True, unique=True)
    user = database.Column(database.String, nullable=True, unique=True)
    password = database.Column(database.String, nullable=True)

    #  Under we wave properties and methods to uso with the FlaskLogin
    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.nif)

    def __init__(self, nif, name, position, contact, email, user, password):
        self.nif = nif
        self.name = name
        self.position = position
        self.contact = contact
        self.email = email
        self.user = user
        self.password = password


class Trip(database.Model):
    __tablename__ = "trips"

    plate = database.Column(database.Integer, primary_key=True)
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
