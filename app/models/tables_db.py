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
    trips = database.relationship('Trip', back_populates='user_object', lazy='dynamic')

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


class Trip(database.Model, UserMixin):
    __tablename__ = "trips"

    id = database.Column(database.Integer, primary_key=True, autoincrement=True)
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
    user_id = database.Column(database.Integer, database.ForeignKey('users.nif'))  # Key to reference with column Id(Users DB)
    user = database.Column(database.String, nullable=True)
    user_object = database.relationship('User', back_populates='trips')

    def __init__(self, plate, departure_place, arrive_place, departure_time, arrive_time, departure_miles,
                 arrive_miles, departure_fuel, arrive_fuel, service, user):
        self.plate = plate
        self.departure_place = departure_place
        self.arrive_place = arrive_place
        self.departure_time = departure_time
        self.arrive_time = arrive_time
        self.departure_miles = departure_miles
        self.arrive_miles = arrive_miles
        self.departure_fuel = departure_fuel
        self.arrive_fuel = arrive_fuel
        self.service = service
        self.user = user

