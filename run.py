from app import app, database
from app.models.tables_db import User, Trip

with app.app_context():  # Before the app run, we create all tables in the database
    database.create_all()
    database.session.commit()

if __name__ == "__main__":
    app.run()
