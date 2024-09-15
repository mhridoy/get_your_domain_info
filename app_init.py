import os
import logging
from flask import Flask
from database import db, run_migrations

def create_app():
    app = Flask(__name__, static_folder='static')

    # Database configuration (in-memory SQLite for this example)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    # Suppress SQLAlchemy modification tracking warnings
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Initialize database
    db.init_app(app)

    # Run migrations (custom function, make sure this is properly implemented)
    run_migrations(app)

    # Import and register routes from the routes module
    from routes import register_routes
    register_routes(app)

    return app
