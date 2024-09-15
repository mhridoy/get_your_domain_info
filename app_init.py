import os
import logging
from flask import Flask
from database import db, run_migrations

def create_app():
    app = Flask(__name__, static_folder='static')

    # Initialize database
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    db.init_app(app)

    # Run migrations
    run_migrations(app)

    # Import and register routes
    from routes import register_routes
    register_routes(app)

    return app