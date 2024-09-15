import os
import logging
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text

db = SQLAlchemy()

class Migration(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False)

def run_migrations(app):
    migration_folder = os.path.join(app.root_path, 'migrations')
    if not os.path.exists(migration_folder):
        logging.info("No migrations folder found. Skipping migrations.")
        return
    
    with app.app_context():
        # Create the Migration table if it doesn't exist
        db.create_all()
        
        migration_files = sorted(f for f in os.listdir(migration_folder) if f.endswith('.sql'))
        
        for migration_file in migration_files:
            migration_record = Migration.query.filter_by(name=migration_file).first()
            
            if migration_record is None:
                with open(os.path.join(migration_folder, migration_file), 'r') as file:
                    migration_sql = file.read()
                
                logging.info(f"Running migration: {migration_file}")
                db.session.execute(text(migration_sql))
                
                new_migration = Migration(name=migration_file)
                db.session.add(new_migration)
                db.session.commit()
                logging.info(f"Migration {migration_file} completed successfully.")
            else:
                logging.info(f"Migration {migration_file} already applied. Skipping.")
        
        logging.info("All migrations completed successfully.")