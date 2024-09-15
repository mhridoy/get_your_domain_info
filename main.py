import logging
import os
from gunicorn.app.base import BaseApplication
from app_init import create_initialized_flask_app
from github import Github

# Flask app creation should be done by create_initialized_flask_app to avoid circular dependency problems.
app = create_initialized_flask_app()

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class StandaloneApplication(BaseApplication):
    def __init__(self, app, options=None):
        self.application = app
        self.options = options or {}
        super().__init__()

    def load_config(self):
        # Apply configuration to Gunicorn
        for key, value in self.options.items():
            if key in self.cfg.settings and value is not None:
                self.cfg.set(key.lower(), value)

    def load(self):
        return self.application

def push_to_github():
    try:
        g = Github(os.environ['GITHUB_TOKEN'])
        user = g.get_user()
        repo = user.create_repo("get_your_domain_info")
        
        # Add files to the repository
        files_to_commit = [
            'main.py', 'app_init.py', 'routes.py', 'database.py',
            'requirements.txt', 'static/css/styles.css', 'static/js/home.js',
            'static/js/header.js', 'templates/home.html',
            'templates/partials/_header.html', 'templates/partials/_desktop_header.html',
            'templates/partials/_mobile_header.html'
        ]
        
        for file_name in files_to_commit:
            with open(file_name, 'r') as file:
                content = file.read()
            repo.create_file(file_name, f"Add {file_name}", content)
        
        logger.info("Successfully pushed code to GitHub repository: get_your_domain_info")
    except Exception as e:
        logger.error(f"Error pushing to GitHub: {str(e)}")

if __name__ == "__main__":
    options = {
        "bind": "0.0.0.0:8080",
        "workers": 4,
        "loglevel": "info",
        "accesslog": "-",
        "timeout": 120
    }
    push_to_github()
    StandaloneApplication(app, options).run()
    StandaloneApplication(app, options).run()