import logging
import os
from app_init import create_app
from github import Github
from werkzeug.middleware.proxy_fix import ProxyFix

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = create_app()

# For Vercel deployment - Ensure proxy headers are handled correctly
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

def push_to_github():
    try:
        g = Github(os.environ['GITHUB_TOKEN'])
        user = g.get_user()
        repo_name = "get_your_domain_info"

        try:
            repo = user.get_repo(repo_name)
            logger.info(f"Repository {repo_name} already exists. Updating files.")
        except:
            repo = user.create_repo(repo_name)
            logger.info(f"Created new repository: {repo_name}")

        # Add files to the repository
        files_to_commit = [
            'main.py', 'app_init.py', 'routes.py', 'database.py',
            'requirements.txt', 'static/css/styles.css', 'static/js/home.js',
            'static/js/header.js', 'templates/home.html',
            'templates/partials/_header.html', 'templates/partials/_desktop_header.html',
            'templates/partials/_mobile_header.html', 'vercel.json'
        ]

        for file_name in files_to_commit:
            try:
                with open(file_name, 'r') as file:
                    content = file.read()

                try:
                    contents = repo.get_contents(file_name)
                    repo.update_file(file_name, f"Update {file_name}", content, contents.sha)
                    logger.info(f"Updated {file_name}")
                except:
                    repo.create_file(file_name, f"Add {file_name}", content)
                    logger.info(f"Added {file_name}")
            except Exception as e:
                logger.error(f"Error processing {file_name}: {str(e)}")

        logger.info(f"Successfully pushed code to GitHub repository: {repo_name}")
    except Exception as e:
        logger.error(f"Error pushing to GitHub: {str(e)}")

# Run the app locally if this is the main script
if __name__ == "__main__":
    # Only push to GitHub when running locally (not in Vercel)
    if 'GITHUB_TOKEN' in os.environ:
        push_to_github()
    app.run(host='0.0.0.0', port=8080)

# No need for a separate `handler` function
# Vercel will automatically detect and serve `app` for serverless deployment
