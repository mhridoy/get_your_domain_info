import logging
from flask import render_template, request, jsonify, Blueprint
import ssl
import socket
from datetime import datetime
import dns.resolver

logging.basicConfig(level=logging.INFO)

routes = Blueprint('routes', __name__)

def get_certificate_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                cert = secure_sock.getpeercert()

        subject = dict(x[0] for x in cert['subject'])
        issuer = dict(x[0] for x in cert['issuer'])
        not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')

        return {
            'common_name': subject.get('commonName'),
            'issuer': issuer.get('commonName'),
            'valid_from': not_before.isoformat(),
            'valid_to': not_after.isoformat(),
            'ip_address': socket.gethostbyname(domain)
        }
    except Exception as e:
        logging.error(f"Error fetching certificate info: {str(e)}")
        return None

def find_subdomains(domain):
    try:
        subdomains = []
        for prefix in ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test', 'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3', 'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static', 'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki', 'web', 'media', 'email', 'images', 'img', 'www1', 'intranet', 'portal', 'video', 'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns4', 'www3', 'dns', 'search', 'staging', 'server', 'mx1', 'chat', 'wap', 'my', 'svn', 'mail1', 'sites', 'proxy', 'ads', 'host', 'crm', 'cms', 'backup', 'mx2', 'lyncdiscover', 'info', 'apps', 'download', 'remote', 'db', 'forums', 'store', 'relay', 'files', 'newsletter', 'app', 'live', 'owa', 'en', 'start', 'sms', 'office', 'exchange', 'ipv4']:
            try:
                socket.gethostbyname(f"{prefix}.{domain}")
                subdomains.append(f"{prefix}.{domain}")
            except socket.gaierror:
                pass
        return subdomains
    except Exception as e:
        logging.error(f"Error finding subdomains: {str(e)}")
        return []

@routes.route("/", methods=["GET", "POST"])
def home_route():
    if request.method == "GET":
        return render_template("home.html")
    # Handle POST request if needed
    return "POST request received"

@routes.route("/api/certificate", methods=["POST"])
def api_certificate():
    domain = request.json.get('domain')
    cert_info = get_certificate_info(domain)
    if cert_info is None:
        return jsonify({"error": "Failed to fetch certificate information"}), 400
    return jsonify(cert_info)

@routes.route("/api/subdomains", methods=["POST"])
def api_subdomains():
    domain = request.json.get('domain')
    subdomains = find_subdomains(domain)
    return jsonify(subdomains)

def register_routes(app):
    app.register_blueprint(routes)