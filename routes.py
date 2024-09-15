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
        resolver = dns.resolver.Resolver()
        resolver.timeout = 1
        resolver.lifetime = 1
        common_subdomains = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig']
        for prefix in common_subdomains:
            try:
                answers = resolver.resolve(f"{prefix}.{domain}", 'A')
                if answers:
                    subdomains.append(f"{prefix}.{domain}")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                pass
            except Exception as e:
                logging.error(f"Error checking subdomain {prefix}.{domain}: {str(e)}")
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
    return jsonify(subdomains)

def register_routes(app):
    app.register_blueprint(routes)