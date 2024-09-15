import logging
from flask import render_template, request, jsonify
from flask import current_app as app
import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
import dns.resolver
import requests
from bs4 import BeautifulSoup

def get_certificate_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                der_cert = secure_sock.getpeercert(True)
                certificate = x509.load_der_x509_certificate(der_cert, default_backend())
                
                common_name = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                issuer = certificate.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                valid_from = certificate.not_valid_before
                valid_to = certificate.not_valid_after
                
                # Get IP address
                ip_address = socket.gethostbyname(domain)
                
                return {
                    "common_name": common_name,
                    "issuer": issuer,
                    "valid_from": valid_from.strftime("%Y-%m-%d"),
                    "valid_to": valid_to.strftime("%Y-%m-%d"),
                    "ip_address": ip_address
                }
    except Exception as e:
        logging.error(f"Error fetching certificate info for {domain}: {str(e)}")
        return {"error": f"Unable to fetch certificate info: {str(e)}"}

def find_subdomains(domain):
    try:
        url = f"https://crt.sh/?q={domain}&output=json"
        response = requests.get(url)
        data = response.json()
        
        subdomains = set()
        for entry in data:
            name_value = entry['name_value']
            if name_value.endswith(domain):
                subdomains.update(name_value.split('\n'))
        
        return list(subdomains)
    except Exception as e:
        logging.error(f"Error finding subdomains for {domain}: {str(e)}")
        return []

def register_routes(app):
    @app.route("/", methods=["GET", "POST"])
    def home_route():
        certificate_info = None
        subdomains = None
        if request.method == "POST":
            domain = request.form.get("domain")
            certificate_info = get_certificate_info(domain)
            subdomains = find_subdomains(domain)
        return render_template("home.html", certificate_info=certificate_info, subdomains=subdomains)
    
    @app.route("/api/certificate", methods=["POST"])
    def api_certificate():
        domain = request.json.get("domain")
        certificate_info = get_certificate_info(domain)
        return jsonify(certificate_info)
    
    @app.route("/api/subdomains", methods=["POST"])
    def api_subdomains():
        domain = request.json.get("domain")
        subdomains = find_subdomains(domain)
        return jsonify(subdomains)