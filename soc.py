import argparse, hashlib, requests, urllib.parse, base64, socket, subprocess

class SocAnalystToolkit:
    
    def __init__(self):
        self.base_url = "https://urlscan.io/api/v1/search/"
        self.headers = {"Content-Type": "application/json"}

    def url_sanitize(self, url):
        # URL Sanitizing Tool
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return urllib.parse.quote(url)

    def proofpoint_decode(self, encoded_url):
        # ProofPoint Decoder
        return urllib.parse.unquote(encoded_url)

    def url_decode(self, encoded_url):
        # URL Decoder
        return urllib.parse.unquote(encoded_url)

    def office_safelinks_decode(self, encoded_url):
        # Office Safelinks Decoder
        return urllib.parse.unquote(encoded_url.replace('https://nam04.safelinks.protection.outlook.com/?url=', ''))

    def url_unshorten(self, short_url):
        # URL Unshortener
        try:
            response = requests.head(short_url, allow_redirects=True)
            return response.url
        except Exception as e:
            print("Error unshortening URL:", e)
            return None

    def base64_decode(self, encoded_string):
        # Base 64 Decoder
        return base64.b64decode(encoded_string).decode()

    def cisco_password7_decode(self, encoded_password):
        # Cisco Password 7 Decoder
        encoded_password = encoded_password.strip()
        if encoded_password.startswith('7'):
            return hashlib.md5(base64.b64decode(encoded_password[1:])).hexdigest()
        else:
            return "Error: Not a Cisco Password 7 hash."

    def url_unfurl(self, url):
        # Unfurl URL
        response = requests.get(url)
        data = response.json()
        return data

    def reputation_check(self, item):
        # Reputation Checker for IP's, URL's or email addresses
        response = requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={item}&verbose=true")
        data = response.json()
        return data

    def reverse_dns_lookup(self, ip_address):
        # Reverse DNS Lookup
        return socket.gethostbyaddr(ip_address)[0]

    def dns_lookup(self, domain_name):
        # DNS Lookup
        return socket.gethostbyname(domain_name)

    def whois_lookup(self, domain_name):
        # WhoIs Lookup
        cmd = f"whois {domain_name}"
        result = subprocess.check_output(cmd, shell=True)
        return result.decode('utf-8')

    def hash_file(self, file_path, hash_type):
        # Hash a File
        hasher = hashlib.new(hash_type)
        with open(file_path, 'rb') as f:
            while True:
                data = f.read(1024)
                if not data:
                    break
                hasher.update(data)
        return hasher.hexdigest()

    def hash_text_input(self, text_input, hash_type):
        # Hash a Text Input
        hasher = hashlib.new(hash_type)
        hasher.update(text_input.encode())
        return hasher.hexdigest()

    def check_hash_malicious_activity(self, hash_value):
        # Check a hash for known malicious activity
        response = requests.get(f"https://www.virustotal.com/vtapi/v2/file/report?apikey=0e5ee9a9b72f3bd10ec443ca0010ffc40393ff9b64f5597833593ff2d8b0496b&resource={hash_value}")
        data = response.json()
        return data

    def hash_file_check_malicious_activity(self, file_path, hash_type):
        # Hash a file and check for known malicious activity
        hash_value = self.hash_file(file_path, hash_type)
        result = self.check_hash_malicious_activity(hash_value)
        return result

    def analyze_email(self, email_path):
        # Analyze an Email
        cmd = f"python3 /opt/phishing_analysis/parse_email.py {email_path}"
        result = subprocess.check_output(cmd, shell=True)
        return result.decode('utf-8')

    def analyze_email_address(self, email_address):
        # Analyze an email address for known malicious activity
        response = requests.get(f"https://api.abuseipdb.com/api/v2/check-email?emailAddress={email_address}")
        data = response.json()
        return data

    def generate_email_template(self, email_path):
        # Generate an email template based on analysis
        cmd = f"python3 /opt/phishing_analysis/email_template.py {email_path}"
        result = subprocess.check_output(cmd, shell=True)
        return result.decode('utf-8')

    def analyze_url_with_phishtank(self, url):
        # Analyze a URL with Phishtank
        response = requests.get(f"http://checkurl.phishtank.com/checkurl/?url={url}&format=json&app_key=YOUR_APP_KEY")
        data = response.json()
        return data

    def haveibeenpwned_lookup(self, email_address):
        # HaveIBeenPwned Lookup
        response = requests.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email_address}")
        data = response.json()
        return data

if __name__ == '__main__':
    soc = SocAnalystToolkit()

    parser = argparse.ArgumentParser(description='SOC Analyst Toolkit')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Sanitize URL's for use in emails
    sanitize_parser = subparsers.add_parser('sanitize', help='URL Sanitizing Tool')
    sanitize_parser.add_argument('url', help='URL to be sanitized')

    # Decoders
    decoders_parser = subparsers.add_parser('decoders', help='Decoders')
    decoders_subparsers = decoders_parser.add_subparsers(dest='decoder', help='Available decoders')

    proofpoint_parser = decoders_subparsers.add_parser('proofpoint', help='ProofPoint Decoder')
    proofpoint_parser.add_argument('encoded_url', help='Encoded URL')

    url_decode_parser = decoders_subparsers.add_parser('urldecode', help='URL Decoder')
    url_decode_parser.add_argument('encoded_url', help='Encoded URL')

    office_safelinks_parser = decoders_subparsers.add_parser('office_safelinks', help='Office Safelinks Decoder')
    office_safelinks_parser.add_argument('encoded_url', help='Encoded URL')

    unshorten_parser = decoders_subparsers.add_parser('unshorten', help='URL Unshortener')
    unshorten_parser.add_argument('short_url', help='Shortened URL')

    base64_parser = decoders_subparsers.add_parser('base64', help='Base 64 Decoder')
    base64_parser.add_argument('encoded_string', help='Encoded String')

    cisco_password7_parser = decoders_subparsers.add_parser('cisco_password7', help='Cisco Password 7 Decoder')
    cisco_password7_parser.add_argument('encoded_password', help='Encoded Password')

    unfurl_parser = decoders_subparsers.add_parser('unfurl', help='Unfurl URL')
    unfurl_parser.add_argument('url', help='URL to unfurl')

    # Reputation Checker
    reputation_parser = subparsers.add_parser('reputation', help='Reputation Checker')
    reputation_parser.add_argument('item', help='IP, URL or email address to check')

    # DNS Tools
    dns_parser = subparsers.add_parser('dns', help='DNS Tools')
    dns_subparsers = dns_parser.add_subparsers(dest='dns_command', help='Available DNS commands')

    reverse_lookup_parser = dns_subparsers.add_parser('reverse', help='Reverse DNS Lookup')
    reverse_lookup_parser.add_argument('ip_address', help='IP address to lookup')

    lookup_parser = dns_subparsers.add_parser('lookup', help='DNS Lookup')
    lookup_parser.add_argument('domain_name', help='Domain name to lookup')

    whois_parser = dns_subparsers.add_parser('whois', help='WhoIs Lookup')
    whois_parser.add_argument('domain_name', help='Domain name to lookup')

    # Hashing Functions
    hashing_parser = subparsers.add_parser('hashing', help='Hashing Functions')
    hashing_subparsers = hashing_parser.add_subparsers(dest='hash_command', help='Available hashing commands')

    hash_file_parser = hashing_subparsers.add_parser('file', help='Hash a File')
    hash_file_parser.add_argument('file_path', help='Path to the file to be hashed')

    args = parser.parse_args()

    # Check if no arguments were provided and print help message
    if not vars(args):
        parser.print_help()
