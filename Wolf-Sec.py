from art import *
from termcolor import colored
import random
import requests
from bs4 import BeautifulSoup
import socket
import logging

# Configure logging
logging.basicConfig(filename='scanner.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

#Function to print text in random colors
def random_colored_text(text):
    colors = ['blue']
    colored_text = ""
    for char in text:
        colored_text += colored(char, random.choice(colors))
    return colored_text

# Generate the text art for "WolfSec"
art_text = text2art("Wolf-Sec", font='slant')

# Apply random colors to each character of the art
colored_art = ""
for line in art_text.splitlines():
    colored_art += random_colored_text(line) + "\n"

# Print the multicolored WolfSec art
print(colored_art)

# Multicolored welcome message
welcome_message = "Welcome To Wolf-Sec  🐺   Secure Your Digital Asset From Cyber Criminals  🛡️"
welcome_message2 = " 🔍  SCAN   🕵️‍♂️ DETECT  🔐 SECURE "
colored_message = random_colored_text(welcome_message)
colored_message2 = random_colored_text(welcome_message2)

# Print the multicolored welcome message
print(colored_message)
print(colored_message2)

# Function to check security headers
def check_security_headers(url):
    findings = ["\nChecking Security Headers..."]
    
    # List of security headers to check and their warning messages
    security_headers = {
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none';",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()"

    }
    
    try:
        # Fetch the headers from the URL response
        response = requests.get(url, timeout=5)
        headers = response.headers
    except requests.exceptions.RequestException as e:
        # Handle errors in retrieving the page
        findings.append(f"[Error] Could not retrieve headers from {url}: {e}")
        logging.error(f"Failed to retrieve headers from {url}: {e}")
        return findings
    
    # Check for each security header in the response
    for header, warning in security_headers.items():
        if header in headers:
            findings.append(f"[Secure] {header} is present")
            logging.info(f"{header} is present at {url}")
        else:
            findings.append(f"[Warning] {warning}")
            logging.warning(f"{warning} at {url}")
    
    return findings

# Function to check for XSS vulnerabilities
def check_xss_vulnerability(url):
    findings = ["\nChecking for XSS Vulnerabilities..."]
    
    # Common XSS payloads to test for vulnerabilities
    payloads = [
       "<script>alert('XSS');</script>",  # Basic Script Injection
    "<img src=x onerror=alert('XSS')>",  # Image Error Event
    "<svg/onload=alert('XSS')>",  # SVG onload Event
    "<body onload=alert('XSS')>",  # Body onload Event
    "<iframe src=\"javascript:alert('XSS');\"></iframe>",  # Iframe JavaScript Injection
    "<div onmouseover=\"alert('XSS')\">Hover over me!</div>",  # Mouseover Event
    "<input type=\"text\" value=\"XSS\" onfocus=\"alert('XSS')\">",  # Input Focus Event
    "<a href=\"#\" onclick=\"alert('XSS')\">Click me</a>",  # Anchor Tag Click Event
    "<math><mtext><malignmark><mi><audio autoplay onloadstart=alert('XSS')></audio>",  # MathML with Audio Autoplay
    "<marquee width=1 loop=1 scrollamount=1 onfinish=confirm(1)>"  # Marquee onfinish Event
    ]
    
    try:
        # Get the page content
        response = requests.get(url, timeout=3)
    except requests.exceptions.RequestException as e:
        # Handle errors in making the request
        findings.append(f"[Error] Could not check for XSS vulnerabilities: {e}")
        logging.error(f"Failed to check for XSS vulnerabilities at {url}: {e}")
        return findings
    
    # Check the response content for any of the XSS payloads
    for payload in payloads:
        if payload in response.text:
            findings.append(f"[Vulnerable] XSS vulnerability found with payload '{payload}' at {url}")
            logging.warning(f"XSS vulnerability found with payload '{payload}' at {url}")
        else:
            findings.append(f"[Secure] No XSS vulnerability found with payload '{payload}' at {url}")
            logging.info(f"No XSS vulnerability found with payload at '{payload}' {url}")
    
    return findings

# Function to check for SQL Injection vulnerabilities
def check_sql_injection(url):
    findings = ["\nChecking for SQL Injection Vulnerabilities..."]
    
    # Common SQL injection payloads to test different types of vulnerabilities
    payloads = [
        "' OR '1'='1'; --",  # Classic SQL Injection
    "' UNION SELECT username, password FROM admin_users; --",  # UNION-Based SQL Injection
    "' OR IF(1=1, SLEEP(5), 0); --",  # Time-Based Blind SQL Injection
    "' OR 1=CONVERT(int, (SELECT @@version)); --",  # Error-Based SQL Injection
    "' OR 1=1; --",  # Boolean-Based Blind SQL Injection
    "' OR DNS_LOOKUP(CHAR(115)+CHAR(101)+CHAR(99)+CHAR(117)+CHAR(114)+CHAR(105)+CHAR(116)+CHAR(121)+CHAR(32)+CHAR(100)+CHAR(111)+CHAR(109)+CHAR(97)+CHAR(105)+CHAR(110)); --",  # Out-of-Band (OOB) SQL Injection
    "'; UPDATE users SET password = 'malicious' WHERE username = 'innocent_user'; --",  # Second-Order SQL Injection
    "' OR 'x'='x'; --",  # Tautology-Based SQL Injection
    "0x73656C656374202A2066726F6D2075736572733B --",  # Hexadecimal Encoding
    "'; DROP TABLE users; --"  # Multipart-Based SQL Injection
    ]
    
    try:
        # Loop through each payload and make a request
        for payload in payloads:
            response = requests.get(f"{url}?id={payload}", timeout=5)
            
            # Analyze the response content for signs of vulnerability
            if any(keyword in response.text.lower() for keyword in ["syntax error", "mysql", "sql", "db", "database"]):
                findings.append(f"[Vulnerable] Potential SQL injection vulnerability with payload '{payload}' at {url}")
                logging.warning(f"Potential SQL injection vulnerability found with payload '{payload}' at {url}")
            else:
                findings.append(f"[Secure] No SQL injection vulnerability with payload '{payload}' at {url}")
                logging.info(f"No SQL injection vulnerability found with payload '{payload}' at {url}")
    
    except requests.exceptions.RequestException as e:
        findings.append(f"[Error] Could not check for SQL injection vulnerabilities: {e}")
        logging.error(f"Failed to check for SQL injection at {url}: {e}")
    
    return findings

# Function to check for open ports
def check_open_ports(host, ports):
    findings = ["\nChecking for Open Ports..."]
    
    # Iterate through each port to check its status
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)  # Set a timeout for the connection attempt
                result = sock.connect_ex((host, port))
                
                if result == 0:  # Port is open
                    findings.append(f"[Open] Port {port} is open on {host}")
                    logging.info(f"Port {port} is open on {host}")
                else:  # Port is closed or unreachable
                    findings.append(f"[Closed] Port {port} is closed on {host}")
                    logging.info(f"Port {port} is closed on {host}")
        
        except socket.error as e:
            # Handle socket errors
            findings.append(f"[Error] Could not check port {port} on {host}: {e}")
            logging.error(f"Failed to check port {port} on {host}: {e}")
    
    return findings

# Function to check for CSRF vulnerabilities
def check_csrf_vulnerability(url):
    findings = ["\nChecking for CSRF Vulnerabilities..."]
    
    try:
        # Attempt to retrieve the page content
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
    except requests.exceptions.RequestException as e:
        # Handle errors in retrieving the page
        findings.append(f"[Error] Could not check for CSRF vulnerabilities: {e}")
        logging.error(f"Failed to retrieve or parse the page at {url}: {e}")
        return findings
    
    # Find all forms on the page
    forms = soup.find_all('form')
    
    # Flag to track if any forms were found
    form_found = False
    
    # Iterate through forms and check for CSRF token
    for form in forms:
        form_found = True
        csrf_token = form.find('input', {'name': 'csrf_token'})
        
        if csrf_token:
            findings.append(f"[Secure] CSRF token found in form at {url}")
            logging.info(f"CSRF token found in form at {url}")
        else:
            findings.append(f"[Vulnerable] Potential CSRF vulnerability in form at {url}")
            logging.warning(f"Potential CSRF vulnerability found in form at {url}")
    
    # If no forms were found, indicate that in the findings
    if not form_found:
        findings.append(f"[Info] No forms found at {url}, skipping CSRF check.")
        logging.info(f"No forms found at {url}, CSRF check skipped.")
    
    return findings

# Function to check for ransomware indicators
def check_ransomware_indicators(url):
    findings = ["\nChecking for Ransomware Indicators..."]
    
    # List of common ransomware-related keywords to scan for
    ransomware_indicators = ["ransom", "decrypt", "bitcoin", "payment", "locker", "encryption", "wallet", "restore"]
    
    try:
        # Fetch the page content with a timeout to avoid hanging
        response = requests.get(url, timeout=3)
        response_text = response.text.lower()  # Convert the response text to lowercase for case-insensitive search
    except requests.exceptions.RequestException as e:
        # Log error and return the findings if the request fails
        findings.append(f"[Error] Could not check for ransomware indicators: {e}")
        logging.error(f"Failed to check for ransomware indicators at {url}: {e}")
        return findings

    # Check the response content for any ransomware indicators
    indicators_found = False
    for indicator in ransomware_indicators:
        if indicator in response_text:
            findings.append(f"[Warning] Potential ransomware indicator '{indicator}' found at {url}")
            logging.warning(f"Potential ransomware indicator '{indicator}' found at {url}")
            indicators_found = True
    
    # If no indicators were found, report the site as secure
    if not indicators_found:
        findings.append("[Secure] No ransomware indicators found")
        logging.info(f"No ransomware indicators found at {url}")
    
    return findings

# Function to generate a report
def generate_report(url, findings):
    with open("vulnerability_report.txt", "w") as file:
        file.write(f"Vulnerability Report for {url}\n")
        file.write("="*50 + "\n")
        for finding in findings:
            file.write(finding + "\n")
    logging.info(f"Report saved as vulnerability_report.txt")

# Main function to run the scanner and generate the report
def run_scanner_with_reporting(url):
    print(f"Scanning {url}...\n")
    logging.info(f"Started scanning {url}")
    
    findings = []
    
    # Check security headers
    findings.extend(check_security_headers(url))
    
    # Check for XSS vulnerabilities
    findings.extend(check_xss_vulnerability(url))
    
    # Check for SQL injection vulnerabilities
    findings.extend(check_sql_injection(url))
    
    # Check for open ports
    host = url.replace("http://", "").replace("https://", "").split('/')[0]
    ports = [80, 443, 8080, 3306]  # Common ports
    findings.extend(check_open_ports(host, ports))
    
    # Check for CSRF vulnerabilities
    findings.extend(check_csrf_vulnerability(url))
    
    # Check for ransomware indicators
    findings.extend(check_ransomware_indicators(url))
    
    print("\nScan complete.")
    logging.info(f"Completed scanning {url}")
    
    # Generate the report
    generate_report(url, findings)

if __name__ == "__main__":
    target_url = input("Enter Web URL to scan: ")  # Replace with your target URL
    run_scanner_with_reporting(target_url)