from art import *
from termcolor import colored
import random

# Function to print text in random colors
def random_colored_text(text):
    colors = ['blue']
    colored_text = ""
    for char in text:
        colored_text += colored(char, random.choice(colors))
    return colored_text

# Generate the text art for "WolfSec"
art_text = text2art("WolfSec", font='slant')

# Apply random colors to each character of the art
colored_art = ""
for line in art_text.splitlines():
    colored_art += random_colored_text(line) + "\n"

# Print the multicolored WolfSec art
print(colored_art)

# Multicolored welcome message
welcome_message = "Welcome To WolfSec .... Secure Your Digital Asset .. !!"
colored_message = random_colored_text(welcome_message)

# Print the multicolored welcome message
print(colored_message)

import requests
from bs4 import BeautifulSoup
import socket
import logging

# Configure logging
logging.basicConfig(filename='scanner.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Function to check security headers
def check_security_headers(url):
    response = requests.get(url)
    headers = response.headers
    
    findings = ["Checking Security Headers..."]
    
    security_headers = {
        "Content-Security-Policy": "CSP header missing!",
        "X-Content-Type-Options": "X-Content-Type-Options header missing!",
        "X-Frame-Options": "X-Frame-Options header missing!",
        "Strict-Transport-Security": "HSTS header missing!",
    }

    for header, warning in security_headers.items():
        if header not in headers:
            findings.append(f"[Warning] {warning}")
            logging.warning(f"{warning} at {url}")
        else:
            findings.append(f"[Secure] {header} is present")
            logging.info(f"{header} is present at {url}")
    
    return findings

# Function to check for potential XSS vulnerabilities
def check_xss_vulnerability(url):
    payload = "<script>alert('XSS');</script>"
    response = requests.get(url)
    
    findings = ["\nChecking for XSS Vulnerabilities..."]
    
    if payload in response.text:
        findings.append(f"[Vulnerable] Potential XSS vulnerability found at {url}")
        logging.warning(f"Potential XSS vulnerability found at {url}")
    else:
        findings.append(f"[Secure] No XSS vulnerability found at {url}")
        logging.info(f"No XSS vulnerability found at {url}")
    
    return findings

# Function to check for potential SQL injection vulnerabilities
def check_sql_injection(url):
    payload = "' OR '1'='1"
    response = requests.get(url + payload)
    
    findings = ["\nChecking for SQL Injection Vulnerabilities..."]
    
    if "syntax error" in response.text or "mysql" in response.text.lower():
        findings.append(f"[Vulnerable] Potential SQL injection vulnerability found at {url}")
        logging.warning(f"Potential SQL injection vulnerability found at {url}")
    else:
        findings.append(f"[Secure] No SQL injection vulnerability found at {url}")
        logging.info(f"No SQL injection vulnerability found at {url}")
    
    return findings

# Function to check for open ports
def check_open_ports(host, ports):
    findings = ["\nChecking for Open Ports..."]
    
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            findings.append(f"[Open] Port {port} is open")
            logging.info(f"Port {port} is open on {host}")
        else:
            findings.append(f"[Closed] Port {port} is closed")
            logging.info(f"Port {port} is closed on {host}")
        sock.close()
    
    return findings

# Function to check for potential CSRF vulnerabilities
def check_csrf_vulnerability(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    
    findings = ["\nChecking for CSRF Vulnerabilities..."]
    
    forms = soup.find_all('form')
    for form in forms:
        if not form.find('input', {'name': 'csrf_token'}):
            findings.append(f"[Vulnerable] Potential CSRF vulnerability found in form at {url}")
            logging.warning(f"Potential CSRF vulnerability found in form at {url}")
        else:
            findings.append(f"[Secure] CSRF token found in form at {url}")
            logging.info(f"CSRF token found in form at {url}")
    
    return findings

# Function to check for potential ransomware indicators
def check_ransomware_indicators(url):
    response = requests.get(url)
    
    findings = ["\nChecking for Ransomware Indicators..."]
    
    ransomware_indicators = ["ransom", "decrypt", "bitcoin", "payment"]
    for indicator in ransomware_indicators:
        if indicator in response.text.lower():
            findings.append(f"[Warning] Potential ransomware indicator '{indicator}' found at {url}")
            logging.warning(f"Potential ransomware indicator '{indicator}' found at {url}")
    
    if len(findings) == 1:
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
        file.write("\nReport generated successfully.\n")
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
