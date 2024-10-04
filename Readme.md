## Wolf-Sec Vulnerability Scanning and Reporting Tool 

   ![Wolf (1)](https://github.com/user-attachments/assets/39b54d0b-a9c9-4e04-95de-fba361a9d417)




## Introduction
WolfSec is a comprehensive web vulnerability scanner designed to identify and analyze common security issues within web applications. This tool is particularly useful for security professionals and developers seeking to enhance the security posture of their web applications. By evaluating various aspects such as security headers, potential vulnerabilities, and open ports, WolfSec provides a detailed overview of a web application's security landscape.
## Features
1. Security Header Analysis: Verifies the presence of essential security headers to mitigate various web vulnerabilities.
2. Cross-Site Scripting (XSS) Detection: Identifies potential XSS vulnerabilities that could be exploited by attackers.
3. SQL Injection Testing: Checks for vulnerabilities that may allow attackers to execute arbitrary SQL queries
4. Open Port Enumeration: Scans specified ports to detect open services that may be susceptible to attacks.
5. Cross-Site Request Forgery (CSRF) Vulnerability Assessment: Analyzes forms for the presence of CSRF tokens, which protect against unauthorized requests.
6. Ransomware Indicators Detection: Searches for specific keywords associated with ransomware threats in the application response.
7. Detailed Logging: Logs findings and activities in a structured format for audit purposes.
8. Report Generation: Produces a comprehensive report summarizing the scan results for easy reference and further analysis.
## Requirements
To run WolfSec, ensure you have the following:

* Python 3.x
* Required libraries:
    * art
    * termcolor
    * requests
    * beautifulsoup4

You can install required libraries using pip :

pip install art termcolor requests beautifulsoup4
## Installation and Useage 
1. Clone or Download the Repository :  Obtain the script from the repository.

2. Navigate to the Directory :  Open a terminal and change to the directory containing the script.

3. Run the Scanner by Executing the script using the following command:

    * python wolfsec.py

5. Enter the target web URL when prompted (e.g., http://example.com)
## Output
The scanner will output findings to the terminal and log them into a file named scanner.log. Additionally, a report named vulnerability_report.txt will be generated, summarizing all findings related to the scanned URL.

## Logging
All scan findings are logged in the scanner.log file with timestamps, making it easier to track the security posture over time.

## Note
* Ensure you have permission to scan the target URL to avoid legal issues.
* This tool is intended for educational purposes and should be used responsibly.
## Contributions
Contributions are welcome! Feel free to open issues or submit pull requests.

## License
This project is licensed under the MIT License.
