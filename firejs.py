import re
import argparse
import requests
import os
import urllib3
import itertools
import threading
import time

# Suppress only the single InsecureRequestWarning from urllib3 when bypassing SSL verification
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ASCII Art for "firejs"
ascii_art = """
  ______ _           
 |  ____(_)          
 | |__   _ _ __  ___ 
 |  __| | | '_ \/ __|
 | |    | | | | \__ \\
 |_|    |_|_| |_|___/

       by jrhackerman
"""

# Print the ASCII art at the start
print(ascii_art)

# Function for a scanning loader
def loader():
    for c in itertools.cycle(['|', '/', '-', '\\']):
        if stop_loading:
            break
        print(f'\rScanning {c}', end='', flush=True)
        time.sleep(0.1)

# Fetch JavaScript file from a URL (with SSL verification bypassed)
def fetch_js_file(url):
    try:
        # Disabling SSL certificate verification by setting verify=False
        response = requests.get(url, verify=False)
        response.raise_for_status()  # Raise an error if the request fails
        return response.text
    except requests.RequestException as e:
        print(f"Error fetching the URL: {e}")
        return None

# Find sensitive information within JS file content
def find_sensitive_info(file_content):
    findings = {
        'hardcoded_urls': [],
        'api_endpoints': [],
        'hardcoded_usernames': [],
        'hardcoded_passwords': [],
        'api_keys_tokens': [],
        'version_info': [],
        'email_addresses': [],
        'phone_numbers': []
    }

    # Regex patterns
    url_pattern = r'https?://[^\s"\'<>]+'  # Matches URLs
    endpoint_pattern = r'(?:(?:GET|POST|PUT|DELETE|PATCH)\s+["\'](\/[^\s"\']+)|(["\']\/api\/[^\s"\']+))'  # Matches API endpoints
    username_pattern = r'username\s*[:=]\s*[\'"]([^\'"]+)[\'"]'  # Matches usernames
    password_pattern = r'password\s*[:=]\s*[\'"]([^\'"]+)[\'"]'  # Matches passwords
    token_pattern = r'\b(?:token|TOKEN|apiKey|authKey)\b\s*[:=]\s*[\'"]([^\'"]+)[\'"]'  # Matches API keys and tokens
    version_pattern = r'\bversion\s*[:=]\s*[\'"]([^\'"]+)[\'"]'  # Matches version information
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'  # Matches email addresses
    phone_pattern = r'\+?\d[\d\s.-]{7,}\d'  # Matches phone numbers

    # Find matches
    findings['hardcoded_urls'] = re.findall(url_pattern, file_content)
    findings['api_endpoints'] = [match[0] or match[1] for match in re.findall(endpoint_pattern, file_content)]
    findings['hardcoded_usernames'] = re.findall(username_pattern, file_content)
    findings['hardcoded_passwords'] = re.findall(password_pattern, file_content)
    findings['api_keys_tokens'] = re.findall(token_pattern, file_content, re.IGNORECASE)
    findings['version_info'] = re.findall(version_pattern, file_content)
    findings['email_addresses'] = re.findall(email_pattern, file_content)
    findings['phone_numbers'] = re.findall(phone_pattern, file_content)

    return findings

# Print findings in a structured manner
def print_findings(findings):
    print("\n=== Findings ===")

    for category, items in findings.items():
        print(f"\n{category.replace('_', ' ').title()}:")
        if items:
            for item in items:
                print(f"  - {item}")
        else:
            print("  None")

# Main function to handle input and file scanning
def main():
    parser = argparse.ArgumentParser(description="Scan JavaScript files for sensitive information.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url', help="URL of the JavaScript file to scan.")
    group.add_argument('-f', '--file', help="Local JavaScript file to scan.")
    
    args = parser.parse_args()

    # Start loader animation in a separate thread
    global stop_loading
    stop_loading = False
    loader_thread = threading.Thread(target=loader)
    loader_thread.start()

    # Fetch or read the JS file content
    if args.url:
        file_content = fetch_js_file(args.url)
    elif args.file:
        if os.path.exists(args.file):
            with open(args.file, 'r') as f:
                file_content = f.read()
        else:
            print(f"File not found: {args.file}")
            return

    # Stop the loader once scanning is complete
    stop_loading = True
    loader_thread.join()

    # Process the file if content is available
    if file_content:
        findings = find_sensitive_info(file_content)
        print_findings(findings)

if __name__ == "__main__":
    main()
