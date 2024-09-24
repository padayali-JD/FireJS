
# FireJS: JavaScript Sensitive Information Scanner

**FireJS** is a powerful tool designed to scan JavaScript files for sensitive information such as hardcoded URLs, API endpoints, usernames, passwords, API keys, version information, email addresses, phone numbers, and other security-related data. This tool can be used to identify potential vulnerabilities in web applications and ensure sensitive data is not exposed in client-side code.

Developed by **@jrhackerman**.

## Features

- Detects **hardcoded URLs**.
- Identifies **API endpoints** in JavaScript files.
- Searches for **hardcoded usernames** and **passwords**.
- Finds **API keys**, **authentication tokens**, and other sensitive information.
- Identifies **email addresses** and **phone numbers**.
- Detects **version information**.
- Option to scan local files or fetch remote JavaScript files via URL.
- Bypasses SSL certificate verification when fetching remote JavaScript files.

## How to Use

### Prerequisites

- Python 3.x
- Install required Python libraries using the following command:

```bash
pip install -r requirements.txt
```

### Running FireJS

You can run **FireJS** in two ways:

1. **Scan a Local JavaScript File**:
   To scan a local file, use the `-f` or `--file` option:
   
   ```bash
   python firejs.py -f /path/to/your/javascript_file.js
   ```

2. **Scan a JavaScript File from a URL**:
   To scan a JavaScript file from a URL, use the `-u` or `--url` option. FireJS will automatically bypass SSL certificate verification if needed.
   
   ```bash
   python firejs.py -u https://example.com/path/to/javascript_file.js
   ```

### Example

```bash
python firejs.py -u https://example.com/app.js
```

Output:
```plaintext
  ______ _           
 |  ____(_)          
 | |__   _ _ __  ___ 
 |  __| | | '_ \/ __|
 | |    | | | | \__  |_|    |_|_| |_|___/

        by jrhackerman

Scanning /

=== Findings ===

Hardcoded Urls:
  - https://example.com/api

Api Endpoints:
  - /api/v1/login
  - /api/v1/get-data

Hardcoded Usernames:
  None

Hardcoded Passwords:
  None

Api Keys Tokens:
  - ABC123TOKEN

Version Info:
  - 1.0.0

Email Addresses:
  - user@example.com

Phone Numbers:
  - +1234567890
```

### Loader Animation

While scanning, the tool shows a simple loader animation to indicate the scanning process. This ensures that the user knows the process is ongoing, especially when scanning large files or fetching files over the network.

## Detected Sensitive Information

FireJS scans for various categories of sensitive data, including:

1. **Personally Identifiable Information (PII)**:
   - Full names
   - Email addresses
   - Phone numbers
   - Passport or driver's license numbers

2. **Financial Information**:
   - Bank account numbers
   - Credit/debit card information

3. **Authentication Credentials**:
   - Hardcoded passwords
   - API tokens
   - Authentication tokens
   - OAuth tokens

4. **Government-Issued Identifiers**:
   - Tax IDs
   - National IDs
   - Voter IDs

5. **Version Information**:
   - Extracts version data from files.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contribution

Feel free to contribute by creating issues or submitting pull requests. This tool is designed for educational purposes, and any contributions that help improve security are highly welcome.

## Disclaimer

This tool is intended for **educational purposes** and **ethical security testing** only. Ensure you have permission to scan any web applications or JavaScript files before using this tool. Unauthorized use may be illegal.

---

Enjoy scanning with **FireJS** by @jrhackerman! 🔥
