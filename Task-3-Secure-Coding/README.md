# Secure Coding Review

## 1. Project Overview

This project demonstrates a secure coding review of a Python Flask web application.

The project contains an application used as the audit target and a separate remediated version showing how common security weaknesses can be addressed using secure coding practices.

The review combines:

- Manual source-code inspection
- Static security analysis using Bandit
- Security-focused application testing
- Secure coding remediation
- Before-and-after comparison

The application is intended for local educational security testing only.

---

## 2. Objectives

The main objectives of this project are:

- Review a Python Flask application for common security weaknesses.
- Identify security issues through source-code inspection.
- Use Bandit for static security analysis.
- Understand the impact of common vulnerabilities.
- Apply secure coding techniques.
- Create a separate secure implementation.
- Test the security improvements locally.
- Document the findings and remediation process.

---

## 3. Technologies Used

- Python
- Flask
- Werkzeug
- SQLite
- Bandit
- HTML/CSS
- Linux / Kali Linux
- Git and GitHub

---

## 4. Project Structure

```text
Task-3-Secure-Coding/
│
├── vulnerable_app.py
├── secure_app.py
├── security_report.txt
├── final_security_report.txt
├── requirements.txt
├── README.md
└── users.db
users.db is generated locally for testing and is excluded from Git using .gitignore.

File Description

vulnerable_app.py

The application used as the original code-review target.

secure_app.py

The improved version containing secure coding practices and remediation.

security_report.txt

Report generated from the security analysis of the original application.

final_security_report.txt

Final security analysis report after remediation.

requirements.txt

Lists the Python dependencies required to run the project.

README.md

Project documentation.

5. Application Description

The Flask application contains several security-relevant functions:

User login
SQLite database interaction
Password authentication
Search functionality
Network ping functionality
User-controlled input processing

The project focuses on demonstrating how insecure coding patterns can introduce vulnerabilities and how they can be mitigated.

6. Security Issues Reviewed

The security review focuses on the following areas:

Hardcoded application secrets
SQL injection
Command injection
Password storage
Flask debug configuration
Cross-site scripting (XSS)
Input validation
Safe subprocess execution
7. Hardcoded Secret
Security Risk

Application secrets should not be stored directly in source code because source code may be shared through repositories or exposed to unauthorized users.

Secure Implementation

The secure application loads the Flask secret from an environment variable:

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "local-development-secret"
)

The fallback value is intended only for local educational testing.

For a real production deployment, a strong secret should be supplied through a secure environment or secret-management system.

8. SQL Injection
Security Risk

Building SQL statements by directly inserting user input can allow attackers to manipulate the intended SQL query.

Secure Implementation

The secure application uses parameterized SQL:

cursor.execute(
    """
    SELECT username, password
    FROM users
    WHERE username = ?
    """,
    (username,)
)

The user input is supplied separately from the SQL statement.

Manual Test

A SQL injection-style login input was tested locally.

Result:

Invalid username or password.

The application did not authenticate the request.

9. Command Injection
Security Risk

Passing user-controlled input to a shell command using shell=True can allow additional operating-system commands to be interpreted.

Secure Implementation

The secure application:

Validates the supplied host.
Does not use shell=True.
Passes command arguments as a list.
Uses a timeout.
Handles command errors safely.

Example:

subprocess.run(
    ["ping", "-c", "1", host],
    capture_output=True,
    text=True,
    timeout=5,
    check=False
)
Manual Test

A command-injection test was performed using:

127.0.0.1;whoami

Result:

Invalid host input.

The malicious input was rejected before execution.

10. Password Security
Security Risk

Passwords should never be stored directly in plaintext or using a fast general-purpose hash such as SHA-256 for password storage.

Secure Implementation

The secure application uses Werkzeug's password hashing functions:

generate_password_hash()
check_password_hash()

The local demonstration database stores a modern password hash rather than the plaintext password.

The database was recreated during testing to verify that the demonstration account was stored using the new password-hashing approach.

11. Flask Debug Mode

Debug mode can expose detailed application information and should not be enabled for a production application.

The secure application explicitly runs with:

app.run(
    host="127.0.0.1",
    port=5000,
    debug=False
)

The Flask server output confirmed:

Debug mode: off
12. Cross-Site Scripting (XSS)

The search functionality accepts user-controlled input.

The secure application passes the value to a Jinja template:

return render_template_string(
    "... {{ query }} ...",
    query=query
)

Jinja automatically escapes HTML characters in this context.

Manual Test

The following harmless XSS test was performed locally:

<script>alert('XSS')</script>
The browser displayed the script as text instead of executing JavaScript.

This demonstrated that the user-controlled input was being escaped.

13. Input Validation

The secure application validates user input before processing it.

Examples include:

Username format validation
Username length restrictions
Password presence validation
Host/IP validation
Search query length restriction

Invalid input is rejected instead of being passed directly to sensitive operations.

14. Security Testing Performed

The secure application was tested locally after remediation.

Test	Result
Normal login	Passed
SQL injection attempt	Rejected
Password hashing	Verified
Normal localhost ping	Passed
Command injection attempt	Rejected
XSS test	Escaped
Flask debug mode	Disabled

Example Flask logs from the testing session confirmed:

GET /ping?host=127.0.0.1 HTTP/1.1" 200
GET /ping?host=127.0.0.1;whoami HTTP/1.1" 400
GET /search?q=<script>alert('XSS')</script> HTTP/1.1" 200
15. Static Security Analysis

Bandit is used as the static security analysis tool for this project.

The security review follows this workflow:

Source Code
     ↓
Manual Code Review
     ↓
Bandit Scan
     ↓
Security Findings
     ↓
Secure Coding Remediation
     ↓
Application Testing
     ↓
Bandit Re-scan
     ↓
Final Verification

Bandit was run against both the original code-review target and the
remediated secure application.

Original code-review target:

    bandit -r vulnerable_app.py

Results:

    High:   0
    Medium: 0
    Low:    3

Remediated application:

    bandit -r secure_app.py

Results:

    High:   0
    Medium: 0
    Low:    3

The three Low-severity findings in the remediated application are
related to the use of the Python subprocess module for the local
ping functionality:

- B404: subprocess module import
- B607: partial executable path
- B603: subprocess call requiring security review

The secure implementation does not use shell=True, validates the host
input, passes command arguments as a list, and applies a timeout.
Manual testing was also performed to verify that command-injection
input was rejected.

The complete Bandit outputs are stored in:

    security_report.txt
    final_security_report.txt

16. Before and After

Security Area             Original / Reviewed Approach       Secure Approach
Application secret        Security-sensitive configuration  Environment variable with local fallback
SQL queries               SQL handling reviewed              Parameterized queries
Command execution         subprocess usage reviewed          Argument list + input validation
Password storage          SHA-256-based handling reviewed    Werkzeug password hashing
Flask debug               Debug configuration reviewed      Debug disabled
XSS                       Output handling reviewed           Jinja template escaping
Input validation          Limited validation                 Explicit validation
Error handling            Detailed/internal errors           Generic user-facing errors

The secure application separates the reviewed code from the
remediated implementation so that the security improvements can be
clearly demonstrated and tested.

17. Security Best Practices Applied

The project demonstrates the following practices:

Do not hardcode sensitive secrets.
Use environment variables for application secrets.
Use parameterized SQL queries.
Validate user input.
Avoid shell=True for user-controlled input.
Use password hashing designed for passwords.
Disable debug mode outside development.
Escape user-controlled HTML output.
Use timeouts for external process execution.
Handle application errors without exposing internal details.
Perform static security analysis.
Test security fixes after remediation.
18. Limitations

This is an educational secure coding project and is not a complete production security audit.

Bandit performs static analysis and cannot detect every possible vulnerability.

A production application would require additional testing such as:

Dynamic application security testing
Dependency vulnerability scanning
Authentication testing
Authorization testing
Session security testing
Configuration review
Manual penetration testing
Secure deployment configuration
19. Security and Ethical Considerations

This project is intended for local educational security testing.

Security testing should only be performed on applications and systems where appropriate permission has been provided.

The techniques demonstrated in this project should be used for defensive security, secure development, and authorized testing.

20. Conclusion

This project demonstrates a practical secure coding review of a Python Flask application.

The project combines manual code review, static security analysis, secure coding remediation, and application testing.

The remediated application demonstrates protections against several common security weaknesses, including SQL injection, command injection, insecure password handling, unsafe secret management, XSS, and insecure debug configuration.

The project also demonstrates the importance of testing security controls after making code changes.
