## Overview

Detect common cross-site scripting (XSS) patterns in Nginx access logs. This detection identifies basic XSS attack attempts using standard injection vectors and common payloads that might indicate an attempt to execute malicious scripts in users' browsers.

The detection focuses on identifying common XSS patterns, including basic script tags, event handlers, and other HTML injection vectors that might be used to execute malicious code in users' browsers through Nginx web server requests.

**References**:
- [OWASP Cross-Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [MITRE ATT&CK: Exploit Public-Facing Application (T1190)](https://attack.mitre.org/techniques/T1190/) 