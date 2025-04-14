## Overview

Detect cross-site scripting attacks in Nginx access logs that use attribute injection to execute malicious scripts. This detection identifies attempts to inject malicious attributes into HTML elements that might be used to execute arbitrary code in users' browsers.

The detection focuses on identifying attribute injection patterns, including malicious HTML attributes, event handlers, and other attribute-based injection vectors that might be used to execute malicious code in users' browsers through Nginx web server requests.

**References**:
- [OWASP Cross-Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [MITRE ATT&CK: Exploit Public-Facing Application (T1190)](https://attack.mitre.org/techniques/T1190/) 