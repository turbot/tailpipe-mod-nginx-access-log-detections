## Overview

Detect DOM-based cross-site scripting attacks in Nginx access logs. This detection identifies attempts to inject malicious scripts that manipulate the Document Object Model (DOM) of a web page. Unlike traditional XSS, DOM-based XSS occurs entirely in the browser without server-side processing, making it particularly challenging to detect.

**References**:
- [OWASP DOM-based XSS](https://owasp.org/www-community/attacks/DOM_Based_XSS)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [MITRE ATT&CK: Exploit Public-Facing Application (T1190)](https://attack.mitre.org/techniques/T1190/) 