## Overview

Detect directory traversal attacks in Nginx access logs using URL encoded or otherwise obfuscated path sequences to bypass security filters. This detection identifies attempts to exploit insufficient validation of user-supplied file names through various encoding techniques.

The detection focuses on identifying encoded path traversal sequences, including URL encoding, double encoding, and UTF-8 encoding variations that might be used to bypass security controls in Nginx web server configurations.

**References**:
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [MITRE ATT&CK: File and Directory Discovery (T1083)](https://attack.mitre.org/techniques/T1083/) 