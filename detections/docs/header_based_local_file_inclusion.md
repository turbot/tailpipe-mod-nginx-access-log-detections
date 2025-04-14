## Overview

Detect header-based local file inclusion attacks in Nginx access logs that attempt to access sensitive files through HTTP headers. This detection identifies attempts to exploit vulnerabilities in header processing that might allow access to local files.

The detection focuses on identifying suspicious patterns in HTTP headers, including attempts to manipulate headers like User-Agent, Referer, and other custom headers that might be used to access local files in Nginx web server configurations.

**References**:
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [MITRE ATT&CK: File and Directory Discovery (T1083)](https://attack.mitre.org/techniques/T1083/) 