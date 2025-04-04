## Overview

Detect attempts to access sensitive configuration or system files. Web applications often have files containing sensitive information such as configuration data, credentials, or source code that should never be directly accessible to users. Attackers frequently probe for these files to gather information about the system architecture, find credentials, or identify other security vulnerabilities to exploit.

**References**:
- [OWASP: Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory](https://cwe.mitre.org/data/definitions/538.html)
- [Web Security Academy: Directory Listing Vulnerabilities](https://portswigger.net/web-security/file-path-traversal/lab-simple) 