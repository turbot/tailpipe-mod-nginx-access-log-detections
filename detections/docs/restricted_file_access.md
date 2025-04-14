## Overview

Detect attempts to access restricted files and directories in Nginx access logs. This detection identifies attempts to access files and directories that should be protected from public access, including configuration files, source code, and other sensitive resources.

The detection focuses on identifying patterns that target restricted files and directories, including attempts to bypass access controls and access files that should be protected by Nginx web server configurations.

**References**:
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [MITRE ATT&CK: File and Directory Discovery (T1083)](https://attack.mitre.org/techniques/T1083/) 