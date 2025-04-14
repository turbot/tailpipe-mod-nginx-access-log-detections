## Overview

Detect attempts to access operating system files through Nginx access logs. This detection identifies attempts to access sensitive system files, configuration files, and other OS-level resources that should not be accessible through the web server.

The detection focuses on identifying patterns that target operating system files and directories, including attempts to access system configuration files, log files, and other sensitive OS resources that might be used to gather information about the underlying system.

**References**:
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [MITRE ATT&CK: File and Directory Discovery (T1083)](https://attack.mitre.org/techniques/T1083/) 