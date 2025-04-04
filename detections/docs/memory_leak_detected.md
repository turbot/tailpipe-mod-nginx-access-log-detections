## Overview

Detect when potential memory leak was detected in logs to check for application resource mismanagement, memory corruption, or growing response sizes indicating data accumulation issues. Memory leaks occur when an application fails to release memory that is no longer needed, causing resource consumption to grow over time. In web applications, these leaks can manifest as gradually increasing response sizes for the same endpoints as server-side data structures expand uncontrollably.

**References**:
- [OWASP: Memory Leak](https://owasp.org/www-community/vulnerabilities/Memory_leak)