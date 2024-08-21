# PS1 Script for SSH
### Powershell Script For Disabling SSL 2.0 and 3.0 and Enabling TLS 1.2

Script created to disable SSL Version 2.0 and 3.0 and Enable the most viable version of TLS. 

Open SSL 2.0 and 3.0 are affected by several cryptographic flaws that can become harmful to your computer and network if exploited. Attacks may use these flaws to conduct man-in-the-middle attacks or to decrypt communications between affected services and clients. 

### Vulnerabilities Include:
- RegreSSHion
- Insecure Padding Scheme with CBC Ciphers
- Insecure Session Renegotiation and Resumption schemes
- Command Injection
- Possible Unauthenticated Code Execution

### Transport Layer Security (TLS)
TLS is a cryptographic protocol designed to provide communication security over a computer network. 
Aims to provide security, privacy, and authentication

### About TLS 1.2

-

### Unified Hello Removal
Unified hello is a message formater that came out with SSL 2.0. With the removal of SSH 2.0 it is no longer necessary and is being removed for storage space optimization. 
https://security.stackexchange.com/questions/59460/what-is-multi-protocol-unified-hello-and-what-are-the-impacts-of-disabling-ena

### PTC 1.0 Removal
Private Communications Technology (PTC) 1.0 is a protocol developed by Microsoft in the mid-1990s to address security flaws in SSL 2.0. With the removal of SSL 2.0 PTC is no longer necessary.
https://en.wikipedia.org/wiki/Private_Communications_Technology

### Sources:
https://www.hass.de/content/setup-microsoft-windows-or-iis-ssl-perfect-forward-secrecy-and-tls-12
https://help.defense.com/en/articles/6302795-ssl-version-2-and-3-protocol-detection-windows-vulnerability
https://nvd.nist.gov/vuln/detail/CVE-2024-6387
https://blog.qualys.com/vulnerabilities-threat-research/2024/07/01/regresshion-remote-unauthenticated-code-execution-vulnerability-in-openssh-server