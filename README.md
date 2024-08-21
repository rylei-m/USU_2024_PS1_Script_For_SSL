# PS1 Script for SSH
### Powershell Script For Disabling SSL 2.0 and 3.0 and Enabling TLS 1.2

Script created to disable SSL Version 2.0 and 3.0 and Enable the most viable version of TLS. 

Open SSL 2.0 and 3.0 are affected by several cryptographic flaws that can become harmful to your computer and network if exploited. Attacks may use these flaws to conduct man-in-the-middle attacks or to decrypt communications between affected services and clients. 

A Gigamon article by Dan Daniels provides a brief statement on why this script is necessary. "Back in 1995, when the internet was still figuring itself out, Netscape decided to address growing concerns over internet security by creating a form of encryption that would allow data to travel safely without the risk of being intercepted — Secure Socket Layers. SSL 1.0 was flawed, and never saw general release, but SSL 2.0 followed shortly afterward, and was then superseded by the much improved SSL 3.0. This final SSL version became the standard for internet encryption for nearly two decades. Unfortunately, as technology improved, so did the capabilities of various online threat actors. In late 2014, the Google Security Team detected a major security flaw in SSL 3.0, necessitating a new approach to communication encryption. TLS was the solution." (Daniels)

### Vulnerabilities Include:
- RegreSSHion
- Insecure Padding Scheme with CBC Ciphers
- Insecure Session Renegotiation and Resumption schemes
- Command Injection
- Possible Unauthenticated Code Execution

### Transport Layer Security (TLS)
TLS is a cryptographic protocol designed to provide communication security over a computer network. 
Aims to provide security, privacy, and authentication. For security and consistency purposes we want to upgrade to at least TLS 1.2 but ideally version 1.3. However, some devices are incompatible with version 1.3 so we will continue support for 1.2. 

### About TLS 1.2
TLS 1.2, released in 2008, was developed with security and performance in mind. It remained the industry standard until yje release of 1.3 in 2018. TLS 1.2 is still functioning. However, it contains obsolete cipher suites that are vulnerable to security attacks.

https://blog.gigamon.com/2021/07/14/what-is-tls-1-2-and-why-should-you-still-care/

### About TLS 1.3
TLS 1.3, released in August 2018, has been widely adopted and is considered the strongest and safest version of the TLS protocol to date. It is supported by major browsers and operating systems, and is recommended for use in secure communication protocols.
- Elimination of obsolete cryptographic algorithms
- Enhanced security over older versions
- Encryption of as much of the handshake as possible
- Use of just 3 cipher suites with perfect forward secrecy (PFS), authenticated encryption, and modern algorithms
- Improved privacy through minimal cleartext protocol bits on the wire
- Content length hiding enabled by minimal cleartext protocol bits

https://www.a10networks.com/glossary/key-differences-between-tls-1-2-and-tls-1-3/
https://www.microsoft.com/en-us/security/blog/2020/08/20/taking-transport-layer-security-tls-to-the-next-level-with-tls-1-3/
https://www.appviewx.com/blogs/why-is-tls-1-3-better-and-safer-than-tls-1-2/

### Unified Hello Removal
Unified hello is a message formater that came out with SSL 2.0. With the removal of SSH 2.0 it is no longer necessary and is being removed for storage space optimization. 

https://security.stackexchange.com/questions/59460/what-is-multi-protocol-unified-hello-and-what-are-the-impacts-of-disabling-ena

### PTC 1.0 Removal
Private Communications Technology (PTC) 1.0 is a protocol developed by Microsoft in the mid-1990s to address security flaws in SSL 2.0. With the removal of SSL 2.0 PTC is no longer necessary.

https://en.wikipedia.org/wiki/Private_Communications_Technology

### Insecure Cipher Removals
- RC4: A bulk cipher listed known for its weaknesses and vulnerabilities.
- 3DES: A bulk cipher considered insecure due to its slow key generation and potential for brute-force attacks.
- DES: A cipher withdrawn as a standard by the National Institute of Standards and Technology (NIST) in 2005 due to its short key-lengths and weaknesses.
- Anonymous key exchanges: Generally vulnerable to Man-in-the-Middle (MitM) attacks.
- CBC mode (without GCM): The CBC encryption algorithm, used in TLS 1.0, SSL 3.0, and lower, is vulnerable to plain-text attacks and the BEAST attack.
- Export ciphers: Ciphers used for export from the United States in the 1990s, now considered insecure due to their weaknesses and vulnerabilities.

https://zofixer.com/what-is-insecure-ssl-insecure-cipher-suite-vulnerability/
https://developers.cloudflare.com/ssl/edge-certificates/additional-options/cipher-suites/recommendations/
https://docs.datadoghq.com/code_analysis/static_analysis_rules/go-security/tls-cipher/
https://pleasantpasswords.com/info/pleasant-password-server/f-best-practices/secure-and-harden-your-server-environment/encryption-protocols-and-ciphers

### Secure Ciphers Install
- AES: Advanced Encryption Standard (AES) is a block cipher algorithm developed by the National Institute of Standards and Technology in 2001. It is considered as industry standard. 
- RC4: Insecure Cipher but Required for Legacy Users
- 3DES: Insecure Cipher, only supported Cipher by Windows XP

https://www.kiteworks.com/risk-compliance-glossary/aes-256-encryption/
https://www.geeksforgeeks.org/advanced-encryption-standard-aes/

### Sources:
https://blog.gigamon.com/2021/07/14/what-is-tls-1-2-and-why-should-you-still-care/
https://www.hass.de/content/setup-microsoft-windows-or-iis-ssl-perfect-forward-secrecy-and-tls-12
https://help.defense.com/en/articles/6302795-ssl-version-2-and-3-protocol-detection-windows-vulnerability
https://nvd.nist.gov/vuln/detail/CVE-2024-6387
https://blog.qualys.com/vulnerabilities-threat-research/2024/07/01/regresshion-remote-unauthenticated-code-execution-vulnerability-in-openssh-server