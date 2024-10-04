# PS1 Script for SSL
## Powershell Script For Disabling SSL 2.0 and 3.0 and Enabling TLS 1.2/1.3

Script created to disable SSL Version 2.0 and 3.0 and Enable the most viable version of TLS. 

Open SSL 2.0 and 3.0 are affected by several cryptographic flaws that can become harmful to your computer and network if
exploited. Attacks may use these flaws to conduct man-in-the-middle attacks or to decrypt communications between
affected services and clients. 

A Gigamon article by Dan Daniels provides a brief statement on why this script is necessary. "Back in 1995, when the 
internet was still figuring itself out, Netscape decided to address growing concerns over internet security by creating 
a form of encryption that would allow data to travel safely without the risk of being intercepted — Secure Socket Layers. 
SSL 1.0 was flawed, and never saw general release, but SSL 2.0 followed shortly afterward, and was then superseded by 
the much improved SSL 3.0. This final SSL version became the standard for internet encryption for nearly two decades. 
Unfortunately, as technology improved, so did the capabilities of various online threat actors. In late 2014, the Google 
Security Team detected a major security flaw in SSL 3.0, necessitating a new approach to communication encryption. TLS 
was the solution." (Daniels)

### Vulnerabilities Include:
- RegreSSHion
- Insecure Padding Scheme with CBC Ciphers
- Insecure Session Renegotiation and Resumption schemes
- Command Injection
- Possible Unauthenticated Code Execution

### Transport Layer Security (TLS)
TLS is a cryptographic protocol designed to provide communication security over a computer network. 
Aims to provide security, privacy, and authentication. For security and consistency purposes we want to upgrade to at 
least TLS 1.2 but ideally version 1.3. However, some devices are incompatible with version 1.3 so we will continue 
support for 1.2. 

#### About TLS 1.2
TLS 1.2, released in 2008, was developed with security and performance in mind. It remained the industry standard until 
the release of 1.3 in 2018. TLS 1.2 is still functioning. However, it contains obsolete cipher suites that are 
vulnerable to security attacks.

https://blog.gigamon.com/2021/07/14/what-is-tls-1-2-and-why-should-you-still-care/

#### About TLS 1.3
TLS 1.3, released in August 2018, has been widely adopted and is considered the strongest and safest version of the TLS 
protocol to date. It is supported by major browsers and operating systems, and is recommended for use in secure 
communication protocols.

- Elimination of obsolete cryptographic algorithms
- Enhanced security over older versions
- Encryption of as much of the handshake as possible
- Use of just 3 cipher suites with perfect forward secrecy (PFS), authenticated encryption, and modern algorithms
- Improved privacy through minimal cleartext protocol bits on the wire
- Content length hiding enabled by minimal cleartext protocol bits

https://www.a10networks.com/glossary/key-differences-between-tls-1-2-and-tls-1-3/ \
https://www.microsoft.com/en-us/security/blog/2020/08/20/taking-transport-layer-security-tls-to-the-next-level-with-tls-1-3/ \
https://www.appviewx.com/blogs/why-is-tls-1-3-better-and-safer-than-tls-1-2/

### Unified Hello Removal
Unified hello is a message formater that came out with SSL 2.0. With the removal of SSH 2.0 it is no longer necessary 
and is being removed for storage space optimization. 

https://security.stackexchange.com/questions/59460/what-is-multi-protocol-unified-hello-and-what-are-the-impacts-of-disabling-ena

### PTC 1.0 Removal
Private Communications Technology (PTC) 1.0 is a protocol developed by Microsoft in the mid-1990s to address security 
flaws in SSL 2.0. With the removal of SSL 2.0 PTC is no longer necessary.

https://en.wikipedia.org/wiki/Private_Communications_Technology

### Insecure Cipher Removals
- RC4: A bulk cipher listed known for its weaknesses and vulnerabilities.
- 3DES: A bulk cipher considered insecure due to its slow key generation and potential for brute-force attacks.
- DES: A cipher withdrawn as a standard by the National Institute of Standards and Technology (NIST) in 2005 due to its short key-lengths and weaknesses.
- Anonymous key exchanges: Generally vulnerable to Man-in-the-Middle (MitM) attacks.
- CBC mode (without GCM): The CBC encryption algorithm, used in TLS 1.0, SSL 3.0, and lower, is vulnerable to plain-text attacks and the BEAST attack.
- Export ciphers: Ciphers used for export from the United States in the 1990s, now considered insecure due to their weaknesses and vulnerabilities.

https://zofixer.com/what-is-insecure-ssl-insecure-cipher-suite-vulnerability/ \
https://developers.cloudflare.com/ssl/edge-certificates/additional-options/cipher-suites/recommendations/ \
https://docs.datadoghq.com/code_analysis/static_analysis_rules/go-security/tls-cipher/ \
https://pleasantpasswords.com/info/pleasant-password-server/f-best-practices/secure-and-harden-your-server-environment/encryption-protocols-and-ciphers

### Secure Ciphers Install
- AES: Advanced Encryption Standard (AES) is a block cipher algorithm developed by the National Institute of Standards and Technology in 2001. It is considered as industry standard. 
- RC4: Insecure Cipher but Required for Legacy Users
- 3DES: Insecure Cipher, only supported Cipher by Windows XP

https://www.kiteworks.com/risk-compliance-glossary/aes-256-encryption/ \
https://www.geeksforgeeks.org/advanced-encryption-standard-aes/

### Secure Hashes
Secure Hashes, also known as Cryptographic Hash Functions, are algorithms that take variable-length input data and 
produce fixed-length, unique digital message digests.
- SHA-2: A family of hashes including SHA-224, SHA-256, SHA-384, and SHA-512. Considered Secure except against length extension attacks. 

https://en.wikipedia.org/wiki/Cryptographic_hash_function \
https://brilliant.org/wiki/secure-hashing-algorithms/ \
https://www.encryptionconsulting.com/education-center/what-is-sha/ \
https://cryptobook.nakov.com/cryptographic-hash-functions/secure-hash-algorithms \
https://csrc.nist.gov/projects/hash-functions

### Key Exchange Algorithms
KEAs are cryptographic protocols used to securely establish a shared secret key between two or more parties over an 
insecure communication channel.
- Diffie-Hellman Key Exchange: A secure key exchange method first introduced in 1976. It relies on discrete logarithms in a finite field. 
- Elliptic Curve Diffie-Hellman (ECDH): A variant of Diffie-Hellman that uses elliptic curves for key exchange.
- RSA: An exchange that uses asymmetric cryptography.

Key Exchange Vulnerabilities:
- Man-in-the-Middle Attacks
- Key Exchange Protocol Vulnerabilities

Microsoft Issued Security Advisory: 3174644
- Updated Support for Diffie-Hellman Key Exchange Fix From 2016, May Need Revisit in the Future
- https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2016/3174644

https://www.jscape.com/blog/key-exchange \
https://www.geeksforgeeks.org/implementation-diffie-hellman-algorithm/ \
https://bluegoatcyber.com/blog/defining-key-exchange-challenges-with-encryption/ \
https://en.wikipedia.org/wiki/Key_exchange

### Cipher Suites
Cipher Suites are sets of instructions on how to secure a network through SSL or TLS. They provide information about how 
to communicate secure data when using network protocols. 

Cipher Suites are a combination of the following:
- Key Exchange Algorithms
- Authentication/Digital Signature Algorithms
- Bulk Encryption Algorithms
- Message Authentication Code Algorithms

https://venafi.com/blog/what-are-cipher-suites/ \
https://www.keyfactor.com/blog/cipher-suites-explained/

### Disabling TLS 1.0 and Adding 1.2/1.3
TLS 1.0 is a security protocol first defined in 1999 for establishing encryption channels over computer networks. 
Evolving requirements and new security vulnerabilities in TLS 1.0 incentivise disabling TLS 1.0 and moving to 1.2 or 1.3.

https://learn.microsoft.com/en-us/security/engineering/solving-tls1-problem \
https://stackoverflow.com/questions/36265534/invoke-webrequest-ssl-fails

### Default Secure Protocols
- TLS 1.2: Enabled by default in Windows 8/Windows Server 2012 and higher.
- TLS 1.1: Not enabled by default in earlier versions of Windows (Windows 7, Windows Server 2012), but can be 
configured manually.
- SSL 3.0 and TLS 1.0: Enabled by default in earlier versions of Windows (Windows 7, Windows Server 2012), but it’s 
recommended to disable them due to security concerns.


- DefaultSecureProtocols Value	Decimal value  Protocol enabled
- 0x00000008 -                               8  Enable SSL 2.0 by default
- 0x00000020  -                             32  Enable SSL 3.0 by default
- 0x00000080   -                           128  Enable TLS 1.0 by default
- 0x00000200    -                          512  Enable TLS 1.1 by default
- 0x00000800     -                        2048  Enable TLS 1.2 by default
- 0x00002000      -                       8192  Enable TLS 1.3 by default

https://knowledge.digicert.com/solution/enable-tls-1-2-as-default-protocols-in-winhttp-windows-2008-and-2012-standard-server \
https://support.laserfiche.com/kb/1013919/raw \
https://superuser.com/questions/1080317/how-to-set-tls-protocols-as-default-after-applying-kb3140245

### About Windows Update KB3140245
Applications and services that are written by using WinHTTP for SSL connections that use the 
WINHTTP_OPTION_SECURE_PROTOCOLS flag can't use TLS 1.1 or TLS 1.2 protocols. This is because the definition of this flag 
doesn't include these applications and services.

This update adds support for DefaultSecureProtocols registry entry that allows the system administrator to specify which 
SSL protocols should be used when the WINHTTP_OPTION_SECURE_PROTOCOLS flag is used.

To apply this update, the DefaultSecureProtocols registry subkey must be added.

https://support.microsoft.com/en-us/topic/update-to-enable-tls-1-1-and-tls-1-2-as-default-secure-protocols-in-winhttp-in-windows-c4bd73d2-31d7-761e-0178-11268bb10392 \
https://www.altium.com/documentation/knowledge-base/altium-designer/update-gives-error-this-application-requires-windows-hotfix-kb3140245?srsltid=AfmBOoqR6KtPjKb0qscR54o1VOx1g8L-wgZMxunOi0Mo63dlZySRgacZ

### Testing
I am still experimenting with how to test this script. I am building this script on Fedora 40, and I am installing a 
Windows 10 VM to run the script. I am also looking into alternate testing methods.

#### Sources to Get SSL 2.0 and 3.0 on VM
The early releases of Firefox would have supported SSL 3.0
- https://ftp.mozilla.org/pub/firefox/releases/

IIS Crypto is a free tool that gives administrators the ability to enable or disable protocols, ciphers, hashes and key 
exchange algorithms on Windows Server 2008, 2012, 2016, 2019 and 2022. It also lets you reorder SSL/TLS cipher suites 
offered by IIS, change advanced settings, implement Best Practices with a single click, create custom templates and test 
your website.

- https://www.nartac.com/Products/IISCrypto

In your configuration file(s), find the entry "SSLProtocol" and modify it to look like: \
SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
- https://support.globalsign.com/ssl/general-ssl/how-enable-or-disable-ssl-and-tls-versions

### Extra Sources:
https://blog.gigamon.com/2021/07/14/what-is-tls-1-2-and-why-should-you-still-care/ \
https://www.hass.de/content/setup-microsoft-windows-or-iis-ssl-perfect-forward-secrecy-and-tls-12 \
https://help.defense.com/en/articles/6302795-ssl-version-2-and-3-protocol-detection-windows-vulnerability \
https://nvd.nist.gov/vuln/detail/CVE-2024-6387 \
https://blog.qualys.com/vulnerabilities-threat-research/2024/07/01/regresshion-remote-unauthenticated-code-execution-vulnerability-in-openssh-server
