# Example??

$cert = New-SelfSignedCertificate -KeyUsage DigitalSignature -KeySpec Signature -KeyAlgorithm RSA -KeyLength 2048 -DNSName “www.yourdomain.com” -CertStoreLocation Cert:\CurrentUser\My -Type CodeSigningCert -Subject “Your Code Signing Certificate Name”

$cert = New-SelfSignedCertificate -KeyUsage DigitalSignature -KeySpec Signature -KeyAlgorithm RSA -KeyLength 2048 -DNSName “www.yourdomain.com” -CertStoreLocation Cert:\CurrentUser\My -Type CodeSigningCert -Subject “Rylei On PowerShell”
