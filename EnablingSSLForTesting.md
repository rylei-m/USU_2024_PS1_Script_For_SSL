# Enabling SSL 2.0 and SSL 3.0 in the Windows Registry, follow these steps:
### SSL 2.0 and 3.0 are Deprecated and Contain Major Security Flaws. These Steps Should Only Be Used for Testing in a Controlled Environment. It's generally recommended to use more secure protocols like TLS 1.2 or TLS 1.3.

## Open Registry Editor:
- Press Win + R, type regedit, and press Enter.
- Navigate to SSL Protocols:
- Go to HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols.

## Create/Modify SSL 2.0 and SSL 3.0 Entries:
- If they don’t exist, create new keys for SSL 2.0 and SSL 3.0 under Protocols.
- For each protocol, create or modify the Client and Server subkeys.

## Enable Protocols:

### For SSL 2.0:
- Path: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client
- Add a DWORD value named Enabled and set it to 1.
- Path: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server
- Add a DWORD value named Enabled and set it to 1.

### For SSL 3.0:

- Path: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client
- Add a DWORD value named Enabled and set it to 1.
- Path: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server
- Add a DWORD value named Enabled and set it to 1.

## Restart Your Computer:
Changes will take effect after a system restart.
