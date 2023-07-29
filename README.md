# RDP-Stealer
The RDP-Stealer is C++ malware that targets Remote Desktop Protocol (RDP) processes. It acts as a keystroke logger, capturing credentials provided by users in RDP and sending back encrypted data to a C2 server.

## Features
- Executes without a visible window (in the background).
- Captures keystrokes in RDP processes using the context of `mstsc.exe` and `CredentialUIBroker.exe`.
- Encrypts the captured data using `XOR` and `BASE64`.
- Sends data to a C2 server.

## POC
https://github.com/Gurpreet06/RDP-Stealer/assets/74554439/117a655e-63eb-409e-a62c-4682eab4a772

