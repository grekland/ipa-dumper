# iOS IPA Dumper

*A powerful Python tool for extracting decrypted IPA files from iOS devices using Frida. Designed for developers and security researchers, it automates the process of retrieving decrypted application binaries.*

<img src="./assets/Icon.png" style="width:60%"/>

## Key Features

- **Automatic Device Detection**: Detects USB-connected devices.
- **SSH Management**: Password and key-based authentication supported.
- **Progress Tracking**: Real-time progress bars for file transfers.
- **IPA Packaging**: Automatically packages extracted files into IPA format.
- **Robust Logging**: Clear, grouped logs for every operation.
- **User-Friendly CLI**: Intuitive command-line interface.

---

## Prerequisites

- **Python**: Version 3.7 or higher.
- **Jailbroken iOS Device**: Frida must be installed.
- **USB Connection**: To the target iOS device.
- **SSH Access**: Enabled on the device.

---

## Installation

1. Clone the repository:
   ```bash
   git clone [<repository-url>](https://github.com/grekland/ipa-dumper/tree/main)
   cd ipa-dumper
   ```

2. Install required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

Required packages include:
- `frida`
- `paramiko`
- `scp`
- `tqdm`
- `pathlib`
- `typing`

---

## Usage

### Basic Command

Run the following command to dump an app:
```bash
python dumper.py <app-identifier> --host <ip-address> [options]
```

### Command-Line Arguments

#### Required Argument
- **target**: Bundle identifier or display name of the target app.

#### SSH Options
- `--host`: SSH hostname (default: `127.0.0.1`).
- `--port`: SSH port (default: `22`).
- `--user`: SSH username (default: `root`).
- `--password`: SSH password for authentication.
- `--key-file`: Path to SSH private key file.

#### Output Options
- `--output`: Custom directory for the dumped IPA (default: `~/Downloads/ios_dumps/`).

---

## Examples

### Password Authentication
```bash
python dumper.py com.example.app --host 192.168.1.100 --password mypassword
```

### SSH Key Authentication
```bash
python dumper.py "App Name" --host 192.168.1.100 --key-file ~/.ssh/id_rsa
```

### Custom Output Directory
```bash
python dumper.py com.example.app --host 192.168.1.100 --password mypass --output ~/Desktop/dumps
```

---

## Output Details

The tool generates:

1. **Decrypted IPA File**: Named after the app.
2. **Logs**: Clear and grouped output for debugging and insights.

---

## Error Handling

Comprehensive error-handling covers:

- SSH connection failures.
- File transfer interruptions.
- Device detection issues.
- Invalid authentication credentials.

---

## Notes

1. Ensure either `--password` or `--key-file` is provided for SSH authentication.
2. Connect the iOS device via USB.
3. The target app should be open on the device.
4. Frida must be properly installed on the jailbroken device.

---

## Credits

- **Frida**: [Frida Tools](https://github.com/frida/frida-tools/)
- **AloneMonkey**: [GitHub Repository](https://github.com/AloneMonkey/frida-ios-dump)

---

For further support or to report issues, visit the GitHub repository.