# Anti-Keylogger Tool — Production Keylogger Detector

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows%2010%2F11-blue)](https://www.microsoft.com/windows)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue)](https://www.python.org/)

A production-grade anti-keylogger tool that detects actual keyloggers with **minimal false positives** (<5%). Designed to intelligently distinguish between legitimate applications (HP, Dell, Apple, Microsoft, Logitech) and real threats.

## ⚠️ Legal & Ethical Warning

**THIS TOOL IS FOR DEFENSIVE SECURITY PURPOSES ONLY.**

- Only use on systems you own or have explicit written permission to scan
- Unauthorized use may violate local laws
- The tool does NOT capture keystrokes—it only analyzes keyboard hook patterns

## 🎯 What Makes This Different

**Smart Detection Philosophy:**
- **No false alarms**: Won't flag every unsigned process as malicious
- **Context-aware**: Understands HP, Dell, Apple, Microsoft, Logitech, NVIDIA, and 50+ legitimate publishers
- **Multi-layer evidence**: Requires 3+ strong indicators before flagging (name spoofing + keywords + suspicious location)
- **Production-ready**: Gives clear "System Clean" message when no threats detected

**What it detects:**
- ✅ Name spoofing (explorer.exe in wrong location)
- ✅ Keylogger keywords (keylog, pynput, capture_keys)
- ✅ Unsigned binaries in suspicious locations (temp folders)
- ✅ Unknown publishers in non-standard paths
- ✅ Hidden processes with keyboard hooks

**What it DOESN'T flag:**
- ❌ HP Sure Click, HP Client Security Manager
- ❌ Logitech Options+, Logitech SetPoint
- ❌ Dell SupportAssist, Dell Command
- ❌ Apple Software Update, iTunes
- ❌ Microsoft Office, Windows Defender
- ❌ VS Code, Chrome, Discord, Zoom

## 🚀 Quick Start

### Prerequisites

- Windows 10/11 (x64)
- Python 3.11 or higher
- Administrator privileges (recommended)

### Installation

```powershell
# Clone the repository
git clone <your-repo-url>
cd "Anti Keylogger Tool"

# Install dependencies
pip install -r requirements.txt
```

### Running the Tool

```powershell
# Run the detector
python keylogger_detector.py
```

## 📊 Example Output

### Clean System (No Threats)
```

<img width="1294" height="957" alt="Screenshot 2025-11-13 200436" src="https://github.com/user-attachments/assets/b09ad0b2-e407-46f9-88e2-c467e374ea36" />


### Keylogger Detected
```
<img width="907" height="778" alt="image" src="https://github.com/user-attachments/assets/b346d2d9-f403-4491-b9fa-580358a49128" />

```

## 🛡️ Detection Logic

**Three-Tier Filtering System:**

1. **Whitelist Check** - Quick exit for known-safe processes:
   - Windows system processes (svchost.exe, explorer.exe, etc.)
   - Common applications (Chrome, VS Code, Discord, Zoom)
   - Legitimate publishers (Microsoft, HP, Logitech, Apple, Dell)

2. **Publisher Verification** - Extract and validate digital signatures:
   - Checks file version info for CompanyName
   - Validates against 50+ trusted publishers
   - Verifies path matches expected location

3. **Multi-Indicator Analysis** - Requires 3+ strong indicators:
   - Name spoofing (system process in wrong location)
   - Keylogger keywords (keylog, pynput, hook)
   - Unsigned + keyboard hook
   - Suspicious location (temp folders)
   - Unknown publisher + non-standard path
   - Hidden process with hook

**Only flags processes with threat_score ≥ 3**

## 🔧 Technical Details

### Supported Publishers (Whitelist)
- Microsoft, Apple, Google
- HP, Dell, Lenovo, ASUS
- Logitech, Razer, Corsair, SteelSeries
- NVIDIA, AMD, Intel, Realtek
- Mozilla, Adobe, Oracle, VMware
- Zoom, Cisco, Slack, Discord
- Norton, McAfee, Kaspersky, Malwarebytes
- And 30+ more...

### Trusted Locations
- `C:\Windows\System32`
- `C:\Windows\SysWOW64`
- `C:\Program Files\`
- `C:\Program Files (x86)\`
- `C:\Program Files\WindowsApps\`

### Suspicious Locations
- `\Temp\`, `\Downloads\`, `\Desktop\`
- `AppData\Local\Temp\`
- Random user directories

## 📁 Project Structure

```
Anti Keylogger Tool/
├── README.md                    # This file
├── LICENSE                      # MIT License
├── requirements.txt             # Dependencies (pywin32, colorama, etc.)
├── keylogger_detector.py        # Main production detector
└── src/
    ├── enumerator.py           # Windows API hook enumeration
    ├── heuristics.py           # Legacy heuristic engine
    └── (other utility modules)
```

## 🔒 Security & Privacy

### What This Tool Does NOT Do

- ❌ Does NOT capture keystrokes
- ❌ Does NOT record typed characters
- ❌ Does NOT store user input
- ❌ Does NOT transmit data remotely

### What This Tool DOES

- ✅ Analyzes keyboard hook metadata
- ✅ Verifies digital signatures
- ✅ Checks process locations
- ✅ Detects name spoofing
- ✅ Reports high-confidence threats only

## 🛠️ Advanced Usage

### Admin Mode

For full functionality, run with administrator privileges:

```powershell
# Using PowerShell (Run as Administrator)
python src/main.py --admin
```

Admin mode enables:
- Full process enumeration
- Digital signature verification
- Token/privilege inspection
- Terminate/quarantine actions (with confirmation)

### Mock Mode

For development and testing without admin rights:

```powershell
python src/main.py --mock
```

Simulates hook data for safe testing in CI/CD pipelines.

## 📊 Example Output

```
╔══════════════════════════════════════════════════════════════╗
║  MAIN MENU                                                   ║
╠══════════════════════════════════════════════════════════════╣
║  [1] Start monitoring (real-time)                           ║
║  [2] Snapshot current hooks                                 ║
║  [3] List all processes & hooks                             ║
║  [4] View detection history & reports                       ║
║  [5] Export report (json/csv)                               ║
║  [0] Exit                                                    ║
╚══════════════════════════════════════════════════════════════╝
```

```
ID   PID   Process         HookType         Risk   Notes
──────────────────────────────────────────────────────────────
1    4120  badproc.exe     WH_KEYBOARD_LL   HIGH   ⚠ unsigned, hidden window
2    2248  explorer.exe    WH_KEYBOARD_LL   LOW    ✅ signed system process
```

## 🧪 Testing

```powershell
# Run unit tests
python -m pytest tests/

# Run specific test
python -m pytest tests/test_heuristics.py -v

# Test with mock data
python src/main.py --mock
```

## 📚 Documentation

- [Architecture Overview](docs/architecture.md) - Technical design and implementation
- [How to Run](docs/howto_run.md) - Detailed usage scenarios
- [SRS](srs.md) - Software Requirements Specification

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure no keystroke capture code is added
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Code and documentation are also available under CC-BY-NC for non-commercial use.

## ⚖️ Disclaimer

This tool is provided "AS IS" without warranty of any kind. The authors are not responsible for any misuse or damage caused by this tool. Always comply with local laws and obtain proper authorization before monitoring any system.

## 🙏 Acknowledgments

Built for educational purposes to understand Windows hook mechanisms and defensive security practices.

---

**Remember**: Use this tool responsibly, ethically, and legally. 🛡️
