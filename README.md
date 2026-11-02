# 🐧 Linux Security Checker

**A lightweight Python-based security auditing tool for Linux systems.**

Linux Security Checker was created from a practical need: understanding how to verify the basic security configuration of a Linux system.

After noticing that colleagues had questions about how to check whether their Linux systems were properly configured, I decided to build a simple tool that brings essential security checks together in one place.

The goal is to make Linux security auditing more accessible while developing practical skills in Python, Linux administration and security engineering.

## 🎯 Project Goals

- Check essential Linux security configurations.
- Identify potentially risky system settings.
- Inspect firewall and system service status.
- Review basic user and permission configurations.
- Generate readable security reports.
- Learn practical Linux Security Engineering through development.

## 🔍 Planned Security Checks

| Category | Description |
|---|---|
| Firewall | Check whether a firewall is active |
| Users | Inspect administrative accounts |
| Services | Identify active system services |
| Permissions | Review selected sensitive file permissions |
| Updates | Check package update status |
| Reporting | Generate structured security reports |

## 🛠️ Technology Stack

- Python 3
- Linux
- Bash
- systemd
- nftables
- JSON
- pytest

## 🚀 Installation

```bash
git clone https://github.com/LourencoGHJ/linux-security-checker.git

cd linux-security-checker

python -m venv .venv

source .venv/bin/activate

pip install -r requirements.txt
```

## 💻 Usage

```bash
python main.py
```

*Usage instructions will be expanded as features are implemented.*

## 🗺️ Roadmap

- [ ] Initial project structure
- [ ] Firewall status inspection
- [ ] Administrative user inspection
- [ ] Active service inspection
- [ ] Sensitive file permission checks
- [ ] System update inspection
- [ ] JSON security reports
- [ ] Automated tests with pytest
- [ ] Documentation and usage examples

## ⚠️ Disclaimer

This project is intended for educational purposes and authorized security auditing of Linux systems.

It does not automatically modify system configurations or apply security changes.

## 👨‍💻 Author

**Guilherme Faria**

GitHub: [@LourencoGHJ](https://github.com/LourencoGHJ)

---

*Built to make Linux security checks simpler, clearer and more accessible.*
