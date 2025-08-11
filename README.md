# Pentesting-Tools-Install

**Pentesting-Tools-Install** is a script that allows you to quickly and easily install a wide variety of penetration testing tools commonly found on Kali Linux and other security distributions. The script supports both Debian-based (APT) and Red Hat-based (DNF) systems, installing tools via the system package manager, pip, or directly from source as appropriate.

---

## Features

- **Automated installation** of dozens of popular and up-to-date pentesting, red teaming, forensics, wireless, and cloud tools.
- **Supports both APT and DNF** package managers (Debian/Ubuntu and RHEL/Fedora/CentOS).
- **Installs via pip or git** for tools not available in the package manager.
- **Error handling and logging** for robust unattended installs.
- **User confirmation** before installation begins.
- **Checks for root privileges and required system commands** before proceeding.

---

## Usage

```bash
sudo ./install_pentesting_tools
```

You will be prompted to select your package manager (`d` for DNF, `a` for APT) and to confirm installation.

---

## How It Works

- The script checks for root privileges and required system commands.
- It moves the tool list files (`apttoolfile`, `rhtoolfile`) to a working directory.
- Based on your selection, it reads the appropriate tool list and installs each tool using the specified method (`apt-get`, `dnf`, `pip`, or `git`).
- All actions and errors are logged to `install_log`.

---

## Included Tools

The following is a non-exhaustive list of tools included. The list is regularly updated to include new and relevant tools for modern penetration testing and red teaming.

### Core Pentesting Tools

- **nmap**: Network discovery and security auditing.
- **wireshark**: Network protocol analyzer.
- **aircrack-ng**: Wireless network security auditing.
- **john**: Password cracker.
- **hydra**: Parallelized login cracker.
- **hashcat**: Advanced password recovery utility.
- **metasploit-framework**: Exploitation framework.
- **sqlmap**: Automated SQL injection and database takeover tool.
- **nikto**: Web server scanner.
- **lynis**: Security auditing tool.
- **openvas**: Vulnerability scanner.
- **zaproxy**: Web application security scanner.
- **burpsuite**: Web application security testing platform.
- **recon-ng**: Web reconnaissance framework.
- **setoolkit**: Social engineering toolkit.
- **wifite**: Automated wireless attack tool.
- **netcat**: Network analysis tool.
- **mitmproxy**: SSL-capable man-in-the-middle HTTP proxy.
- **crunch**: Wordlist generator.
- **foremost**: File carving tool.
- **binwalk**: Firmware analysis tool.
- **chkrootkit**: Rootkit detector.
- **macchanger**: MAC address changer.
- **driftnet**: Network image sniffer.
- **cutycapt**: Web page screenshot utility.
- **gobuster**: Directory/file brute-forcer.
- **amass**: DNS enumeration and attack surface mapping.
- **sublist3r**: Subdomain enumeration.
- **theharvester**: OSINT gathering tool.
- **dnsrecon**: DNS enumeration.
- **fierce**: DNS reconnaissance tool.
- **dirb/dirsearch**: Web content scanners.
- **responder**: LLMNR, NBT-NS, and MDNS poisoner.
- **evil-winrm**: WinRM shell for red teaming.
- **bloodhound**: Active Directory enumeration.
- **crackmapexec**: Swiss army knife for pentesting networks.
- **impacket**: Collection of Python classes for network protocols.

### Wireless & Radio

- **kismet**: Wireless network detector/sniffer.
- **reaver**: WPA/WPA2 WPS attack tool.
- **cowpatty**: WPA-PSK dictionary attack tool.
- **gqrx**: Software-defined radio receiver.
- **rtl-sdr**: SDR utilities.

### Web & App Testing

- **skipfish**: Web application security scanner.
- **vega**: Web vulnerability scanner.
- **webscarab**: Web application testing tool.
- **wfuzz**: Web application brute forcer.

### Forensics & Reverse Engineering

- **volatility**: Memory forensics framework.
- **autopsy**: Digital forensics platform.
- **stegcracker**: Steganography brute-force tool.
- **exiftool**: Metadata reader/writer.
- **gdb**: GNU Debugger.
- **radare2**: Reverse engineering framework.
- **apktool**: Android reverse engineering tool.
- **jd-gui**: Java decompiler.

### Cloud & Active Directory

- **cloudenum**: Cloud asset enumeration.
- **m365-defender**: Microsoft 365 Defender API client.
- **bloodhound-py**: BloodHound data collector for AD.

### Extra Useful Tools

- **httrack**: Website copier.
- **medusa**: Login brute-forcer.
- **ncrack**: Network authentication cracker.
- **p0f**: Passive OS fingerprinting.
- **ike-scan**: VPN scanner.
- **ferret, sparta, bdfproxy, magictree, regripper, metagoofil**: Various tools installed via git.

### Python Tools

- **pip**: Python package manager (and upgrade).
- **requests, shodan, autopwn, termineter**: Python security libraries and tools.

### Red Team & Post Exploitation

- **PowerSploit**: PowerShell post-exploitation framework.
- **CredCrack**: Credential harvester.
- **Mimikatz**: Credential extraction tool.

---

## Adding or Updating Tools

- To add or update tools, edit the `apttoolfile` or `rhtoolfile` files.
- Each line should follow the format:  
  `TOOLNAME (method) install_command`
- Supported methods: `auto` (package manager), `pip`, `manual` (git/wget), etc.

---

## Logging

- All actions and errors are logged to `install_log` in the current directory.

---

## Requirements

- Linux system with either APT or DNF package manager.
- Root privileges.
- Internet connection.

---

## Disclaimer

This script is intended for use in authorized penetration testing and security research environments only. Use responsibly and with permission.

---

## License

MIT License

---

## Credits

Tool descriptions and inspiration from [tools.kali.org](https://tools.kali.org/) and various open source projects. Special thanks to the contributors and maintainers of the included tools.
