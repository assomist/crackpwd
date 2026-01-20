# CrackPWD

```
    _____                _   ____  _    _ ____  
   / ____|              | | |  _ \| |  | |  _ \ 
  | |     _ __ __ _  ___| |_| |_) | |  | | | | |
  | |    | '__/ _` |/ __| |/ __/| |/| | | | |
  | |____| | | (_| | (__| < |   | |  | | |_| |
   \_____|_|  \__,_|\___|_|\_\_|   |_|  |_|____/ 
```

Professional multi-protocol password cracker. Pure PowerShell. Zero dependencies.

---

## Features

- Full auto-detection (form URL, fields, fail patterns)
- Multi-protocol support (HTTP, SSH, FTP, RDP, ZIP)
- WAF/Rate-limit bypass (random UA, X-Forwarded-For)
- Hash cracking (MD5, SHA1, SHA256, SHA512)
- Port scanner
- Target analyzer
- Progress tracking with speed stats
- Session saving and resume
- Proxy support
- Custom headers and cookies
- Output to file

---

## Modes

| Mode | Description |
|------|-------------|
| `web` | HTTP/HTTPS form bruteforce |
| `hash` | Hash cracker (auto-detect type) |
| `zip` | ZIP/RAR password cracker |
| `ssh` | SSH bruteforce |
| `ftp` | FTP bruteforce |
| `rdp` | RDP bruteforce |
| `scan` | Port scanner |
| `analyze` | Analyze target for login forms |

---

## Install

```powershell
git clone https://github.com/assomist/crackpwd.git
cd crackpwd
```

---

## Usage

Add passwords to `wordlist.txt` (one per line), then:

```powershell
.\crackpwd.ps1 web -Target "https://site.com/" -User admin

.\crackpwd.ps1 web -Target "https://site.com/" -User admin -Bypass

.\crackpwd.ps1 hash -Hash "5f4dcc3b5aa765d61d8327deb882cf99"

.\crackpwd.ps1 zip -Target secret.zip

.\crackpwd.ps1 ssh -Target 192.168.1.1 -User root

.\crackpwd.ps1 ftp -Target 192.168.1.1 -User admin

.\crackpwd.ps1 scan -Target 192.168.1.1

.\crackpwd.ps1 analyze -Target "https://site.com/"
```

---

## Options

### Basic

| Option | Description |
|--------|-------------|
| `-Target` | URL, IP, or file |
| `-User` | Username |
| `-Wordlist` | Password file (default: wordlist.txt) |
| `-Port` | Custom port |
| `-Output` | Save results to file |

### Web

| Option | Description |
|--------|-------------|
| `-FormUrl` | Form action URL |
| `-PostData` | POST data with ^USER^ and ^PASS^ |
| `-FailString` | Fail indicator |
| `-SuccessString` | Success indicator |
| `-Cookie` | Custom cookies |
| `-Headers` | Custom headers |
| `-Proxy` | Proxy URL |
| `-FollowRedirect` | Follow redirects |
| `-IgnoreSSL` | Ignore SSL errors |

### Hash

| Option | Description |
|--------|-------------|
| `-Hash` | Hash to crack |
| `-HashType` | auto, md5, sha1, sha256, sha512 |

### Evasion

| Option | Description |
|--------|-------------|
| `-Bypass` | Enable all evasion |
| `-RandomAgent` | Random User-Agent |
| `-RandomDelay` | Random delay (100-1000ms) |
| `-Delay` | Fixed delay (ms) |
| `-Timeout` | Request timeout |

---

## Output

```
    _____                _   ____  _    _ ____  
   / ____|              | | |  _ \| |  | |  _ \ 
  | |     _ __ __ _  ___| |_| |_) | |  | | | | |
  | |    | '__/ _` |/ __| |/ __/| |/| | | | |
  | |____| | | (_| | (__| < |   | |  | | |_| |
   \_____|_|  \__,_|\___|_|\_\_|   |_|  |_|____/ 
                                                
  [ Professional Password Cracker v1.0.0 ]
  [ @assomist | discord.gg/lcp ]

[*] Starting web bruteforce attack
[*] Target: https://site.com/auth.php
[*] User: admin
[+] Form URL: https://site.com/auth.php
[+] User field: username
[+] Pass field: password
[+] Hidden field: action=login
[*] POST data: action=login&username=^USER^&password=^PASS^
[+] Fail pattern: 'incorrects'
[*] Loaded 100 passwords
[*] ATTACK STARTED

  [47/100] (47%) secretpass123 | 12.5 pwd/s | Errors: 0

  ================================================================
  |                    PASSWORD FOUND!                          |
  ================================================================
  |  Username : admin
  |  Password : secretpass123
  |  Target   : https://site.com/auth.php
  |  Time     : 3.76s
  |  Attempts : 47 / 100
  ================================================================

[*] Session complete. Total time: 3.82s
```

---

## Requirements

| Mode | Requires |
|------|----------|
| web | Nothing |
| hash | Nothing |
| zip | 7-Zip |
| ssh | plink.exe (PuTTY) |
| ftp | Nothing |
| rdp | Nothing |
| scan | Nothing |

---

## Disclaimer

For authorized security testing only. Unauthorized access is illegal.

---

## Links

Website: [lcpnet.fr](https://lcpnet.fr)

Website: [d4rp.fr]
(https://d4rp.fr)

Discord: [discord.gg/lcp](https://discord.gg/lcp)

---

## License

MIT
