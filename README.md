# WebScanX 🚀

```
 __      __      ___.     _________                    ____  ___
/  \    /  \ ____\_ |__  /   _____/ ____ _____    ____ \   \/  /
\   \/\/   // __ \| __ \ \_____  \_/ ___\\__  \  /    \ \     /
 \        /\  ___/| \_\ \/        \  \___ / __ \|   |  \/     \
  \__/\  /  \___  >___  /_______  /\___  >____  /___|  /___/\  \
       \/       \/    \/        \/     \/     \/     \/      \_/
```

**WebScanX** is a comprehensive web scanning tool that helps you discover subdomains, detect technologies, check for important files, detect WAFs, and brute-force directories on a target domain.

## Features

- **Subdomain enumeration**: Discover subdomains associated with a target domain.  
- **Web technology detection**: Identify technologies used by the target website.  
- **File discovery**: Search for important files like `robots.txt`, `security.txt`, etc.  
- **WAF detection**: Identify the presence of Web Application Firewalls (WAFs).  
- **Directory brute-forcing**: Brute-force directories on the target website.  

## Installation

### Step 1: Clone the repository

Clone the repository using the following command:

```bash
git clone https://github.com/sczxw/WebScanX.git
```

Navigate into the WebScanX directory:

```bash
cd webscanx
```

### Step 2: Set Up a Virtual Environment

Create a virtual environment to manage dependencies:

- **On Linux/macOS:**

  ```bash
  python3 -m venv venv
  source venv/bin/activate
  ```

- **On Windows:**

  ```bash
  python -m venv venv
  venv\Scripts\activate
  ```

### Step 3: Install Dependencies

With the virtual environment activated, install the required dependencies:

```bash
pip install -r requirements.txt
```

The dependencies include:

- `requests`  
- `dnspython`  
- `builtwith`  
- `wafw00f`  
- `colorama`  

## Usage


Once you have installed the dependencies, you can run the tool as follows:

```bash
python webscanx.py
```

Or, if you're on a Unix-like system and want to execute the script directly:

```bash
chmod +x webscanx.py
```

```bash
./webscanx.py
```
---

## Deactivating the Virtual Environment

After you are done using the tool, deactivate the virtual environment by running:

```bash
deactivate
```

This works in both Command Prompt and PowerShell on Windows, as well as in terminal on Linux/macOS.  

---

[![X](https://img.shields.io/badge/X-%23000000.svg?style=for-the-badge&logo=X&logoColor=white)](https://x.com/sczxw_)

Made by sczxw.
