# CachePurgeHound

**CachePurgeHound** is a lightweight Python tool that automates detection of the **Unauthenticated Cache Purging** vulnerability across subdomains of a given target.

## 🚀 Features

- Collects subdomains using `subfinder`
- Filters for live hosts with status `200` using `httpx`
- Checks for presence of the `x-cache` header
- Sends unauthenticated `PURGE` requests and detects if `{"status":"ok"}` is returned
- Prints potential vulnerable endpoints

## 🔧 Requirements

Make sure the following tools are installed and in your PATH:

- [subfinder](https://github.com/projectdiscovery/subfinder)
- [httpx](https://github.com/projectdiscovery/httpx)
- `curl`
- Python 3.x
- `tqdm` module (`pip install tqdm`)

## 📦 Installation

```bash
git clone https://github.com/CyberSecurityUP/CachePurgeHound
cd CachePurgeHound
pip install -r requirements.txt
