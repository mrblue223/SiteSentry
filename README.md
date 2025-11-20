# 🛡️ SiteSentry: Advanced Footprinting & Security Assessment Tool (WORK IN PROGRESS!!!)

**Enterprise-grade reconnaissance and security assessment tool for comprehensive website footprinting, vulnerability analysis, and Open Source Intelligence (OSINT) gathering.**

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Basic Usage](#-basic-usage)
- [Scan Workflow](#-scan-workflow)
- [Legal & Ethics](#-legal--ethics)

---

## 🎯 Overview

The **SiteSentry** tool is a comprehensive Python-based reconnaissance platform designed for security professionals and penetration testers. It performs deep technical analysis, security assessment, and intelligence gathering across multiple attack vectors in a single automated workflow.

**Tool Name**: `SiteSentry.py`

---

## ✨ Features

The tool executes a multi-layered scan covering the following areas:

| Category | Features |
| :--- | :--- |
| **🔍 Comprehensive Reconnaissance** | Full DNS record enumeration (A, AAAA, MX, NS, TXT, CNAME) |
| | **WHOIS Analysis**, **GeoIP/ASN Lookup**, Common **Email Enumeration** |
| | Multi-threaded **Subdomain Discovery** with wildcard detection |
| **🛡️ Security Assessment** | Deep **Technology Fingerprinting** (CMS, framework, version detection) |
| | **Security Header Analysis** (HSTS, CSP, X-Frame-Options) |
| | **CORS Misconfiguration Testing**, **Email Security Audit** (SPF, DMARC) |
| **☁️ Exposure Analysis** | **Cloud Bucket Enumeration** (AWS S3, Google Cloud, Azure Blob) |
| | **Automated Google Dorking** for exposed files and directories |
| | **Document Metadata Discovery** patterns for sensitive info |
| **⚙️ Advanced Capabilities** | Robust **Retry Logic** & **Timeouts** for all external connections |
| | Optimized **Multi-threaded Performance** |
| | Comprehensive report output in **Text** and **JSON** formats |

---

## 🛠️ Installation

### Prerequisites
- **Python 3.7** or higher
- **pip** (Python package manager)
- **Internet connection** for external API calls

### Step 1: Download Requirements File

Create a file called `requirements.txt` with the following content:

### Step 2: Install Dependencies

**Method 1: Using requirements file (Recommended)**
		pip install -r requirements.txt

**Method 2: Development installation with virtual environment**
		python -m venv sitesentry-env
		source sitesentry-env/bin/activate  # Linux/Mac

### Step 3: Verify Installation
		python3 sitesentry.py --help

# Quick start
**Run the script by providing a target domain as a positional argument:**
		python sitesentry.py example.com
**Basic Security Assessment Example**
		python sitesentry.py api-docs.target-company.com

# Basic Usage
**Command Structure**
		python sitesentry.py <domain> [options]
**Essential exmple**
		python sitesentry.py targetdomain.net

# Scan Workflow
**What happens during a scan? The tool automatically performs:**
- ✅ DNS lookups and WHOIS analysis
- 🔍 Subdomain discovery and Technology detection
- 🛡️ Security Header analysis and CORS testing
- ☁️ Cloud Storage and external Exposure checks
- 📊 Comprehensive Report Generation

# ⚖️ Legal & Ethics

**Warning:** This tool is designed for authorized security testing and educational purposes only. Unauthorized scanning of networks or systems is illegal and unethical. **Always obtain explicit written permission from the target domain owner before running this tool.** The user is responsible for adhering to all applicable laws and regulations.
