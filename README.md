# Phishing & Malicious Link Warning System

A Chrome Manifest V3 extension that scans web pages in real-time for phishing indicators, open redirects, brand impersonation, clickjacking attempts, deceptive subdomains, and credential-harvesting elements.


## Features
- **Real-Time Link Scanner:** Parses DOM `<a>` tags and identifies unsafe URLs.
- **On-Page Highlights:** Highlights suspicious links directly on the webpage in red.
- **Toolbar Threat Counter Badge:** Updates extension icon badge text with the active threat count.
- **Export Threat Log:** Downloads detected threats as a structured `.json` log file.
- **Advanced Detection Logic:** Features advanced detection logic to detect clickjacking, open redirects, subdomain depth, domain mismatch, unsandboxed iframes, no trusted domain whitelist

## Team Members (Group 36 - ROSPL)
- **Vinit Yadav** (`vinity7`) - Lead Developer & Repository Owner
- **Kshitij Sawant** (`kshitijsawant`) - Developer (Badge Counter)
- **Nitin Mitbhavkar** (`nitinmitbhavkar`) - Documentation Lead
- **Deep Mistry** (`deepmistry`) - QA & Testing Lead

## Setup Instructions
1. Clone this repository:
   ```bash
   git clone [https://github.com/vinity7/AI-Phishing-Detector.git](https://github.com/vinity7/AI-Phishing-Detector.git)
