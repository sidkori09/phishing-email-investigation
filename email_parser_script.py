#!/usr/bin/env python3
"""
Automated EML Email Header & Threat Indicator Extractor
Author: SOC Analyst Portfolio
Description: Parses raw .eml files to extract routing headers, SPF/DKIM/DMARC status, links, and attachments.
"""

import sys
import email
from email import policy
import re
import json

def parse_eml(file_path):
    with open(file_path, 'rb') as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    print("=" * 60)
    print("      SOC EMAIL THREAT PARSER - INCIDENT INVESTIGATION      ")
    print("=" * 60)

    # Basic Headers
    print(f"\n[+] Subject: {msg.get('Subject')}")
    print(f"[+] From (Header): {msg.get('From')}")
    print(f"[+] To: {msg.get('To')}")
    print(f"[+] Return-Path: {msg.get('Return-Path')}")
    print(f"[+] Date: {msg.get('Date')}")

    # Authentication Checks
    auth_results = msg.get('Authentication-Results', '')
    print("\n[+] Authentication Results Analysis:")
    if 'spf=' in auth_results.lower():
        spf_status = re.search(r'spf=(\w+)', auth_results, re.IGNORECASE)
        print(f"    - SPF Status:   {spf_status.group(1).upper() if spf_status else 'UNKNOWN'}")
    if 'dkim=' in auth_results.lower():
        dkim_status = re.search(r'dkim=(\w+)', auth_results, re.IGNORECASE)
        print(f"    - DKIM Status:  {dkim_status.group(1).upper() if dkim_status else 'UNKNOWN'}")
    if 'dmarc=' in auth_results.lower():
        dmarc_status = re.search(r'dmarc=(\w+)', auth_results, re.IGNORECASE)
        print(f"    - DMARC Status: {dmarc_status.group(1).upper() if dmarc_status else 'UNKNOWN'}")

    # Extract Links & URLs
    urls = []
    attachments = []

    for part in msg.walk():
        content_type = part.get_content_type()
        content_disposition = str(part.get("Content-Disposition"))

        if content_type == "text/html":
            body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
            found_urls = re.findall(r'href=["\'](https?://[^"\']+)["\']', body)
            urls.extend(found_urls)

        if "attachment" in content_disposition or part.get_filename():
            filename = part.get_filename()
            if filename:
                attachments.append({
                    "filename": filename,
                    "content_type": content_type
                })

    print("\n[+] Extracted Hyperlinks (Potential Phishing Indicators):")
    for url in urls:
        print(f"    - [URL] {url}")

    print("\n[+] Attached Files:")
    for att in attachments:
        filename = att['filename']
        is_suspicious = filename.count('.') > 1 or filename.endswith(('.exe', '.scr', '.vbs', '.bat', '.ps1'))
        alert_flag = "⚠️ [SUSPICIOUS DOUBLE EXTENSION / EXECUTABLE]" if is_suspicious else ""
        print(f"    - {filename} (Type: {att['content_type']}) {alert_flag}")

    print("\n" + "=" * 60)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python parse_eml.py <path_to_eml_file>")
        sys.exit(1)
    parse_eml(sys.argv[1])