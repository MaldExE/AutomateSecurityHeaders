#!/usr/bin/env python3

import argparse
import subprocess
import sys
import os
import re

RECOMMANDATIONS = {
    "Strict-Transport-Security": {
        'owasp': "max-age=31536000; includeSubDomains",
        'compat': "max-age=31536000; includeSubDomains"
    },
    "Content-Security-Policy": {
        'owasp': [
            "default-src 'self'",
            "form-action 'self'",
            "object-src 'none'",
            "frame-ancestors 'none'",
            "upgrade-insecure-requests",
            "block-all-mixed-content"
        ],
        'compat': None  # Entête absent accepté pour compatibilité étendue
    },
    "X-Frame-Options": {
        'owasp': "deny",
        'compat': "sameorigin"
    },
    "X-Content-Type-Options": {
        'owasp': "nosniff",
        'compat': "nosniff"
    },
    "X-XSS-Protection": {
        'owasp': ["0", None],  # "0" ou absent
        'compat': "1;mode=block"
    },
}

HEADERS_ORDER = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection"
]

def check_header_status(header, value):
    rec = RECOMMANDATIONS[header]
    if value is None:
        if header == "Content-Security-Policy" and rec['compat'] is None:
            return "**(!)**"
        if header == "X-XSS-Protection" and None in rec['owasp']:
            return '[component="icon" type="check"]'
        return '[component="icon" type="close"] Absent'
    val = value.strip().lower()
    if header == "Content-Security-Policy":
        owasp_ok = all(dir in val.replace(";", ";\n") for dir in [d.lower() for d in rec['owasp']])
        if owasp_ok:
            return '[component="icon" type="check"]'
        if rec['compat'] is None:
            return '[component="icon" type="close"] Présente, mais non conforme'
        return '[component="icon" type="close"] Présente, mais non conforme'
    elif header == "X-XSS-Protection":
        if val == "0":
            return '[component="icon" type="check"]'
        elif "1; mode=block" in val:
            return "**(!)**"
        else:
            return '[component="icon" type="close"] Valeur non recommandée'
    else:
        ow_val = rec['owasp']
        compat_val = rec['compat']
        if val == (ow_val.lower() if ow_val else ""):
            return '[component="icon" type="check"]'
        elif compat_val and val == compat_val.lower():
            return "**(!)**"
        else:
            return '[component="icon" type="close"] Valeur non recommandée'

def parse_shcheck_output(output):
    """
    Parse la sortie brute de shcheck et retourne un dict {header: value}.
    Spécialement pour les entêtes avec bloc multi-lignes (ex: Content-Security-Policy).
    """
    headers = {}
    lines = output.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        # Cas header simple avec (Value: ...)
        match = re.match(r'^\[\*\] Header (.*) is present!\s+\(Value:\s*(.+)\)', line)
        if match:
            hdr = match.group(1)
            val = match.group(2)
            headers[hdr] = val
            i += 1
            continue
        # Cas header avec bloc multi-lignes Value:
        match2 = re.match(r'^\[\*\] Header (.*) is present!$', line)
        if match2:
            hdr = match2.group(1)
            # Verifie si la ligne suivante est 'Value:'
            if i+1 < len(lines) and lines[i+1].strip() == "Value:":
                val_lines = []
                i += 2
                # On accepte lignes tabulées ou espaces (pour compatibilité shcheck)
                while i < len(lines) and (lines[i].startswith("\t") or lines[i].startswith("    ") or lines[i].strip().find(":") != -1):
                    val_lines.append(lines[i].strip())
                    i += 1
                headers[hdr] = "\n".join(val_lines)
            else:
                headers[hdr] = None
            continue
        i += 1
    return headers

def output(line, outputfile):
    if outputfile:
        with open(outputfile, 'a', encoding='utf-8') as f:
            f.write(line + '\n')
    else:
        print(line)

def main():
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument('-f', '--file', dest='inputfile', required=True)
    parser.add_argument('-o', '--output', dest='outputfile', required=False)
    args = parser.parse_args()

    if args.outputfile:
        os.makedirs(os.path.dirname(args.outputfile), exist_ok=True)
        open(args.outputfile, 'w', encoding='utf-8').close()

    header_row = "| Application | " + " | ".join(HEADERS_ORDER) + " |"
    sep_row = "|" + "|".join(['--------' for _ in range(len(HEADERS_ORDER) + 1)]) + "|"
    output(header_row, args.outputfile)
    output(sep_row, args.outputfile)

    with open(args.inputfile, 'r', encoding='utf-8') as infile:
        for line in infile:
            line = line.strip()
            if not line:
                continue
            proc = subprocess.run(
                ['python3', 'shcheck/shcheck.py', line, '--colours=none', '-d'],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                encoding='utf-8'
            )
            parsed = parse_shcheck_output(proc.stdout)
            row = [line]
            for header in HEADERS_ORDER:
                val = parsed.get(header)
                status = check_header_status(header, val)
                row.append(status)
            row_str = "| " + " | ".join(row) + " |"
            output(row_str, args.outputfile)

    if args.outputfile:
        print(f"Le résultat a été écrit dans {args.outputfile}")

if __name__ == "__main__":
    main()
