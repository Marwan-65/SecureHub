#!/usr/bin/env python3
"""
Ransomware Detector - A tool to detect potential ransomware by analyzing binary files
for common ransomware indicators including imports, entropy, suspicious strings,
malformed certificates, and matching against YARA rules.
"""

import os
import re
import math
import argparse
import pefile
import yara
import hashlib
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID

# Set of suspicious imports commonly found in ransomware
SUSPICIOUS_IMPORTS = {
    'CryptEncrypt', 'CryptDecrypt', 'CryptGenRandom', 'CryptAcquireContext',
    'CreateService', 'ShellExecute', 'VirtualAlloc', 'WriteProcessMemory',
    'SetWindowsHookEx', 'GetAsyncKeyState', 'GetForegroundWindow',
    'AdjustTokenPrivileges', 'BCryptEncrypt', 'BCryptDecrypt'
}

# Suspicious strings often found in ransomware
SUSPICIOUS_STRINGS = [
    r'\.locked', r'\.encrypted', r'\.crypt', r'\.pay', r'\.ransom',
    r'bitcoin', r'btc', r'monero', r'xmr', r'decrypt', r'decrypt_file',
    r'readme\.txt', r'how_to_decrypt', r'how_to_recover',
    r'your files have been encrypted', r'payment',
    r'AES-?[0-9]{3}', r'RSA-?[0-9]{4}', r'decrypt_instruction',
    r'onion\.to', r'\.onion', r'tor2web', r'contact us',
    r'timer', r'deadline', r'secret key', r'private key',
    r'HOW_TO_RECOVER_FILES', r'README',
    r'ransom', r'restore files',
]

def calculate_entropy(data):
    """
    Calculate the Shannon entropy of a byte array.
    High entropy (>7) often indicates encryption or compression.
    """
    if not data:
        return 0
    
    entropy = 0
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    
    return entropy

def check_for_suspicious_imports(pe):
    """
    Check for suspicious imports commonly used by ransomware.
    """
    suspicious_found = []
    
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    imp_name = imp.name.decode('utf-8', errors='ignore')
                    if any(susp_import in imp_name for susp_import in SUSPICIOUS_IMPORTS):
                        suspicious_found.append(imp_name)
    except AttributeError:
        pass  # No imports found
    
    return suspicious_found

def check_for_suspicious_strings(file_data):
    """
    Check for suspicious strings commonly found in ransomware.
    """
    strings_found = []
    data_str = file_data.decode('latin-1')
    
    for pattern in SUSPICIOUS_STRINGS:
        matches = re.finditer(pattern, data_str, re.IGNORECASE)
        for match in matches:
            if match.group() not in strings_found:
                strings_found.append(match.group())
    
    return strings_found

def check_certificate(pe):
    """
    Check if the file has a valid digital signature.
    Returns a tuple (has_cert, is_valid, issues)
    """
    issues = []
    has_cert = False
    is_valid = False
    
    try:
        # Check if there's a security directory
        if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY') and pe.DIRECTORY_ENTRY_SECURITY.VirtualAddress != 0:
            has_cert = True
            
            # Extract certificate data
            security_dir = pe.DIRECTORY_ENTRY_SECURITY
            cert_data = pe.get_data(security_dir.VirtualAddress, security_dir.Size)
            
            try:
                # Try to parse the certificate using cryptography
                cert = x509.load_der_x509_certificate(cert_data[8:], default_backend())
                
                # Check if certificate is expired
                import datetime
                now = datetime.datetime.now()
                if cert.not_valid_before > now or cert.not_valid_after < now:
                    issues.append("Certificate has expired or is not yet valid")
                
                # Check for basic constraints
                try:
                    basic_constraints = cert.extensions.get_extension_for_oid(
                        ExtensionOID.BASIC_CONSTRAINTS
                    )
                    if basic_constraints.value.ca:
                        issues.append("Certificate is a CA certificate, which is unusual for code signing")
                except x509.ExtensionNotFound:
                    issues.append("No basic constraints extension found")
                
                # If no issues, consider it valid
                if not issues:
                    is_valid = True
                    
            except Exception as e:
                issues.append(f"Invalid certificate structure: {str(e)}")
        else:
            issues.append("No digital signature found")
    
    except Exception as e:
        issues.append(f"Error checking certificate: {str(e)}")
    
    return (has_cert, is_valid, issues)

def check_for_hardcoded_network(file_data):
    """
    Check for hardcoded IP addresses or .onion (TOR) URLs.
    """
    data_str = file_data.decode('latin-1')
    
    # Look for IPv4 addresses
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ips = re.findall(ip_pattern, data_str)
    
    # Look for .onion addresses and URLs
    onion_pattern = r'\b[a-zA-Z2-7]{16,56}\.onion\b'
    onions = re.findall(onion_pattern, data_str)
    
    # Look for http/https URLs
    url_pattern = r'https?://[^\s<>"\']{5,500}'
    urls = re.findall(url_pattern, data_str)
    
    return {
        'ips': ips,
        'onion_addresses': onions,
        'urls': urls
    }

def check_for_packing(pe):
    """
    Check if the file might be packed or obfuscated.
    """
    indicators = []
    
    # Few sections might indicate packing
    if len(pe.sections) <= 3:
        indicators.append(f"Few sections: {len(pe.sections)}")
    
    # Check for high entropy in sections
    high_entropy_sections = []
    for section in pe.sections:
        section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
        section_data = section.get_data()
        if section_data:
            entropy = calculate_entropy(section_data)
            if entropy > 7.0:
                high_entropy_sections.append(f"{section_name} ({entropy:.2f})")
    
    if high_entropy_sections:
        indicators.append(f"High entropy sections: {', '.join(high_entropy_sections)}")
    
    # Check for unusual section names
    standard_sections = {'.text', '.data', '.rdata', '.rsrc', '.reloc', '.idata', '.pdata', '.bss'}
    unusual_sections = []
    
    for section in pe.sections:
        section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
        if section_name and section_name not in standard_sections:
            unusual_sections.append(section_name)
    
    if unusual_sections:
        indicators.append(f"Unusual section names: {', '.join(unusual_sections)}")
    
    # Check for suspicious section permissions
    for section in pe.sections:
        section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
        if section.Characteristics & 0xE0000000:  # Check if section is executable and writable
            indicators.append(f"Section {section_name} is both executable and writable")
    
    return indicators

def get_file_hash(file_path):
    """Calculate SHA256 hash of the file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def analyze_file(file_path):
    """
    Main analysis function for a potential ransomware file.
    """
    results = {
        'file_path': file_path,
        'file_size': os.path.getsize(file_path),
        'sha256': get_file_hash(file_path),
        'suspicious_score': 0,
        'is_pe': False,
        'entropy': 0,
        'suspicious_imports': [],
        'suspicious_strings': [],
        'yara_matches': [],
        'certificate_info': {},
        'network_indicators': {},
        'packing_indicators': [],
        'overall_verdict': 'Unknown'
    }
    
    # Read the file data
    with open(file_path, 'rb') as f:
        file_data = f.read()
    
    # Calculate overall entropy
    results['entropy'] = calculate_entropy(file_data)
    if results['entropy'] > 7.0:
        results['suspicious_score'] += 20
    
    # Check for suspicious strings
    results['suspicious_strings'] = check_for_suspicious_strings(file_data)
    results['suspicious_score'] += len(results['suspicious_strings']) * 5
    
    # Check for network indicators
    results['network_indicators'] = check_for_hardcoded_network(file_data)
    if results['network_indicators']['onion_addresses']:
        results['suspicious_score'] += 20
    results['suspicious_score'] += len(results['network_indicators']['ips']) * 2
    
    # Check if it's a PE file
    try:
        pe = pefile.PE(file_path)
        results['is_pe'] = True
        
        # Check for suspicious imports
        results['suspicious_imports'] = check_for_suspicious_imports(pe)
        results['suspicious_score'] += len(results['suspicious_imports']) * 5
        
        # Check certificate
        has_cert, is_valid, cert_issues = check_certificate(pe)
        results['certificate_info'] = {
            'has_certificate': has_cert,
            'is_valid': is_valid,
            'issues': cert_issues
        }
        
        if not has_cert or not is_valid:
            results['suspicious_score'] += 15
        
        # Check for packing/obfuscation
        results['packing_indicators'] = check_for_packing(pe)
        results['suspicious_score'] += len(results['packing_indicators']) * 10
        
    except Exception as e:
        results['is_pe'] = False
        results['pe_error'] = str(e)
    
    # Run YARA rules from separate file
    try:
        # Get the directory of the current script
        script_dir = os.path.dirname(os.path.abspath(__file__))
        # Path to rules directory
        rules_dir = os.path.join(script_dir, 'rules')
        # Path to YARA rules file
        rules_path = os.path.join(rules_dir, 'ransomware_rules.yar')
        
        # Check if rules file exists
        if not os.path.exists(rules_path):
            results['yara_error'] = f"YARA rules file not found at {rules_path}"
        else:
            # Compile and run rules
            rules = yara.compile(filepath=rules_path)
            matches = rules.match(data=file_data)
            
            for match in matches:
                results['yara_matches'].append(match.rule)
            
            results['suspicious_score'] += len(results['yara_matches']) * 25
    except Exception as e:
        results['yara_error'] = str(e)
    
    # Determine overall verdict
    if results['suspicious_score'] >= 80:
        results['overall_verdict'] = 'Highly Suspicious - Likely Ransomware'
    elif results['suspicious_score'] >= 50:
        results['overall_verdict'] = 'Moderately Suspicious - Possible Ransomware'
    elif results['suspicious_score'] >= 30:
        results['overall_verdict'] = 'Slightly Suspicious - Requires Further Analysis'
    else:
        results['overall_verdict'] = 'Low Risk - Probably Not Ransomware'
    
    return results

def print_results(results):
    """
    Print the analysis results in a readable format.
    """
    print("\n" + "=" * 60)
    print(f"RANSOMWARE DETECTOR RESULTS FOR: {results['file_path']}")
    print("=" * 60)
    
    print(f"File Size: {results['file_size']} bytes")
    print(f"SHA256: {results['sha256']}")
    print(f"Overall Entropy: {results['entropy']:.2f}/8.00")
    print(f"Suspicious Score: {results['suspicious_score']}/100")
    print(f"VERDICT: {results['overall_verdict']}")
    print("-" * 60)
    
    if results['is_pe']:
        print("FILE TYPE: Windows PE Executable")
        
        if results['suspicious_imports']:
            print("\nSuspicious Imports:")
            for imp in results['suspicious_imports']:
                print(f"  - {imp}")
        else:
            print("\nNo suspicious imports found.")
            
        print("\nDigital Certificate:")
        if results['certificate_info']['has_certificate']:
            print(f"  - Has Certificate: Yes")
            print(f"  - Valid: {'Yes' if results['certificate_info']['is_valid'] else 'No'}")
            if results['certificate_info']['issues']:
                print("  - Issues:")
                for issue in results['certificate_info']['issues']:
                    print(f"    * {issue}")
        else:
            print("  - No digital certificate found")
        
        if results['packing_indicators']:
            print("\nPacking/Obfuscation Indicators:")
            for indicator in results['packing_indicators']:
                print(f"  - {indicator}")
        else:
            print("\nNo packing indicators found.")
    else:
        print("FILE TYPE: Not a Windows PE Executable")
        if 'pe_error' in results:
            print(f"Error: {results['pe_error']}")
    
    if results['suspicious_strings']:
        print("\nSuspicious Strings:")
        for string in results['suspicious_strings']:
            print(f"  - {string}")
    else:
        print("\nNo suspicious strings found.")
    
    print("\nNetwork Indicators:")
    if results['network_indicators']['ips']:
        print("  - IP Addresses:")
        for ip in results['network_indicators']['ips'][:10]:  # Limit to 10
            print(f"    * {ip}")
        if len(results['network_indicators']['ips']) > 10:
            print(f"    * And {len(results['network_indicators']['ips']) - 10} more...")
    else:
        print("  - No IP addresses found")
        
    if results['network_indicators']['onion_addresses']:
        print("  - Tor Onion Addresses:")
        for onion in results['network_indicators']['onion_addresses']:
            print(f"    * {onion}")
    else:
        print("  - No Tor onion addresses found")
    
    if results['yara_matches']:
        print("\nYARA Rule Matches:")
        for rule in results['yara_matches']:
            print(f"  - {rule}")
    else:
        print("\nNo YARA rule matches.")
    
    if 'yara_error' in results:
        print(f"\nYARA Error: {results['yara_error']}")
    
    print("\n" + "=" * 60)

def main():
    """
    Main function to run the ransomware detector.
    """
    parser = argparse.ArgumentParser(description='Ransomware Detector')
    parser.add_argument('file_path', help='Path to the file to analyze')
    parser.add_argument('--json', action='store_true', help='Output results in JSON format')
    args = parser.parse_args()
    
    # Ensure rules directory exists
    script_dir = os.path.dirname(os.path.abspath(__file__))
    rules_dir = os.path.join(script_dir, 'rules')
    
    # Create rules directory if it doesn't exist
    if not os.path.exists(rules_dir):
        try:
            os.makedirs(rules_dir)
            print(f"Created rules directory at {rules_dir}")
        except Exception as e:
            print(f"Error creating rules directory: {e}")
            return 1
    
    # Check for rules file
    rules_path = os.path.join(rules_dir, 'ransomware_rules.yar')
    if not os.path.exists(rules_path):
        print(f"Warning: YARA rules file not found at {rules_path}")
        print("Please create this file with your YARA rules before running analysis.")
    
    if not os.path.exists(args.file_path):
        print(f"Error: File '{args.file_path}' does not exist")
        return 1
    
    results = analyze_file(args.file_path)
    
    if args.json:
        import json
        print(json.dumps(results, indent=2))
    else:
        print_results(results)
    
    return 0

if __name__ == "__main__":
    main()
