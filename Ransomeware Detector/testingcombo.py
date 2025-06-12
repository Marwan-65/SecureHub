import sys
import os
import pefile
import hashlib
import math
import re
import argparse
from datetime import datetime
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QPushButton, QLabel, QFileDialog, 
                             QProgressBar, QTextEdit, QListWidget, QTabWidget,
                             QListWidgetItem, QMessageBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QIcon, QFont, QColor
import yara
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID

# Set of suspicious imports commonly found in ransomware
SUSPICIOUS_IMPORTS = {
    'CryptEncrypt', 'CryptDecrypt', 'CryptGenRandom', 'CryptAcquireContext',
    'CreateService', 'ShellExecute', 'VirtualAlloc', 'WriteProcessMemory',
    'SetWindowsHookEx', 'GetAsyncKeyState', 'GetForegroundWindow',
    'AdjustTokenPrivileges', 'BCryptEncrypt', 'BCryptDecrypt',
    'CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory',
    'ReadProcessMemory', 'WSASocket', 'connect', 'InternetOpenUrl',
    'HttpOpenRequest', 'InternetReadFile', 'RegOpenKey', 'RegSetValue',
    'RegCreateKey', 'StartServiceCtrlDispatcher', 'CreateProcess',
    'ShellExecute', 'WinExec', 'system', 'IsDebuggerPresent'
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

class ScanThread(QThread):
    """Thread for performing scans without freezing the UI"""
    update_progress = pyqtSignal(int)
    update_status = pyqtSignal(str)
    scan_complete = pyqtSignal(list)
    log_message = pyqtSignal(str)  # Added signal for logging
    
    def __init__(self, scan_type, path):
        super().__init__()
        self.scan_type = scan_type  # 'file' or 'directory'
        self.path = path
        self.is_running = True
        self.rules = None
        self.results = []
        self.files_to_scan = []
        self.files_scanned = 0
        
    
    def log(self, message):
        """Send a log message to the UI"""
        self.log_message.emit(message)
        
    def run(self):
        # Initialize YARA rules first
        rules_loaded = self.yara_setup()
        self.log(f"YARA rules initialization: {'Success' if rules_loaded else 'Failed'}")
        if self.scan_type == 'file':
            self.scan_file(self.path)
            self.scan_complete.emit(self.results)
        else:
            self.scan_directory()

    def yara_setup(self):
        """Setup YARA rules for scanning"""
        rules_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")
        self.update_status.emit(f"Loading YARA rules from {rules_dir}")
        
        if not os.path.exists(rules_dir):
            self.update_status.emit("Rules directory not found.")
            return False
        
        # Compile all rules into a single ruleset instead of a list
        try:
            filepaths = {}
            for filename in os.listdir(rules_dir):
                if filename.endswith('.yar') or filename.endswith('.yara'):
                    rule_path = os.path.join(rules_dir, filename)
                    filepaths[filename] = rule_path
                    self.update_status.emit(f"Found rule: {filename}")
            
            if not filepaths:
                self.update_status.emit("No valid YARA rules found")
                return False
                
            # Compile all rules at once instead of individually
            self.rules = yara.compile(filepaths=filepaths)
            self.update_status.emit(f"Successfully loaded {len(filepaths)} YARA rules")
            return True
            
        except Exception as e:
            self.update_status.emit(f"Error loading YARA rules: {str(e)}")
            return False

    def calculate_entropy(self, data):
        """
        Calculate the Shannon entropy of a byte array.
        High entropy (>7) often indicates encryption or compression.
        """
        if not data:
            return 0
        
        # Count byte occurrences
        byte_counts = {}
        for byte in data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1
            
        # Calculate entropy
        entropy = 0.0
        total_bytes = len(data)
        for count in byte_counts.values():
            probability = count / total_bytes
            entropy -= probability * math.log2(probability)
            
        return entropy  # Max entropy for byte data is 8.0

    def check_for_suspicious_imports(self, pe):
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

    def check_for_suspicious_strings(self, file_data):
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

    def check_signature(self, file_path):
        """Check if the file is digitally signed by a trusted publisher"""
        try:
            # Using PowerShell to check signature
            import subprocess
            result = subprocess.run(
                ['powershell', '-Command', f'Get-AuthenticodeSignature -FilePath "{file_path}" | Format-List'],
                capture_output=True, text=True
            )
            
            signature_info = result.stdout
            
            # Check if signature is valid
            if "Valid" in signature_info and not "NotSigned" in signature_info:
                # Extract publisher name
                publisher = None
                # Use a more flexible regex to match CN= pattern anywhere in the output
                cn_match = re.search(r'CN=([^,]+)', signature_info)
                if cn_match:
                    publisher = cn_match.group(1).strip()
                
                self.update_status.emit(f"File is signed by: {publisher}")
                return True, publisher
            return False, None
        except Exception as e:
            self.update_status.emit(f"Error checking signature: {str(e)}")
            return False, None

    def check_for_hardcoded_network(self, file_data):
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

    def check_for_packing(self, pe):
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
                entropy = self.calculate_entropy(section_data)
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
    
    def is_likely_installer(self, file_path, pe):
        """Check if a PE file has characteristics of a legitimate installer"""
        try:
            # 1. Check digital signature
            is_signed, publisher = self.check_signature(file_path)
            if is_signed and publisher:
                # List of known trusted publishers
                trusted_publishers = [
                    "Microsoft", "Adobe", "Oracle", "Google", "Apple", 
                    "Mozilla", "Intel", "NVIDIA", "Dell", "HP", "Lenovo"
                ]
                
                for trusted in trusted_publishers:
                    if trusted.lower() in publisher.lower():
                        return True
            
            # 2. Check filename patterns typical for installers
            filename = os.path.basename(file_path).lower()
            installer_patterns = [
                "setup", "install", "wizard", "bootstrap", "deploy", 
                "update", "patch", "-kb", "dotnet", "redist",
                "vcredist", "framework", "runtime"
            ]
            
            if any(pattern in filename for pattern in installer_patterns):
                # Additional verification to prevent false negatives
                
                # 3. Check for resources typical in installers
                try:
                    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                        # Check for Dialog resources (common in installers)
                        for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                            if hasattr(entry, 'id') and entry.id == 5:  # RT_DIALOG
                                return True
                except:
                    pass

                # 4. Check for common installer imports
                installer_imports = [
                    "msi.dll", "setupapi.dll", "cabinet.dll", "wextract.dll"
                ]
                
                try:
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        dll_name = entry.dll.decode('utf-8', errors='ignore').lower()
                        if any(imp in dll_name for imp in installer_imports):
                            return True
                except:
                    pass
                    
                # If the filename matches but no other installer traits were found,
                # give it a 50% chance of being an installer
                return True
                    
            return False
            
        except Exception as e:
            self.update_status.emit(f"Error checking installer: {str(e)}")
            return False
        
    def check_signature(self, file_path):
        """Check if the file is digitally signed by a trusted publisher"""
        try:
            # Using PowerShell to check signature
            import subprocess
            result = subprocess.run(
                ['powershell', '-Command', f'Get-AuthenticodeSignature -FilePath "{file_path}" | Format-List'],
                capture_output=True, text=True
            )
            
            signature_info = result.stdout
            
            # Check if signature is valid
            if "Valid" in signature_info and not "NotSigned" in signature_info:
                # Extract publisher name
                publisher = None
                # Use a more flexible regex to match CN= pattern anywhere in the output
                cn_match = re.search(r'CN=([^,]+)', signature_info)
                if cn_match:
                    publisher = cn_match.group(1).strip()
    
                
                self.update_status.emit(f"File is signed by: {publisher}")
                return True, publisher
            return False, None
        except Exception as e:
            self.update_status.emit(f"Error checking signature: {str(e)}")
            return False, None

    def get_file_hash(self, file_path):
        """Calculate SHA256 hash of the file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
#################################################################################################
##############################             Main function        #################################
#################################################################################################
    def scan_file(self, file_path):
        """Complete file scanning with all checks and enhanced scoring"""
        if not self.is_running:
            return None

        try:
            # Initialize result dictionary
            result = {
                'file': file_path,
                'score': 0,
                'threat_level': 'CLEAN',
                'components': {
                    'entropy': 0,
                    'strings': 0,
                    'imports': 0,
                    'network': 0,
                    'packing': 0,
                    'signature': 0,
                    'yara': 0,
                    'contextual': 0
                },
                'indicators': {
                    'entropy': 0,
                    'suspicious_strings': [],
                    'suspicious_imports': [],
                    'network_indicators': {},
                    'packing_indicators': [],
                    'signature_info': {},
                    'yara_matches': [],
                    'file_type': None
                },
                'details': {}
            }
            
            pe = pefile.PE(file_path)
            # File is a valid PE file, continue with scanning
            self.update_status.emit(f"Valid PE file found: {os.path.basename(file_path)}")
            if self.is_likely_installer(file_path, pe):
                self.results.append((file_path, "File appears to be a legitimate installer", "info"))
                self.update_status.emit(f"File {os.path.basename(file_path)} appears to be a legitimate installer")
                return False
            
            is_signed, publisher = self.check_signature(file_path)
            if is_signed:
                self.results.append((file_path, f"File is signed by: {publisher}", "info"))
                # If file has valid signature, skip other checks
                self.update_status.emit(f"File {os.path.basename(file_path)} has valid signature from {publisher}")
                return False

            # Skip non-executable files unless they're scripts/documents
            file_type = self.determine_file_type(file_path)
            result['indicators']['file_type'] = file_type

            if file_type == 'other':
                return None

            # Read file data
            with open(file_path, 'rb') as f:
                file_data = f.read()

            # 1. Entropy Analysis
            entropy_result = self.analyze_file_entropy(file_data)
            result['indicators']['entropy'] = entropy_result['overall_entropy']

            # Score entropy
            for threshold, points in SCORING_RULES['entropy']['thresholds']:
                if entropy_result['overall_entropy'] >= threshold:
                    result['components']['entropy'] = max(points, result['components']['entropy'])

            # 2. PE File Analysis (for executables)
            pe = None
            if file_type == 'executable':
                try:
                    pe = pefile.PE(data=file_data)

                    # Check for installer characteristics
                    if self.is_likely_installer(file_path, pe):
                        result['details']['installer'] = True
                        result['components']['contextual'] -= 20  # Reduce suspicion for installers

                    # Check imports
                    suspicious_imports = self.check_for_suspicious_imports(pe)
                    result['indicators']['suspicious_imports'] = suspicious_imports

                    # Score imports
                    for imp in suspicious_imports:
                        if imp in SCORING_RULES['imports']['critical']:
                            result['components']['imports'] += SCORING_RULES['imports']['critical'][imp]
                        elif imp in SCORING_RULES['imports']['suspicious']:
                            result['components']['imports'] += SCORING_RULES['imports']['suspicious'][imp]

                    # Check packing indicators
                    packing_indicators = self.check_for_packing(pe)
                    result['indicators']['packing_indicators'] = packing_indicators

                    # Score packing
                    if packing_indicators:
                        result['components']['packing'] += min(
                            len(packing_indicators) * SCORING_RULES['packing']['section_entropy']['per_section'],
                            SCORING_RULES['packing']['section_entropy']['max']
                        )

                except Exception as e:
                    self.log(f"PE analysis error for {os.path.basename(file_path)}: {str(e)}")
                    result['details']['pe_error'] = str(e)

            # 3. Suspicious Strings
            suspicious_strings = self.check_for_suspicious_strings(file_data)
            result['indicators']['suspicious_strings'] = suspicious_strings

            # Score strings
            for string in suspicious_strings:
                matched = False
                for pattern, points in SCORING_RULES['suspicious_strings']['high_confidence_matches'].items():
                    if re.search(pattern, string, re.IGNORECASE):
                        result['components']['strings'] += points
                        matched = True
                        break
                if not matched:
                    result['components']['strings'] += SCORING_RULES['suspicious_strings']['per_match']

            # 4. Network Indicators
            network_indicators = self.check_for_hardcoded_network(file_data)
            result['indicators']['network_indicators'] = network_indicators

            # Score network
            if network_indicators['onion_addresses']:
                result['components']['network'] += SCORING_RULES['network']['tor']

            ip_count = len(network_indicators['ips'])
            for threshold, points in SCORING_RULES['network']['ip_addresses']['thresholds']:
                if ip_count >= threshold:
                    result['components']['network'] = max(points, result['components']['network'])

            # 5. Digital Signature Check
            is_signed, publisher = self.check_signature(file_path)
            result['indicators']['signature_info'] = {
                'signed': is_signed,
                'publisher': publisher
            }

            # Score signature
            if not is_signed:
                result['components']['signature'] += SCORING_RULES['signature']['unsigned']
            elif publisher and "unknown" in publisher.lower():
                result['components']['signature'] += SCORING_RULES['signature']['signed_but_suspicious']

            # 6. YARA Rules
            if hasattr(self, 'rules') and self.rules is not None:
                try:
                    yara_matches = self.rules.match(data=file_data)
                    result['indicators']['yara_matches'] = [str(m) for m in yara_matches]

                    # Score YARA matches
                    for match in yara_matches:
                        if 'critical' in match.tags:
                            result['components']['yara'] += SCORING_RULES['yara']['critical_rules']
                        elif 'suspicious' in match.tags:
                            result['components']['yara'] += SCORING_RULES['yara']['suspicious_rules']
                        else:
                            result['components']['yara'] += SCORING_RULES['yara']['informational_rules']
                except Exception as e:
                    self.log(f"YARA scan error for {os.path.basename(file_path)}: {str(e)}")
                    result['details']['yara_error'] = str(e)

            # Apply maximums to all categories
            for category in result['components']:
                if category in SCORING_RULES and 'max' in SCORING_RULES[category]:
                    result['components'][category] = min(
                        result['components'][category],
                        SCORING_RULES[category]['max']
                    )

            # Calculate contextual adjustments
            contextual_info = {
                'high_entropy': entropy_result['overall_entropy'] > 7.0,
                'crypto_imports': any('crypt' in imp.lower() for imp in result['indicators']['suspicious_imports']),
                'network_indicators': bool(network_indicators['onion_addresses'] or len(network_indicators['ips']) > 5),
                'is_installer': result['details'].get('installer', False)
            }

            result['components']['contextual'] = self.calculate_contextual_adjustments(
                contextual_info,
                sum(result['components'].values())
            )

            # Calculate final score
            result['score'] = sum(result['components'].values())

            # Determine threat level
            result['threat_level'] = self.determine_threat_level(
                result['score'],
                file_type
            )

            # Add file hash
            result['file_hash'] = self.get_file_hash(file_path)
            #print(result)
            import copy
            result_copy = copy.deepcopy(result)
            self.results.append(result_copy)
            return result

        except Exception as e:
            error_msg = f"Error scanning file {os.path.basename(file_path)}: {str(e)}"
            self.update_status.emit(error_msg)
            return {
                'file': file_path,
                'error': error_msg,
                'threat_level': 'ERROR'
            }

    def is_likely_installer(self, file_path, pe):
        """Check if a PE file has characteristics of a legitimate installer"""
        try:
            # 1. Check digital signature
            is_signed, publisher = self.check_signature(file_path)
            if is_signed and publisher:
                # List of known trusted publishers
                trusted_publishers = [
                    "Microsoft", "Adobe", "Oracle", "Google", "Apple", 
                    "Mozilla", "Intel", "NVIDIA", "Dell", "HP", "Lenovo"
                ]
                
                for trusted in trusted_publishers:
                    if trusted.lower() in publisher.lower():
                        return True
            
            # 2. Check filename patterns typical for installers
            filename = os.path.basename(file_path).lower()
            installer_patterns = [
                "setup", "install", "wizard", "bootstrap", "deploy", 
                "update", "patch", "-kb", "dotnet", "redist",
                "vcredist", "framework", "runtime"
            ]
            
            if any(pattern in filename for pattern in installer_patterns):
                # Additional verification to prevent false negatives
                
                # 3. Check for resources typical in installers
                try:
                    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                        # Check for Dialog resources (common in installers)
                        for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                            if hasattr(entry, 'id') and entry.id == 5:  # RT_DIALOG
                                return True
                except:
                    pass

                # 4. Check for common installer imports
                installer_imports = [
                    "msi.dll", "setupapi.dll", "cabinet.dll", "wextract.dll"
                ]
                
                try:
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        dll_name = entry.dll.decode('utf-8', errors='ignore').lower()
                        if any(imp in dll_name for imp in installer_imports):
                            return True
                except:
                    pass
                    
                # If the filename matches but no other installer traits were found,
                # give it a 50% chance of being an installer
                return True
                    
            return False
            
        except Exception as e:
            self.update_status.emit(f"Error checking installer: {str(e)}")
            return False

    def determine_file_type(self, file_path):
        """Determine file type for scoring adjustments"""
        lower_path = file_path.lower()

        if any(lower_path.endswith(ext) for ext in ['.exe', '.dll', '.sys', '.drv']):
            return 'executable'
        elif any(lower_path.endswith(ext) for ext in ['.ps1', '.vbs', '.js', '.bat', '.cmd']):
            return 'script'
        elif any(lower_path.endswith(ext) for ext in ['.doc', '.docx', '.xls', '.xlsx', '.pdf']):
            return 'document'
        else:
            return 'other'

    def calculate_contextual_adjustments(self, context_info, base_score):
        """Apply multipliers based on file context"""
        adjustments = 0

        # Critical combination: Encryption APIs + High Entropy
        if context_info['high_entropy'] and context_info['crypto_imports']:
            adjustments += 15
            if len(context_info.get('suspicious_strings', [])) > 3:
                adjustments += 10

        # Network + Encryption is very suspicious
        if context_info['network_indicators'] and context_info['crypto_imports']:
            adjustments += 20

        # Reduce suspicion for known installers
        if context_info['is_installer']:
            adjustments = max(-20, adjustments - 20)

        return min(adjustments, 30)  # Cap adjustments

    def determine_threat_level(self, score, file_type):
        """Classify threat based on score and file type"""
        thresholds = {
            'executable': 60,
            'script': 70,
            'document': 80,
            'other': 100  # Shouldn't reach here as we filter these out
        }

        base_threshold = thresholds.get(file_type, 60)

        if score >= base_threshold * 1.3:
            return "CRITICAL"
        elif score >= base_threshold:
            return "HIGH"
        elif score >= base_threshold * 0.7:
            return "MEDIUM"
        elif score >= base_threshold * 0.4:
            return "LOW"
        else:
            return "CLEAN"

    def analyze_file_entropy(self, file_data):
        """
        Analyze data entropy to detect potential obfuscation or encryption
        Returns dictionary with entropy analysis results
        """
        try:
            # If data is very small, ignore entropy analysis
            if len(file_data) < 100:
                return {'overall_entropy': 0, 'entropy_suspicious': False}

            # Calculate overall entropy
            entropy = self.calculate_entropy(file_data)

            # Check for sections with high entropy
            high_entropy_sections = []

            # Break data into chunks and analyze entropy per chunk
            chunk_size = min(4096, len(file_data) // 10)  # Fixed missing parenthesis
            if chunk_size > 0:
                chunks = [file_data[i:i + chunk_size] for i in range(0, len(file_data), chunk_size)]

                chunk_entropies = []
                for i, chunk in enumerate(chunks):
                    chunk_entropy = self.calculate_entropy(chunk)
                    chunk_entropies.append(chunk_entropy)

                    # If chunk has very high entropy (>7.5), it's suspicious
                    if chunk_entropy > 7.5:
                        offset = i * chunk_size
                        high_entropy_sections.append((offset, offset + len(chunk), chunk_entropy))

                # Check if multiple consecutive sections have high entropy
                high_entropy_regions = len(high_entropy_sections)

                # Detect shifts in entropy that might indicate embedded encrypted/compressed data
                has_entropy_shift = False
                if len(chunk_entropies) > 2:
                    for i in range(1, len(chunk_entropies) - 1):
                        # Look for sharp increases in entropy (potential start of encrypted data)
                        if (chunk_entropies[i] > 7.0 and chunk_entropies[i - 1] < 6.0):
                            has_entropy_shift = True
                            break

                return {
                    'overall_entropy': entropy,
                    'high_entropy_regions': high_entropy_regions,
                    'has_entropy_shift': has_entropy_shift,
                    'entropy_suspicious': entropy > 7.7 or high_entropy_regions > 3 or has_entropy_shift
                }

            return {'overall_entropy': entropy, 'entropy_suspicious': entropy > 7.7}

        except Exception as e:
            self.update_status.emit(f"Error analyzing entropy: {str(e)}")
            return {'overall_entropy': 0, 'entropy_suspicious': False}

    def scan_directory(self):
        """Scan a directory by finding all files and scanning each one"""
        self.update_status.emit(f"Scanning directory: {self.path}")
        self.results = []  # Clear previous results

        try:
            # Process files in smaller batches to avoid memory issues
            batch_size = 5
            all_files = []

            for root, _, filenames in os.walk(self.path):
                if any(skip_dir in root for skip_dir in ['/node_modules/', '/__pycache__/', '/venv/', '/.git/']):
                    continue
                all_files.extend(os.path.join(root, f) for f in filenames)

            total_files = len(all_files)
            if total_files == 0:
                self.update_status.emit("No files found in directory")
                self.scan_complete.emit([])
                return

            self.update_status.emit(f"Found {total_files} files to scan")

            # Process in batches
            for i in range(0, total_files, batch_size):
                if not self.is_running:
                    return

                batch = all_files[i:i + batch_size]
                for file_path in batch:
                    try:
                        self.scan_file(file_path)
                    except Exception as e:
                        self.update_status.emit(f"Error scanning {file_path}: {str(e)}")

                    # Update progress
                    self.files_scanned += 1
                    progress = int((self.files_scanned / total_files) * 100)
                    self.update_progress.emit(progress)
                    self.update_status.emit(f"Scanning {self.files_scanned}/{total_files}")

            self.update_progress.emit(100)
            self.update_status.emit("Scan complete!")
            self.scan_complete.emit(self.results.copy())  # Send a copy of results

        except Exception as e:
            self.update_status.emit(f"Error scanning directory: {str(e)}")
            self.scan_complete.emit([])
        
    def stop(self):
        self.is_running = False

    def prioritize_files(self, file_list):
        """Sort files so the most suspicious file types are scanned first"""
        high_priority = []
        medium_priority = []
        low_priority = []
        
        for file_path in file_list:
            lower_path = file_path.lower()
            # High priority: Executables and scripts
            if any(lower_path.endswith(ext) for ext in ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js']):
                high_priority.append(file_path)
            # Medium priority: Other code files
            elif any(lower_path.endswith(ext) for ext in ['.py', '.php', '.asp', '.aspx', '.jsp']):
                medium_priority.append(file_path)
            # Low priority: Everything else
            else:
                low_priority.append(file_path)
        
        return high_priority + medium_priority + low_priority


class DropArea(QWidget):
    """Widget that accepts drag and drop operations"""
    file_dropped = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        layout = QVBoxLayout(self)
        
        # Create a label with instructions
        self.label = QLabel("Drag and drop files or folders here")
        self.label.setAlignment(Qt.AlignCenter)
        self.label.setStyleSheet("""
            font-size: 16px;
            color: #888888;
            padding: 20px;
            border: 2px dashed #555555;
            border-radius: 8px;
        """)
        layout.addWidget(self.label)
    
    def dragEnterEvent(self, event):
        """Handle drag enter events"""
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self.label.setStyleSheet("""
                font-size: 16px;
                color: #E0E0E0;
                padding: 20px;
                border: 2px dashed #0078D7;
                border-radius: 8px;
                background-color: rgba(0, 120, 215, 0.1);
            """)
    
    def dragLeaveEvent(self, event):
        """Handle drag leave events"""
        self.label.setStyleSheet("""
            font-size: 16px;
            color: #888888;
            padding: 20px;
            border: 2px dashed #555555;
            border-radius: 8px;
        """)
    
    def dropEvent(self, event):
        """Handle drop events"""
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            url = event.mimeData().urls()[0]
            file_path = url.toLocalFile()
            self.file_dropped.emit(file_path)
            self.label.setStyleSheet("""
                font-size: 16px;
                color: #888888;
                padding: 20px;
                border: 2px dashed #555555;
                border-radius: 8px;
            """)


class AntivirusUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.scan_thread = None
        self.initUI()
        
    def initUI(self):
        self.setWindowTitle('Ransomware Detector')
        self.setWindowIcon(QIcon('antivirus.png'))
        self.setGeometry(100, 100, 800, 600)
        self.setStyleSheet("""
            QMainWindow {
                background-color: #2D2D30;
            }
            QWidget {
                background-color: #2D2D30;
                color: #E0E0E0;
            }
            QPushButton {
                background-color: #0078D7;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #1C97EA;
            }
            QPushButton:pressed {
                background-color: #00569C;
            }
            QPushButton:disabled {
                background-color: #555555;
                color: #888888;
            }
            QLabel {
                color: #E0E0E0;
            }
            QProgressBar {
                border: 1px solid #555555;
                border-radius: 5px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #0078D7;
                width: 10px;
            }
            QTextEdit, QListWidget {
                background-color: #1E1E1E;
                color: #E0E0E0;
                border: 1px solid #555555;
                border-radius: 4px;
            }
            QTabWidget::pane {
                border: 1px solid #555555;
                background-color: #2D2D30;
            }
            QTabBar::tab {
                background-color: #252526;
                color: #E0E0E0;
                padding: 8px 16px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #007ACC;
            }
            QTabBar::tab:hover:!selected {
                background-color: #3E3E40;
            }
        """)
        
        # Central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Create title with icon
        title_layout = QHBoxLayout()
        title_label = QLabel("Ransomware Detector")
        title_label.setFont(QFont("Arial", 18, QFont.Bold))
        title_layout.addWidget(title_label)
        title_layout.addStretch()
        main_layout.addLayout(title_layout)
        
        # Create stacked section for drop area and file details
        self.main_section = QVBoxLayout()
        
        # Add drop area
        self.drop_area = DropArea()
        self.drop_area.file_dropped.connect(self.handle_dropped_file)
        self.main_section.addWidget(self.drop_area)
        
        # Create file details area (initially hidden)
        self.file_details = QWidget()
        self.file_details.setVisible(False)
        file_details_layout = QVBoxLayout(self.file_details)
        
        # File icon and type
        self.file_type_label = QLabel()
        self.file_type_label.setAlignment(Qt.AlignCenter)
        self.file_type_label.setFont(QFont("Arial", 16))
        file_details_layout.addWidget(self.file_type_label)
        
        # File/directory name
        self.file_name_label = QLabel()
        self.file_name_label.setAlignment(Qt.AlignCenter)
        self.file_name_label.setWordWrap(True)
        self.file_name_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        file_details_layout.addWidget(self.file_name_label)
        
        # File path
        self.file_path_label = QLabel()
        self.file_path_label.setAlignment(Qt.AlignCenter)
        self.file_path_label.setWordWrap(True)
        self.file_path_label.setStyleSheet("color: #AAAAAA; font-size: 12px;")
        file_details_layout.addWidget(self.file_path_label)
        
        # Clear selection button
        self.clear_btn = QPushButton("Clear Selection")
        self.clear_btn.clicked.connect(self.clear_selection)
        file_details_layout.addWidget(self.clear_btn, alignment=Qt.AlignCenter)
        
        # Add the file details widget to the main section
        self.main_section.addWidget(self.file_details)
        
        # Add the main section to the main layout
        main_layout.addLayout(self.main_section)
        
        # File/Directory selection section
        selection_layout = QHBoxLayout()
        
        # File scan button
        self.file_btn = QPushButton("Scan File")
        self.file_btn.clicked.connect(self.select_file)
        selection_layout.addWidget(self.file_btn)
        
        # Directory scan button
        self.dir_btn = QPushButton("Scan Directory")
        self.dir_btn.clicked.connect(self.select_directory)
        selection_layout.addWidget(self.dir_btn)
        
        # Selected path label
        self.path_label = QLabel("No file or directory selected")
        selection_layout.addWidget(self.path_label, 1)
        
        # Start scan button
        self.scan_btn = QPushButton("Start Scan")
        self.scan_btn.clicked.connect(self.start_scan)
        self.scan_btn.setEnabled(False)
        selection_layout.addWidget(self.scan_btn)
        
        # Cancel scan button
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.cancel_scan)
        self.cancel_btn.setEnabled(False)
        selection_layout.addWidget(self.cancel_btn)
        
        main_layout.addLayout(selection_layout)
        
        # Progress section
        progress_layout = QVBoxLayout()
        
        # Status label
        self.status_label = QLabel("Ready")
        progress_layout.addWidget(self.status_label)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        progress_layout.addWidget(self.progress_bar)
        
        main_layout.addLayout(progress_layout)
        
        # Tabs for results and logs
        self.tabs = QTabWidget()
        
        # Results tab
        self.results_tab = QWidget()
        results_layout = QVBoxLayout(self.results_tab)
        
        # Add color legend
        legend_layout = QHBoxLayout()
        legend_layout.addWidget(QLabel("Threat Level:"))
        
        high_label = QLabel("High")
        high_label.setStyleSheet("color: #FF4040; font-weight: bold;")
        legend_layout.addWidget(high_label)
        
        medium_label = QLabel("Medium")
        medium_label.setStyleSheet("color: #FFA500; font-weight: bold;")
        legend_layout.addWidget(medium_label)
        
        low_label = QLabel("Low")
        low_label.setStyleSheet("color: #FFFF00; font-weight: bold;")
        legend_layout.addWidget(low_label)
        
        error_label = QLabel("Error")
        error_label.setStyleSheet("color: #AAAAAA;")
        legend_layout.addWidget(error_label)
        
        legend_layout.addStretch()
        results_layout.addLayout(legend_layout)
        
        # Results list
        self.results_list = QListWidget()
        results_layout.addWidget(self.results_list)
        
        # Log tab
        self.log_tab = QWidget()
        log_layout = QVBoxLayout(self.log_tab)
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        log_layout.addWidget(self.log_text)
        
        # Add tabs
        self.tabs.addTab(self.results_tab, "Scan Results")
        self.tabs.addTab(self.log_tab, "Log")
        
        main_layout.addWidget(self.tabs)
        
        # Add initial log entry
        self.log("Ransomware Detector started - ready to scan")
        
    def select_file(self):
        """Open file dialog to select a file to scan"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select File to Scan",
            "",
            "All Files (*)"
        )
        
        if file_path:
            self.path_label.setText(file_path)
            self.scan_btn.setEnabled(True)
            self.log(f"Selected file: {file_path}")
            self.selected_type = 'file'
            self.selected_path = file_path
            self.update_file_details()
            
    def select_directory(self):
        """Open directory dialog to select a directory to scan"""
        dir_path = QFileDialog.getExistingDirectory(
            self,
            "Select Directory to Scan",
            ""
        )
        
        if dir_path:
            self.path_label.setText(dir_path)
            self.scan_btn.setEnabled(True)
            self.log(f"Selected directory: {dir_path}")
            self.selected_type = 'directory'
            self.selected_path = dir_path
            self.update_file_details()
    
    def start_scan(self):
        """Start scanning the selected file or directory"""
        if not hasattr(self, 'selected_path'):
            return
            
        # Reset UI for new scan
        self.results_list.clear()
        self.progress_bar.setValue(0)
        self.status_label.setText("Starting scan...")
        
        # Update UI state
        self.scan_btn.setEnabled(False)
        self.file_btn.setEnabled(False)
        self.dir_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        
        # Create and start scan thread
        self.scan_thread = ScanThread(self.selected_type, self.selected_path)
        self.scan_thread.update_progress.connect(self.update_progress)
        self.scan_thread.update_status.connect(self.update_status)
        self.scan_thread.scan_complete.connect(self.handle_scan_results)
        self.scan_thread.log_message.connect(self.log)  # Connect the new log signal
        self.scan_thread.start()
        
        self.log(f"Started {self.selected_type} scan on: {self.selected_path}")

    def handle_scan_results(self, results):
        """Handle the structured scan results"""
        try:
            # Reset UI
            self.reset_ui()
            self.results_list.clear()

            if not results:
                self.log("Scan complete - No threats found")
                self.status_label.setText("Scan complete - No threats found!")
                return

            threat_counts = {
                'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0,
                'LOW': 0, 'CLEAN': 0, 'ERROR': 0
            }

            for result in results:
                if not result:
                    continue

                try:
                    # Check if result is a tuple (legacy format) or dictionary (new format)
                    if isinstance(result, tuple):
                        # Handle tuple format (file_path, message, level)
                        file_path = result[0]
                        threat_message = result[1]
                        threat_level = result[2] if len(result) > 2 else "info"
                        
                        # Convert to upper case for consistency
                        if threat_level.upper() in threat_counts:
                            threat_counts[threat_level.upper()] += 1
                        
                        filename = os.path.basename(file_path)
                        item = QListWidgetItem(f"{filename}: {threat_message}")
                        
                        # Color coding
                        if threat_level == "high":
                            item.setForeground(QColor("#FF0000"))
                        elif threat_level == "medium":
                            item.setForeground(QColor("#FFA500"))
                        elif threat_level == "low":
                            item.setForeground(QColor("#FFFF00"))
                        elif threat_level == "error":
                            item.setForeground(QColor("#AAAAAA"))
                        
                        item.setData(Qt.UserRole, file_path)
                    else:
                        # Handle dictionary format
                        if 'error' in result:
                            threat_level = 'ERROR'
                            threat_message = f"Error: {result['error']}"
                        else:
                            threat_level = result.get('threat_level', 'CLEAN')
                            score = result.get('score', 0)
                            threat_message = f"{threat_level} (Score: {score})"

                            # Add indicators
                            indicators = []
                            if result.get('indicators', {}).get('yara_matches'):
                                indicators.append(f"YARA: {len(result['indicators']['yara_matches'])} matches")
                            if result.get('indicators', {}).get('packing_indicators'):
                                indicators.append(f"Packing: {len(result['indicators']['packing_indicators'])} indicators")
                            if not result.get('indicators', {}).get('signature_info', {}).get('signed', True):
                                indicators.append("Unsigned")

                            if indicators:
                                threat_message += " - " + ", ".join(indicators)

                        threat_counts[threat_level] += 1

                        # Create list item
                        filename = os.path.basename(result.get('file', 'unknown'))
                        item = QListWidgetItem(f"{filename}: {threat_message}")
                        item.setData(Qt.UserRole, result.copy())  # Store a copy

                        # Color coding
                        if threat_level == 'CRITICAL':
                            item.setForeground(QColor("#FF0000"))
                        elif threat_level == 'HIGH':
                            item.setForeground(QColor("#FF6B6B"))
                        elif threat_level == 'MEDIUM':
                            item.setForeground(QColor("#FFA500"))
                        elif threat_level == 'LOW':
                            item.setForeground(QColor("#FFFF00"))
                        elif threat_level == 'ERROR':
                            item.setForeground(QColor("#AAAAAA"))

                    self.results_list.addItem(item)

                except Exception as e:
                    self.log(f"Error processing result item: {str(e)}")
                    continue

            # Update summary
            summary = []
            for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                if threat_counts[level] > 0:
                    summary.append(f"{threat_counts[level]} {level.lower()}")

            if threat_counts['ERROR'] > 0:
                summary.append(f"{threat_counts['ERROR']} errors")

            if summary:
                msg = f"Found {'; '.join(summary)} threats"
            else:
                msg = "No threats found"

            self.status_label.setText(msg)
            self.log(f"Scan complete - {msg}")
            self.tabs.setCurrentIndex(0)

        except Exception as e:
            self.log(f"Error handling scan results: {str(e)}")
            self.status_label.setText("Error processing results")

    def cancel_scan(self):
        """Cancel the current scan"""
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.stop()
            self.scan_thread.wait()
            self.update_status("Scan cancelled")
            self.log("Scan cancelled by user")
            
        # Reset UI
        self.reset_ui()
            
    def update_progress(self, value):
        """Update progress bar"""
        self.progress_bar.setValue(value)
        
    def update_status(self, message):
        """Update status label and log"""
        self.status_label.setText(message)
        self.log(message)
        
    def scan_complete(self, threats):
        """Handle scan completion"""
        # Reset UI
        self.reset_ui()
        
        # Display threats if found
        if threats:
            # Count different threat levels
            high_threats = 0
            medium_threats = 0
            low_threats = 0
            errors = 0
            
            for threat in threats:
                file_path = threat[0]
                threat_message = threat[1]
                
                # Check if there's a threat level indicator (for backward compatibility)
                threat_level = threat[2] if len(threat) > 2 else "info"
                
                item = QListWidgetItem(f"{os.path.basename(file_path)}: {threat_message}")
                item.setData(Qt.UserRole, file_path)
                
                # Color code based on threat level
                if "VERDICT" in threat_message:
                    if threat_level == "high":
                        item.setForeground(QColor("#FF4040"))  # Bright red
                        high_threats += 1
                    elif threat_level == "medium":
                        item.setForeground(QColor("#FFA500"))  # Orange
                        medium_threats += 1
                    elif threat_level == "low":
                        item.setForeground(QColor("#FFFF00"))  # Yellow
                        low_threats += 1
                elif threat_level == "error":
                    item.setForeground(QColor("#AAAAAA"))  # Gray for errors
                    errors += 1
                else:
                    item.setForeground(QColor("#FFFFFF"))  # White for informational items
                
                self.results_list.addItem(item)
            
            # Create a summary message
            total_threats = high_threats + medium_threats + low_threats
            summary = []
            if high_threats > 0:
                summary.append(f"{high_threats} high severity")
            if medium_threats > 0:
                summary.append(f"{medium_threats} medium severity")
            if low_threats > 0:
                summary.append(f"{low_threats} low severity")
            if errors > 0:
                summary.append(f"{errors} errors")
            
            summary_msg = f"Scan complete - {total_threats} threats found " + \
                         f"({', '.join(summary)})"
            
            self.log(summary_msg)
            self.status_label.setText(summary_msg)
            
            # Switch to results tab
            self.tabs.setCurrentIndex(0)
        else:
            self.log("Scan complete - No threats found")
            self.status_label.setText("Scan complete - No threats found!")
            
    def reset_ui(self):
        """Reset UI state after scan completes or is cancelled"""
        self.scan_btn.setEnabled(True)
        self.file_btn.setEnabled(True)
        self.dir_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        
    def update_file_details(self):
        """Update the file details area with selected file/directory information"""
        if not hasattr(self, 'selected_path'):
            return
            
        # Update file type
        if self.selected_type == 'file':
            self.file_type_label.setText("📄 File Selected")
            # Get file size
            file_size = os.path.getsize(self.selected_path)
            size_str = self.format_size(file_size)
            self.file_type_label.setText(f"📄 File Selected ({size_str})")
        else:
            self.file_type_label.setText("📁 Directory Selected")
            
        # Update file name
        file_name = os.path.basename(self.selected_path)
        self.file_name_label.setText(file_name)
        
        # Update file path
        dir_path = os.path.dirname(self.selected_path)
        self.file_path_label.setText(dir_path)
        
        # Show file details and hide drop area
        self.drop_area.setVisible(False)
        self.file_details.setVisible(True)
        
    def format_size(self, size_bytes):
        """Format bytes into a human-readable format"""
        if size_bytes < 1024:
            return f"{size_bytes} bytes"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes/1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes/(1024*1024):.1f} MB"
        else:
            return f"{size_bytes/(1024*1024*1024):.1f} GB"
    
    def clear_selection(self):
        """Clear the selected file/directory"""
        if hasattr(self, 'selected_path'):
            delattr(self, 'selected_path')
            delattr(self, 'selected_type')
            
        # Reset UI
        self.path_label.setText("No file or directory selected")
        self.scan_btn.setEnabled(False)
        self.log("Selection cleared")
        
        # Show drop area and hide file details
        self.file_details.setVisible(False)
        self.drop_area.setVisible(True)
            
    def log(self, message):
        """Add a message to the log"""
        import datetime
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_text.append(f"[{timestamp}] {message}")
        
    def handle_dropped_file(self, path):
        """Handle a file or directory dropped onto the drop area"""
        if os.path.isfile(path):
            self.path_label.setText(path)
            self.scan_btn.setEnabled(True)
            self.log(f"File dropped: {path}")
            self.selected_type = 'file'
            self.selected_path = path
            self.update_file_details()
        elif os.path.isdir(path):
            self.path_label.setText(path)
            self.scan_btn.setEnabled(True)
            self.log(f"Directory dropped: {path}")
            self.selected_type = 'directory'
            self.selected_path = path
            self.update_file_details()
        else:
            self.log(f"Invalid path dropped: {path}")
            QMessageBox.warning(self, "Invalid Path", 
                                "The dropped item is neither a valid file nor directory.")


FILE_TYPE_PROFILES = {
    'executable': {
        'base_threshold': 60,
        'entropy_weight': 1.2,
        'imports_weight': 1.3
    },
    'script': {
        'base_threshold': 70,
        'string_weight': 1.4,
        'entropy_weight': 0.8
    },
    'document': {
        'base_threshold': 80,
        'macro_weight': 2.0,
        'entropy_weight': 1.1
    }
}
SCORING_RULES = {
    'entropy': {
        'thresholds': [(6.5, 10), (7.0, 20), (7.5, 30)],
        'max': 30
    },
    'suspicious_strings': {
        'per_match': 3,
        'max': 30,
        'high_confidence_matches': {  # These get double points
            r'\.locked$': 6,
            r'your files have been encrypted': 6,
            r'payment.*bitcoin': 6
        }
    },
    'imports': {
        'critical': {  # Very dangerous APIs
            'CryptEncrypt': 10,
            'CreateRemoteThread': 8,
            'VirtualAllocEx': 7
        },
        'suspicious': {  # Potentially dangerous
            'ShellExecute': 3,
            'WinExec': 3,
            'GetAsyncKeyState': 2
        },
        'max': 40
    },
    'network': {
        'tor': 15,
        'ip_addresses': {
            'per_ip': 1,
            'thresholds': [(5, 5), (10, 10)]
        },
        'urls': {
            'malicious_domains': 8,
            'generic': 2
        },
        'max': 30
    },
    'packing': {
        'section_entropy': {
            'per_section': 5,
            'max': 20
        },
        'unusual_sections': {
            'per_section': 3,
            'max': 15
        },
        'max': 30
    },
    'signature': {
        'unsigned': 10,
        'invalid': 15,
        'signed_but_suspicious': 5,
        'max': 15
    },
    'yara': {
        'critical_rules': 25,
        'suspicious_rules': 15,
        'informational_rules': 5,
        'max': 50
    }
}
if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = AntivirusUI()
    window.show()
    sys.exit(app.exec_())