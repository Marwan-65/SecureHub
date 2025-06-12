import sys
import os
import pefile
import hashlib
import math  # Add import for entropy calculation
from datetime import datetime
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QPushButton, QLabel, QFileDialog, 
                             QProgressBar, QTextEdit, QListWidget, QTabWidget,
                             QListWidgetItem, QMessageBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QIcon, QFont, QColor
import yara 

class ScanThread(QThread):
    """Thread for performing scans without freezing the UI"""
    update_progress = pyqtSignal(int)
    update_status = pyqtSignal(str)
    scan_complete = pyqtSignal(list)
    
    def __init__(self, scan_type, path):
        super().__init__()
        self.scan_type = scan_type  # 'file' or 'directory'
        self.path = path
        self.is_running = True
        self.results = []
        self.files_to_scan = []
        self.files_scanned = 0
        
    def run(self):
        # Initialize YARA rules first
        self.yara_setup()
        
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
            
    def analyze_file_entropy(self, file_path):
        """
        Analyze file entropy to detect potential obfuscation or encryption
        Returns (average_entropy, is_suspicious)
        """
        try:
            # Don't analyze very large files (>10MB) for performance
            if os.path.getsize(file_path) > 10 * 1024 * 1024:
                return None, False
                
            # Read file in binary mode
            with open(file_path, 'rb') as f:
                content = f.read()
                
            # If file is very small, ignore entropy analysis
            if len(content) < 100:
                return None, False
                
            # Calculate overall file entropy
            entropy = self.calculate_entropy(content)
            
            # Check for sections with high entropy
            high_entropy_sections = []
            
            # Break file into chunks and analyze entropy per chunk
            chunk_size = min(4096, len(content) // 10)  # Analyze in chunks
            if chunk_size > 0:
                chunks = [content[i:i+chunk_size] for i in range(0, len(content), chunk_size)]
                
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
                    for i in range(1, len(chunk_entropies)-1):
                        # Look for sharp increases in entropy (potential start of encrypted data)
                        if (chunk_entropies[i] > 7.0 and chunk_entropies[i-1] < 6.0):
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
            self.update_status.emit(f"Error analyzing entropy for {os.path.basename(file_path)}: {str(e)}")
            return None, False
            
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of binary data"""
        if not data:
            return 0.0
            
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

    def scan_file(self, file_path):
        """Scan a single file using YARA rules and pattern matching"""
        if not self.is_running:
            return False
            
        try:
            
            # Skip certain file types that are known to be safe
            if any(file_path.lower().endswith(ext) for ext in ['.jpg', '.png', '.gif', '.bmp', '.mp3', '.wav']):
                return False
            
            # Only scan PE files with PE analyzer to save time
            threat_found = False
            is_executable = file_path.lower().endswith(('.exe', '.dll', '.sys', '.ocx', '.scr'))
            
            if is_executable:
                pe_issues, is_suspicious = self.analyze_pe_file(file_path)
                
                if pe_issues:
                    for issue in pe_issues:
                        self.results.append((file_path, f"PE Analysis: {issue}"))
                    if is_suspicious:
                        threat_found = True
                        return True
            
            # Perform entropy analysis on suspicious file types
            entropy_suspicious_ext = ['.exe', '.dll', '.sys', '.bin', '.dat', '.ocx', '.rar', '.zip', '.7z', '.msi', '.scr']
            if any(file_path.lower().endswith(ext) for ext in entropy_suspicious_ext):
                entropy_results = self.analyze_file_entropy(file_path)
                if entropy_results and entropy_results.get('entropy_suspicious'):
                    overall = entropy_results.get('overall_entropy', 0)
                    regions = entropy_results.get('high_entropy_regions', 0)
                    has_shift = entropy_results.get('has_entropy_shift', False)
                    
                    # Add results for high entropy files
                    entropy_message = f"High entropy detected: {overall:.2f}/8.0"
                    if regions > 0:
                        entropy_message += f", with {regions} high-entropy region(s)"
                    if has_shift:
                        entropy_message += ", with suspicious entropy shifts"
                        
                    self.results.append((file_path, f"Entropy Analysis: {entropy_message}"))
                    threat_found = True
            
            # Only use YARA for suspicious file types
            suspicious_extensions = ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.hta', '.scr', '.php', '.py']
            if hasattr(self, 'rules') and any(file_path.lower().endswith(ext) for ext in suspicious_extensions):
                try:
                    matches = self.rules.match(file_path)
                    if matches:
                        print(f"YARA matches found in {file_path}: {matches}")
                        for match in matches:
                            self.results.append((file_path, f"YARA match: {match.rule}"))
                            threat_found = True
                except Exception:
                    # Fall back to simple scan only on YARA failure for suspicious files
                    if file_path.lower().endswith(('.exe', '.dll', '.bat', '.cmd', '.ps1')):
                        return self.scan_file_simple(file_path)
            
            # Only do simple scan if other methods didn't find issues
            if not threat_found and is_executable:
                return self.scan_file_simple(file_path)
                
            return threat_found
            
        except Exception as e:
            self.update_status.emit(f"Error scanning file {os.path.basename(file_path)}: {str(e)}")
            return False
    
    def scan_file_simple(self, file_path):
        """Simple pattern matching fallback scan method"""
        try:
            # Skip large files for simple scan
            if os.path.getsize(file_path) > 5 * 1024 * 1024:  # 5MB limit for simple scan
                return False
                
            # Simple pattern matching (faster implementation)
            try:
                with open(file_path, 'rb') as f:
                    # Read in chunks instead of the whole file
                    content = f.read(256 * 1024)  # Read only first 256KB to check
                    content_lower = content.lower()  # Convert once
                    
                    # Check for suspicious binary patterns
                    suspicious_patterns = [
                        b'tvqaaamaaaaeaaaa',  # Base64 encoded MZ header (lowercase)
                        b'powershell -e',    
                        b'cmd.exe',          
                        b'regcreatekeyex',   
                        b'createremotethread',
                        b'virtualalloc',     
                        b'wscript.shell',    
                        b'winexec',          
                        b'shellcode',        
                        b'malware',          
                        b'trojan',           
                    ]
                    
                    # Count matches instead of storing them
                    matches_count = sum(1 for pattern in suspicious_patterns if pattern in content_lower)
                    
                    # If multiple suspicious patterns found
                    if matches_count >= 2:
                        self.results.append((file_path, f"Simple scan: Contains {matches_count} suspicious patterns"))
                        return True
                
                return False
                
            except Exception:
                return False
                
        except Exception:
            return False
        
    def scan_directory(self):
        """Scan a directory by finding all files and scanning each one"""
        self.update_status.emit(f"Scanning directory: {self.path}")
        
        # Get all files in directory (including subdirectories)
        try:
            for root, _, filenames in os.walk(self.path):
                # Skip certain directories that are typically safe
                if any(skip_dir in root for skip_dir in ['/node_modules/', '/__pycache__/', '/venv/', '/.git/']):
                    continue
                    
                for filename in filenames:
                    if not self.is_running:
                        return
                    self.files_to_scan.append(os.path.join(root, filename))
        except Exception as e:
            self.update_status.emit(f"Error walking directory {self.path}: {str(e)}")
            self.scan_complete.emit(self.results)
            return
                
        total_files = len(self.files_to_scan)
        if total_files == 0:
            self.update_status.emit("No files found in directory")
            self.scan_complete.emit(self.results)
            return
            
        self.update_status.emit(f"Found {total_files} files to scan")
        
        # Prioritize files for scanning
        self.files_to_scan = self.prioritize_files(self.files_to_scan)
        
        # Process files in batches to update progress less frequently
        batch_size = 10
        for i in range(0, total_files, batch_size):
            if not self.is_running:
                return
                
            # Process a batch of files
            batch = self.files_to_scan[i:min(i+batch_size, total_files)]
            for file_path in batch:
                self.files_scanned += 1
                self.scan_file(file_path)
            
            # Update progress after each batch
            progress = int((self.files_scanned / total_files) * 100)
            self.update_progress.emit(progress)
            self.update_status.emit(f"Scanning {self.files_scanned}/{total_files}")
            
        self.update_progress.emit(100)
        self.update_status.emit("Scan complete!")
        self.scan_complete.emit(self.results)
        
    def stop(self):
        self.is_running = False

    def analyze_pe_file(self, file_path):
        """
        Analyze a PE file for suspicious characteristics and imports
        Returns a list of issues found
        """
        suspicious_imports = {
            # Process manipulation
            'CreateRemoteThread': 'Can be used for code injection',
            'VirtualAllocEx': 'Memory allocation in another process',
            'WriteProcessMemory': 'Writing to another process memory',
            'SetWindowsHookEx': 'Can be used for keylogging',
            'GetAsyncKeyState': 'Can be used for keylogging',
            'ReadProcessMemory': 'Reading from another process memory',
            
            # Network functions that might indicate backdoor/C2
            'WSASocket': 'Network socket creation',
            'connect': 'Network connection',
            'InternetOpenUrl': 'Web requests',
            'HttpOpenRequest': 'Web requests',
            'InternetReadFile': 'Web data download',
            
            # File operations
            'CreateFile': 'File operations',
            'WriteFile': 'File writing',
            'MoveFile': 'File operations',
            'CopyFile': 'File operations',
            
            # Registry operations
            'RegOpenKey': 'Registry access',
            'RegSetValue': 'Registry modification',
            'RegCreateKey': 'Registry creation',
            
            # Persistence mechanisms
            'StartServiceCtrlDispatcher': 'Service operations',
            'CreateService': 'Service creation',
            
            # Process creation
            'CreateProcess': 'Process creation',
            'ShellExecute': 'Process execution',
            'WinExec': 'Process execution',
            'system': 'Command execution',
            
            # Anti-debugging and evasion
            'IsDebuggerPresent': 'Anti-debugging check',
            'CheckRemoteDebuggerPresent': 'Anti-debugging check',
            'GetTickCount': 'Potential anti-sandbox timing',
            'QueryPerformanceCounter': 'Potential anti-sandbox timing',
            'Sleep': 'Potential anti-sandbox timing',
        }
        
        suspicious_sections = {
            '.text': {'high_entropy': 7.0, 'executable': True, 'writable': False},
            '.data': {'high_entropy': 7.0, 'executable': False, 'writable': True},
            '.rdata': {'high_entropy': 7.0, 'executable': False, 'writable': False},
            # Custom or packed sections often have anomalous characteristics
            'UPX': {'note': 'UPX packed file'},
            'nsp0': {'note': 'Potential packer section'},
            'pebundle': {'note': 'Packed executable'}
        }
        
        issues = []
        anomaly_score = 0
        
        try:
            pe = pefile.PE(file_path)
            
            # Check compilation timestamp
            timestamp = pe.FILE_HEADER.TimeDateStamp
            compile_time = datetime.fromtimestamp(timestamp)
            current_time = datetime.now()
            
            # Check for future compilation date
            if compile_time > current_time:
                issues.append(f"Suspicious compilation timestamp in the future: {compile_time}")
                anomaly_score += 10
            
            # Check for very old compilation date
            if timestamp == 0 or timestamp == 0x5245504F:  # REPO in ASCII
                issues.append("Invalid/zeroed compilation timestamp")
                anomaly_score += 5
                
            # Analyze imports for suspicious APIs
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                suspicious_import_count = 0
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    library = entry.dll.decode('utf-8', errors='ignore')
                    for imp in entry.imports:
                        if imp.name:
                            name = imp.name.decode('utf-8', errors='ignore')
                            
                            # Check against suspicious imports list
                            for sus_import, reason in suspicious_imports.items():
                                if sus_import in name:
                                    issues.append(f"Suspicious import: {library}.{name} - {reason}")
                                    suspicious_import_count += 1
                                    anomaly_score += 3
                                    break
                
                # If many suspicious imports found
                if suspicious_import_count >= 5:
                    issues.append(f"High number of suspicious imports detected ({suspicious_import_count})")
                    anomaly_score += 10
            
            # Check for no imports (unusual for legit programs)
            elif not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                issues.append("No imports found - unusual for legitimate executables")
                anomaly_score += 8
                
            # Analyze sections
            high_entropy_sections = 0
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                section_entropy = section.get_entropy()
                is_executable = bool(section.Characteristics & 0x20000000)
                is_writable = bool(section.Characteristics & 0x80000000)
                
                # Check for high entropy (potential packing/encryption)
                if section_entropy > 7.0:
                    high_entropy_sections += 1
                    issues.append(f"High entropy section '{section_name}': {section_entropy:.2f}/8.00")
                    anomaly_score += 3
                
                # Executable + writable sections (often malicious)
                if is_executable and is_writable:
                    issues.append(f"Section '{section_name}' is both executable and writable (suspicious)")
                    anomaly_score += 8
                    
                # Check for known packer section names
                if any(packer in section_name for packer in ['UPX', 'nsp', 'pebundle', 'ASPack', 'FSG']):
                    issues.append(f"Possible packed section detected: '{section_name}'")
                    anomaly_score += 5
                    
            # Multiple high-entropy sections
            if high_entropy_sections >= 2:
                issues.append(f"Multiple high-entropy sections detected ({high_entropy_sections}) - possible packing")
                anomaly_score += 5
            
            # Resource analysis for embedded executables
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if hasattr(resource_type, 'directory'):
                        for resource_id in resource_type.directory.entries:
                            if hasattr(resource_id, 'directory'):
                                for resource_lang in resource_id.directory.entries:
                                    data_rva = resource_lang.data.struct.OffsetToData
                                    size = resource_lang.data.struct.Size
                                    
                                    # Check for large embedded resources
                                    if size > 200000:  # 200KB
                                        issues.append(f"Large embedded resource: {size/1024:.1f}KB")
                                        
                                    # Attempt to read resource
                                    try:
                                        resource_data = pe.get_data(data_rva, size)
                                        # Check if resource starts with MZ (embedded executable)
                                        if resource_data[:2] == b'MZ':
                                            issues.append("Embedded executable found in resources")
                                            anomaly_score += 15
                                    except:
                                        pass
            
            # Calculate overall threat score
            if anomaly_score >= 30:
                threat_level = "Critical"
            elif anomaly_score >= 20:
                threat_level = "High"
            elif anomaly_score >= 10:
                threat_level = "Medium"
            elif anomaly_score > 0:
                threat_level = "Low"
            else:
                threat_level = "None"
                
            if anomaly_score > 0:
                # Calculate file hash for reference
                sha256_hash = hashlib.sha256()
                with open(file_path, 'rb') as f:
                    for byte_block in iter(lambda: f.read(4096), b""):
                        sha256_hash.update(byte_block)
                file_hash = sha256_hash.hexdigest()
                
                issues.append(f"Overall threat assessment: {threat_level} (Score: {anomaly_score})")
                issues.append(f"File SHA-256: {file_hash}")
                
            return issues, anomaly_score >= 10  # Return True if suspicious
            
        except Exception as e:
            self.update_status.emit(f"Error analyzing PE file {os.path.basename(file_path)}: {str(e)}")
            return [], False

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
        self.setWindowTitle('Best Antivirus')
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
        title_label = QLabel("Best Antivirus")
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
        self.log("Application started - ready to scan")
        
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
        self.scan_thread.scan_complete.connect(self.scan_complete)
        self.scan_thread.start()
        
        self.log(f"Started {self.selected_type} scan on: {self.selected_path}")
        
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
            for file_path, threat_type in threats:
                item = QListWidgetItem(f"{os.path.basename(file_path)}: {threat_type}")
                item.setData(Qt.UserRole, file_path)
                item.setForeground(QColor("#FF6B6B"))  # Red color for threats
                self.results_list.addItem(item)
                
            self.log(f"Scan complete - {len(threats)} threats found")
            self.status_label.setText(f"Scan complete - {len(threats)} threats found!")
            
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
            
if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = AntivirusUI()
    window.show()
    sys.exit(app.exec_())