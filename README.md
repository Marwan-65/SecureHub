# SecureHub: Advanced Ransomware Simulation System



SecureHub is a comprehensive security project developed for a university course that simulates a sophisticated ransomware attack chain. The system demonstrates how psychological manipulation, technical deception, and cryptographic techniques can be combined to create a realistic cyber threat scenario.

## Project Overview

SecureHub consists of three interconnected components:
1. **Phishing Campaign**: Psychological manipulation via email
2. **Ransomware Payload**: File encryption with advanced obfuscation
3. **Ransomware Detector**: AI-powered threat analysis tool

This project demonstrates a complete attack lifecycle from initial compromise to data encryption and finally threat detection.

---

## 1. Phishing Campaign: The Human Vulnerability Exploit

### Attack Strategy
SecureHub employs a sophisticated two-stage phishing technique that exploits time pressure and authority bias:

1. **Initial Contact Email**:
   - Notification of successful CV screening
   - Announcement of upcoming technical exam
   - Establishes credibility and anticipation

2. **Follow-up Email** (10 minutes before exam):
   - Urgent requirement to download "proctoring software"
   - Creates time pressure to bypass critical thinking
   - Contains link to fake SecureHub application website

```plaintext
Hi Applicant,

You have been invited to take Siebens Software Diploma Admission Exam 2025 - Web by Siebens DISW.

Test Duration: 1 hrs 30 mins
Start date: May 4, 2025 08:30 PM EEST (Africa/Cairo)
End date: May 4, 2025 10:00 PM EEST (Africa/Cairo)
1	Download SecureHub Smart Proctoring browser
2	Launch the test by clicking the button below
OR
Paste the given link into your browser's address bar
https://securehub-ai.netlify.app/
Important
You can take this test anytime between the start date/time and end date/time.
Once the test starts, you cannot pause it. The test will run continuously for 1 hrs 30 mins.
Keep aside 15 minutes extra for downloading or updating the Smart Browser. You can only take the test in the latest version.
To learn more about the system compatibility of the Smart Browser, refer to this article.
Learn more about SecureHub
Before you begin
The practice test helps you to get familiar with the SecureHub platform and its proctoring settings.There is an automatic system-compatibility check in place before the test to check if your system is compatible for the test. To Download SecureHub you can use the download key "SecurityLab2023". This will expire after the exam is done. After downloading, unzip and run securehub.exe

Regards,
Team Siebens DISW
```

### Psychological Principles Applied:
- **Authority Bias**: Appearing as legitimate HR department
- **Time Pressure**: 10-minute deadline before exam
- **Fear of Missing Out (FOMO)**: Threat of disqualification
- **Plausibility**: Professional-looking fake website

---

## 2. Ransomware Payload: Advanced Encryption System

### Payload Delivery
Victims download a ZIP archive containing:
- Multiple decoy files (PDFs, images, videos)
- Nested folders with random executables
- The malicious `SecureHub.exe` payload

### Encryption Mechanism
The ransomware employs high quality cryptography with several obfuscation layers:

```python
# AES-CTR Encryption in 64KB chunks
def encrypt_file(key, in_filename, out_filename=None):
    chunksize = 64 * 1024  # 64KB chunks
    iv = Random.new().read(AES.block_size)
    encryptor = AES.new(key, AES.MODE_CTR, counter=Counter.new(128))
    
    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(iv)
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(encryptor.encrypt(chunk))
```

### Key Management System
1. **Key Generation**: 
   - 128-bit cryptographically secure random key
   - `os.urandom(16)` for true randomness

2. **Key Hiding** (Steganography):
   - Custom LSB (Least Significant Bit) algorithm
   - Key length stored in first 32 bits of image
   - Key bits distributed across RGB channels

```python
# Custom steganography implementation
def hide_key_in_image(image_path, key):
    img = Image.open(image_path)
    pixels = img.load()
    width, height = img.size
    
    # Store key length in first 4 bytes
    key_len = len(key).to_bytes(4, 'big')
    
    # Embed key in LSB of RGB channels
    key_index = 0
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            # Embed in LSB of each channel
            r = (r & 0xFE) | ((key[key_index] >> 0) & 1) if key_index < len(key) else r
            g = (g & 0xFE) | ((key[key_index] >> 1) & 1) if key_index < len(key) else g
            b = (b & 0xFE) | ((key[key_index] >> 2) & 1) if key_index < len(key) else b
            pixels[x, y] = (r, g, b)
            key_index += 1
```

### Anti-Forensic Features
- **File Mapping**: Hidden JSON database tracks original ↔ encrypted filenames
- **Decoy Files**: 50+ random files distract from malicious executables
- **Decryption Separation**: Decryption executable randomly named and hidden among decoys
- **Health Checks**: Decryptor verifies encryption status before operation

### Payment & Decryption Flow
1. User sees threatening GUI demanding payment
2. Upon payment confirmation:
   - Decryptor locates key via steganography
   - Files decrypted in 64KB chunks
   - Original filenames restored via mapping database
   - All malicious components self-destruct

---

## 3. Ransomware Detector: AI-Powered Threat Analysis

The detector uses multi-layered analysis to identify ransomware characteristics:

### Detection Techniques
1. **YARA Rule Scanning**:
   - Custom rules for SecureHub patterns
   - Malicious import detection
   - Encryption function signatures

2. **Entropy Analysis**:
   - Shannon entropy calculation
   - High entropy detection (>7.5 indicates encryption)
   - Entropy shift identification

```python
def calculate_entropy(data):
    entropy = 0.0
    total_bytes = len(data)
    byte_counts = {byte: data.count(byte) for byte in set(data)}
    for count in byte_counts.values():
        probability = count / total_bytes
        entropy -= probability * math.log2(probability)
    return entropy
```

3. **PE File Analysis**:
   - Suspicious import detection (CryptEncrypt, VirtualAlloc, etc.)
   - Section characteristic analysis
   - Compilation timestamp verification
   - Digital certificate validation

4. **Behavioral Indicators**:
   - Ransom note patterns
   - Bitcoin address detection
   - TOR network references
   - File extension changes (.locked, .encrypted)

### Threat Scoring System
The detector calculates a threat score based on:

| Indicator                | Score Contribution |
|--------------------------|-------------------|
| Suspicious imports       | +5 per match      |
| High entropy sections    | +10 per section   |
| YARA rule match          | +25 per match     |
| Invalid certificate      | +15               |
| .onion addresses         | +20               |
| Ransom-related strings   | +5 per match      |

**Threat Classification**:
- 0-29: Low risk
- 30-49: Moderate risk
- 50-79: High risk
- 80-100: Critical risk

---

## Technical Implementation

### Packaging & Deployment
- **Executable Conversion**: Python scripts converted to EXE using cx_Freeze
- **Dependency Handling**: All required libraries bundled into executable
- **Anti-Analysis**: No Python installation required on victim machine

### Why Executables?
1. Lower victim suspicion compared to Python scripts
2. No dependency installation required
3. No terminal visibility during execution
4. Harder to inspect than source code

### GitHub Repository Structure
```plaintext
SecureHub/
├── Phishing_Emails/            # Email templates
├── Ransomware_Payload/
│   ├── SecureHub.exe           # Main payload
│   ├── decrypt_XXXX.exe        # Hidden decryptor
│   ├── hidden_key.png          # Steganography container
│   ├── mapping.json            # Encrypted file database
│   ├── decoy_files/            # Distraction files
│   └── ...                     # Additional decoys
├── Ransomware_Detector/
│   ├── ransomware_detector.py  # Detection script
│   └── rules/                  # YARA rules directory
└── README.md                   # This document
```

---

## Ethical Considerations

SecureHub was developed strictly for educational purposes with these safeguards:
- Only deployed in controlled lab environments
- Never tested on non-consenting individuals
- Contains automatic expiration mechanisms
- Full data recovery capabilities built-in
- Used exclusively for security awareness training

---

## Conclusion

SecureHub demonstrates how sophisticated ransomware attacks combine:
1. **Psychological manipulation** through phased phishing
2. **Technical obfuscation** via steganography and file hiding
3. **Cryptographic sophistication** with proper AES implementation
4. **Anti-forensic techniques** through environmental awareness

The included ransomware detector provides a defense blueprint showing how multi-layered analysis can identify such threats through entropy measurement, import analysis, and behavioral pattern recognition.

**Disclaimer**: This project is for educational purposes only. Never deploy ransomware against non-consenting targets or outside controlled environments.