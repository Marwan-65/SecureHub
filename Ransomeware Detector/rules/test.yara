/*
    Ransomware Detection YARA Rules
    Purpose: Detect common ransomware characteristics and behaviors
*/

rule Generic_Ransomware_File_Operations {
    meta:
        description = "Detects common file operations used by ransomware"
        severity = "critical"
        
    strings:
        // API calls for file enumeration
        $file_enum1 = "FindFirstFileW" ascii wide
        $file_enum2 = "FindNextFileW" ascii wide
        $file_enum3 = "FindFirstFileExW" ascii wide
        
        // File operations
        $file_op1 = "CreateFileW" ascii wide
        $file_op2 = "WriteFile" ascii wide
        $file_op3 = "DeleteFileW" ascii wide
        $file_op4 = "MoveFileExW" ascii wide
        
        // Common file extensions targeted by ransomware
        $target1 = ".doc" ascii wide nocase
        $target2 = ".xls" ascii wide nocase
        $target3 = ".ppt" ascii wide nocase
        $target4 = ".pdf" ascii wide nocase
        $target5 = ".jpg" ascii wide nocase
        $target6 = ".png" ascii wide nocase
        $target7 = ".txt" ascii wide nocase
        $target8 = ".zip" ascii wide nocase
        $target9 = ".sql" ascii wide nocase
        $target10 = ".mp3" ascii wide nocase
        $target11 = ".mp4" ascii wide nocase
    
    condition:
        uint16(0) == 0x5A4D and
        3 of ($file_enum*) and
        3 of ($file_op*) and
        5 of ($target*)
}

rule Ransomware_Encrypted_File_Extensions {
    meta:
        description = "Detects creation of files with common ransomware extensions"
        severity = "critical"
        
    strings:
        // Common ransomware file extensions
        $ext1 = ".locked" nocase ascii wide
        $ext2 = ".encrypted" nocase ascii wide
        $ext3 = ".crypted" nocase ascii wide
        $ext4 = ".crypt" nocase ascii wide
        $ext5 = ".enc" nocase ascii wide
        $ext6 = ".cry" nocase ascii wide
        $ext7 = ".crypto" nocase ascii wide
        $ext8 = ".WNCRY" nocase ascii wide    // WannaCry
        $ext9 = ".locky" nocase ascii wide    // Locky
        $ext10 = ".cerber" nocase ascii wide  // Cerber
        $ext11 = ".zepto" nocase ascii wide   // Zepto
        $ext12 = ".thor" nocase ascii wide    // Thor
        $ext13 = ".aesir" nocase ascii wide   // Aesir
        $ext14 = ".zzzzz" nocase ascii wide   // Cryptomix
        $ext15 = ".ccc" nocase ascii wide     // TeslaCrypt
        $ext16 = ".ctbl" nocase ascii wide    // CTB-Locker
        $ext17 = ".ACCDFISA" nocase ascii wide // Globe 
        
    condition:
        uint16(0) == 0x5A4D and
        2 of them
}

rule Ransomware_Ransom_Notes {
    meta:
        description = "Detects common phrases used in ransomware ransom notes"
        severity = "critical"
        
    strings:
        // Common ransom note filenames
        $note_name1 = "READ_ME.txt" nocase ascii wide
        $note_name2 = "HELP_DECRYPT" nocase ascii wide
        $note_name3 = "HOW_TO_DECRYPT" nocase ascii wide
        $note_name4 = "HOW_TO_RECOVER" nocase ascii wide
        $note_name5 = "RECOVERY_FILES" nocase ascii wide
        $note_name6 = "DECRYPT_INSTRUCTION" nocase ascii wide
        $note_name7 = "YOUR_FILES" nocase ascii wide
        $note_name8 = "RESTORE_FILES" nocase ascii wide
        $note_name9 = "!README" nocase ascii wide
        
        // Common phrases in ransom notes
        $text1 = "your files have been encrypted" nocase ascii wide
        $text2 = "pay the ransom" nocase ascii wide
        $text3 = "bitcoin" nocase ascii wide
        $text4 = "decrypt your files" nocase ascii wide
        $text5 = "recovery your files" nocase ascii wide
        $text6 = "pay within" nocase ascii wide
        $text7 = "deadline" nocase ascii wide
        $text8 = "payment instructions" nocase ascii wide
        $text9 = "private key" nocase ascii wide
        $text10 = "all your data will be lost" nocase ascii wide
        $text11 = "tor browser" nocase ascii wide
        $text12 = "contact us" nocase ascii wide
        
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($note_name*) or 4 of ($text*))
}

rule Ransomware_Encryption_APIs {
    meta:
        description = "Detects common encryption API calls used by ransomware"
        severity = "suspicious"
        
    strings:
        // Cryptography API functions
        $crypt1 = "CryptAcquireContextA" ascii wide
        $crypt2 = "CryptAcquireContextW" ascii wide
        $crypt3 = "CryptCreateHash" ascii wide
        $crypt4 = "CryptHashData" ascii wide
        $crypt5 = "CryptDeriveKey" ascii wide
        $crypt6 = "CryptEncrypt" ascii wide
        $crypt7 = "CryptDecrypt" ascii wide
        $crypt8 = "CryptGenRandom" ascii wide
        $crypt9 = "CryptImportKey" ascii wide
        $crypt10 = "CryptExportKey" ascii wide
        
        // Additional encryption libraries/capabilities
        $openssl1 = "OpenSSL" ascii wide
        $openssl2 = "AES_encrypt" ascii wide
        $openssl3 = "EVP_EncryptInit" ascii wide
        $openssl4 = "EVP_EncryptUpdate" ascii wide
        
        // Custom crypto
        $cust_crypto1 = "aes256" nocase ascii wide
        $cust_crypto2 = "rijndael" nocase ascii wide
        $cust_crypto3 = "serpent" nocase ascii wide
        $cust_crypto4 = "blowfish" nocase ascii wide
        $cust_crypto5 = "twofish" nocase ascii wide
        
    condition:
        uint16(0) == 0x5A4D and
        (
            5 of ($crypt*) or
            2 of ($openssl*) or
            2 of ($cust_crypto*)
        )
}

rule Ransomware_Shadow_Copy_Deletion {
    meta:
        description = "Detects attempts to delete Windows Volume Shadow Copies"
        severity = "critical"
        
    strings:
        // Shadow copy deletion commands
        $shadow1 = "vssadmin delete shadows" nocase ascii wide
        $shadow2 = "wmic shadowcopy delete" nocase ascii wide
        $shadow3 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" nocase ascii wide
        $shadow4 = "bcdedit /set {default} recoveryenabled no" nocase ascii wide
        $shadow5 = "wbadmin delete catalog" nocase ascii wide
        
        // COM objects used for VSS deletion
        $shadow_com1 = "IVssBackupComponents" ascii wide
        $shadow_com2 = "VSS_BT_COPY" ascii wide
        $shadow_com3 = "VSS_CTX_BACKUP" ascii wide
        
        // WMI access for VSS operations
        $wmi1 = "root\\cimv2" ascii wide
        $wmi2 = "Win32_ShadowCopy" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and
        (
            2 of ($shadow*) or
            (1 of ($shadow_com*) and 1 of ($wmi*))
        )
}

rule Specific_Ransomware_WannaCry {
    meta:
        description = "Detects WannaCry ransomware"
        severity = "critical"
        
    strings:
        $s1 = "WanaCrypt0r" nocase ascii wide
        $s2 = "WANACRY!" nocase ascii wide
        $s3 = "msg/m_bulgarian.wnry" ascii wide
        $s4 = "msg/m_chinese (simplified).wnry" ascii wide
        $s5 = "msg/m_chinese (traditional).wnry" ascii wide
        $s6 = "msg/m_croatian.wnry" ascii wide
        $s7 = "tasksche.exe" ascii wide
        $s8 = "@WanaDecryptor@" ascii wide
        $s9 = ".WNCRY" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and
        3 of them
}

rule Specific_Ransomware_Locky {
    meta:
        description = "Detects Locky ransomware"
        severity = "critical"
        
    strings:
        $s1 = "_HELP_instructions" ascii wide
        $s2 = ".locky" ascii wide
        $s3 = ".osiris" ascii wide
        $s4 = ".odin" ascii wide
        $s5 = ".aesir" ascii wide
        $s6 = ".thor" ascii wide
        $s7 = ".zzzzz" ascii wide
        $s8 = "Locky_recover" ascii wide
        $s9 = "thvsf" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and
        3 of them
}

rule Specific_Ransomware_Ryuk {
    meta:
        description = "Detects Ryuk ransomware"
        severity = "critical"
        
    strings:
        $s1 = "RyukReadMe.txt" ascii wide
        $s2 = ".RYK" ascii wide
        $s3 = ".RYUK" ascii wide
        $s4 = "YOUR_FILES_ARE_ENCRYPTED.HTML" ascii wide
        $s5 = "No system is safe" ascii wide
        $s6 = "LuckyNumber" ascii wide
        $s7 = "RyukReadMe.html" ascii wide
        
        // Registry manipulation
        $reg = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and
        (3 of ($s*) or (2 of ($s*) and $reg))
}

rule Ransomware_Anti_Analysis {
    meta:
        description = "Detects anti-analysis techniques commonly used by ransomware"
        severity = "suspicious"
        
    strings:
        // Anti-debugging/VM detection
        $anti_dbg1 = "IsDebuggerPresent" ascii wide
        $anti_dbg2 = "CheckRemoteDebuggerPresent" ascii wide
        $anti_dbg3 = "GetTickCount" ascii wide
        $anti_dbg4 = "QueryPerformanceCounter" ascii wide
        $anti_dbg5 = "GetSystemTime" ascii wide
        $anti_dbg6 = "GetProcessHeap" ascii wide
        $anti_dbg7 = "IsProcessorFeaturePresent" ascii wide
        
        // VM detection
        $vm1 = "vmware" nocase ascii wide
        $vm2 = "virtualbox" nocase ascii wide
        $vm3 = "vbox" nocase ascii wide
        $vm4 = "qemu" nocase ascii wide
        $vm5 = "bochs" nocase ascii wide
        
        // Sandbox evasion
        $sandbox1 = "username" nocase ascii wide
        $sandbox2 = "computername" nocase ascii wide
        $sandbox3 = "sleep" nocase ascii wide
        $sandbox4 = "GetComputerNameA" ascii wide
        $sandbox5 = "GetUserNameA" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and
        (
            3 of ($anti_dbg*) or
            2 of ($vm*) or
            3 of ($sandbox*)
        )
}

rule Ransomware_Process_Manipulation {
    meta:
        description = "Detects process manipulation typical for ransomware"
        severity = "critical"
        
    strings:
        // Process termination strings
        $proc_term1 = "taskkill /f /im" nocase ascii wide
        $proc_term2 = "net stop" nocase ascii wide
        
        // Specific services and processes targeted by ransomware
        $target_proc1 = "sql" nocase ascii wide
        $target_proc2 = "oracle" nocase ascii wide
        $target_proc3 = "postgres" nocase ascii wide
        $target_proc4 = "mysql" nocase ascii wide
        $target_proc5 = "backup" nocase ascii wide
        $target_proc6 = "vss" nocase ascii wide
        $target_proc7 = "firebird" nocase ascii wide
        $target_proc8 = "syncback" nocase ascii wide
        $target_proc9 = "acronis" nocase ascii wide
        $target_proc10 = "veeam" nocase ascii wide
        
        // Process API
        $proc_api1 = "CreateProcessA" ascii wide
        $proc_api2 = "CreateProcessW" ascii wide
        $proc_api3 = "OpenProcess" ascii wide
        $proc_api4 = "TerminateProcess" ascii wide
        $proc_api5 = "Process32First" ascii wide
        $proc_api6 = "Process32Next" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and
        (
            (1 of ($proc_term*) and 3 of ($target_proc*)) or
            (3 of ($proc_api*) and 2 of ($target_proc*))
        )
}