rule Ransomware_Indicators {
    meta:
        description = "Detects common ransomware indicators"
        author = "Security Analyst"
        severity = "critical"        
    strings:
        $ransom_note1 = "YOUR FILES HAVE BEEN ENCRYPTED" nocase wide ascii
        $ransom_note2 = "TO GET YOUR FILES BACK" nocase wide ascii
        $ransom_note3 = "BITCOIN" nocase wide ascii
        $ransom_note4 = "DECRYPT" nocase wide ascii
        $ransom_note5 = "ALL YOUR FILES HAVE BEEN LOCKED" nocase wide ascii
        
        $file_ext1 = ".locked" nocase wide ascii
        $file_ext2 = ".encrypted" nocase wide ascii
        $file_ext3 = ".crypt" nocase wide ascii
        $file_ext4 = ".pay" nocase wide ascii
        $file_ext5 = ".cry" nocase wide ascii
        
        $crypto1 = "AES" nocase wide ascii
        $crypto2 = "RSA" nocase wide ascii
        $crypto3 = "Blowfish" nocase wide ascii
        
        $tor1 = ".onion" nocase wide ascii
        $tor2 = "tor2web" nocase wide ascii
        
    condition:
        uint16(0) == 0x5A4D and // PE file
        (
            (2 of ($ransom_note*)) or
            (2 of ($file_ext*) and 1 of ($crypto*)) or
            (1 of ($ransom_note*) and 1 of ($crypto*) and 1 of ($tor*)) or
            (2 of ($crypto*) and 1 of ($tor*))
        )
}

rule Ransomware_Code_Indicators {
    meta:
        description = "Detects common code patterns in ransomware"
        author = "Security Analyst"
        severity = "critical"        
        
    strings:
        // File enumeration patterns
        $enum1 = "FindFirstFile" ascii wide
        $enum2 = "FindNextFile" ascii wide
        $enum3 = "SHGetFileInfo" ascii wide
        
        // Crypto API usage
        $crypto_api1 = "CryptEncrypt" ascii wide
        $crypto_api2 = "CryptDecrypt" ascii wide
        $crypto_api3 = "CryptGenRandom" ascii wide
        $crypto_api4 = "BCryptEncrypt" ascii wide
        
        // File operations with multiple extensions
        $file_op = /CreateFile.{1,100}\.docx|\.xlsx|\.pdf|\.jpg|\.png|\.txt/ ascii wide
        
        // Command execution
        $cmd1 = "cmd.exe /c" ascii wide
        $cmd2 = "vssadmin delete shadows" ascii wide
        $cmd3 = "bcdedit /set" ascii wide
        $cmd4 = "wbadmin delete" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and // PE file
        (
            (all of ($enum*) and 2 of ($crypto_api*)) or
            (2 of ($enum*) and $file_op and 1 of ($crypto_api*)) or
            (1 of ($cmd*) and 2 of ($crypto_api*)) or
            (2 of ($cmd*))
        )
}