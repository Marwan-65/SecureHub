

// rule Contains_Hardcoded_IP
// {
//     meta:
//         description = "Detects hardcoded IPv4 addresses in binary"
//         author = "YourName"
//         reference = "https://yourreference.com"
//         date = "2025-05-03"
//         malware_family = "Generic"

//     strings:
//         $ipv4 = /(?<![\d])((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(\.)){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(?![\d])/

//     condition:
//         uint16(0) == 0x5A4D and $ipv4
// }


// rule Contains_TOR_Onion_URL
// {
//     meta:
//         description = "Detects embedded .onion addresses"
//         author = "YourName"
//         reference = "https://yourreference.com"
//         date = "2025-05-03"
//         malware_family = "Ransomware"

//     strings:
//         $onion_url1 = /[a-z2-7]{16,56}\.onion/
//         $onion_url2 = ".onion"

//     condition:
//         uint16(0) == 0x5A4D and any of ($onion_url*)
// }
