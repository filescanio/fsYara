////////////////////////////////////////////////////////
// YARA ruleset: RedLine.yar
// license: MIT License
// repository: kevthehermit/RATDecoders
// url: https://github.com/kevthehermit/RATDecoders/blob/d675ba1c06e6dd8365149c9ee8a8db1a6e5e508e/malwareconfig/yaraRules/RedLine.yar

// original YARA name: RedLine
private rule Redline0 {
meta:
	description = "Identifies RedLine stealer."
	author = "@bartblaze"
	date = "2021-06"
	tlp = "White"

strings:
	$ = "Account" ascii wide
	$ = "AllWalletsRule" ascii wide
	$ = "ArmoryRule" ascii wide
	$ = "AtomicRule" ascii wide
	$ = "Autofill" ascii wide
	$ = "BrowserExtensionsRule" ascii wide
	$ = "BrowserVersion" ascii wide
	$ = "Chrome" ascii wide
	$ = "CoinomiRule" ascii wide
	$ = "CommandLineUpdate" ascii wide
	$ = "CryptoHelper" ascii wide
	$ = "CryptoProvider" ascii wide
	$ = "DataBaseConnection" ascii wide
	$ = "DesktopMessangerRule" ascii wide
	$ = "DiscordRule" ascii wide
	$ = "DisplayHelper" ascii wide
	$ = "DownloadAndExecuteUpdate" ascii wide
	$ = "DownloadUpdate" ascii wide
	$ = "ElectrumRule" ascii wide
	$ = "EndpointConnection" ascii wide
	$ = "EthRule" ascii wide
	$ = "ExodusRule" ascii wide
	$ = "Extensions" ascii wide
	$ = "FileCopier" ascii wide
	$ = "FileScanner" ascii wide
	$ = "FileScannerArg" ascii wide
	$ = "FileScannerRule" ascii wide
	$ = "FileZilla" ascii wide
	$ = "GameLauncherRule" ascii wide
	$ = "Gecko" ascii wide
	$ = "GeoHelper" ascii wide
	$ = "GeoInfo" ascii wide
	$ = "GeoPlugin" ascii wide
	$ = "GuardaRule" ascii wide
	$ = "HardwareType" ascii wide
	$ = "IpSb" ascii wide
	$ = "IRemoteEndpoint" ascii wide
	$ = "ITaskProcessor" ascii wide
	$ = "JaxxRule" ascii wide
	$ = "NordApp" ascii wide
	$ = "OpenUpdate" ascii wide
	$ = "OpenVPNRule" ascii wide
	$ = "OsCrypt" ascii wide
	$ = "Program" ascii wide
	$ = "ProgramMain" ascii wide
	$ = "ProtonVPNRule" ascii wide
	$ = "RecordHeaderField" ascii wide
	$ = "RecoursiveFileGrabber" ascii wide
	$ = "ResultFactory" ascii wide
	$ = "ScanDetails" ascii wide
	$ = "ScannedBrowser" ascii wide
	$ = "ScannedCookie" ascii wide
	$ = "ScannedFile" ascii wide
	$ = "ScanningArgs" ascii wide
	$ = "ScanResult" ascii wide
	$ = "SqliteMasterEntry" ascii wide
	$ = "StringDecrypt" ascii wide
	$ = "SystemHardware" ascii wide
	$ = "SystemInfoHelper" ascii wide
	$ = "TableEntry" ascii wide
	$ = "TaskResolver" ascii wide
	$ = "UpdateAction" ascii wide
	$ = "UpdateTask" ascii wide
	$ = "XMRRule" ascii wide

condition:
	45 of them
}

////////////////////////////////////////////////////////

////////////////////////////////////////////////////////
// YARA ruleset: MALW_redline.yar
// license: Apache License 2.0
// repository: advanced-threat-research/Yara-Rules
// url: https://github.com/advanced-threat-research/Yara-Rules/blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/malware/MALW_redline.yar

// original YARA name: redline_payload
private rule Redline1 {
   
   meta:
     
      description = "Rule to detect the RedLine payload"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2020-04-16"
      rule_version = "v1"
      malware_type = "backdoor"
      malware_family = "Backdoor:W32/RedLine"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://www.proofpoint.com/us/threat-insight/post/new-redline-stealer-distributed-using-coronavirus-themed-email-campaign"
      hash = "5df956f08d6ad0559efcdb7b7a59b2f3b95dee9e2aa6b76602c46e2aba855eff"
      
   strings:

      $s1 = "Cambrel.exe" fullword ascii

      //TextInputFramework.DYNLINK
      $s2 = { 22 00 54 00 65 00 78 00 74 00 49 00 6e 00 70 00 75 00 74 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 2e 00 44 00 59 00 4e 00 4c 00 49 00 4e 00 4b 00 22 00 }

      $op0 = { 06 7c 34 00 00 04 7b 17 00 00 04 7e 21 00 00 0a }
      $op1 = { 96 00 92 0e 83 02 02 00 f4 20 }
      $op2 = { 03 00 c6 01 d9 08 1b 03 44 }

      $p0 = { 80 00 96 20 83 11 b7 02 10 }
      $p1 = { 20 01 00 72 0f 00 20 02 00 8a 0f 00 20 03 00 61 }
      $p2 = { 03 00 c6 01 cd 06 13 03 79 }

   condition:

      uint16(0) == 0x5a4d and
      filesize < 60KB and
      all of ($s*) and
      all of ($op*) or
      all of ($p*) 
}

////////////////////////////////////////////////////////



////////////////////////////////////////////////////////
// YARA ruleset: Windows_Trojan_RedLineStealer.yar
// license: Other
// repository: elastic/protections-artifacts
// url: https://github.com/elastic/protections-artifacts/blob/f98777756fcfbe5ab05a296388044a2dbb962557/yara/rules/Windows_Trojan_RedLineStealer.yar

// original YARA name: Windows_Trojan_RedLineStealer_17ee6a17
private rule Redline2 {
    meta:
        author = "Elastic Security"
        id = "17ee6a17-161e-454a-baf1-2734995c82cd"
        fingerprint = "a1f75937e83f72f61e027a1045374d3bd17cd387b223a6909b9aed52d2bc2580"
        creation_date = "2021-06-12"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.RedLineStealer"
        reference_sample = "497bc53c1c75003fe4ae3199b0ff656c085f21dffa71d00d7a3a33abce1a3382"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "RedLine.Logic.SQLite" ascii fullword
        $a2 = "RedLine.Reburn.Data.Browsers.Gecko" ascii fullword
        $a3 = "RedLine.Client.Models.Gecko" ascii fullword
        $b1 = "SELECT * FROM Win32_Process Where SessionId='{0}'" wide fullword
        $b2 = "get_encryptedUsername" ascii fullword
        $b3 = "https://icanhazip.com" wide fullword
        $b4 = "GetPrivate3Key" ascii fullword
        $b5 = "get_GrabTelegram" ascii fullword
        $b6 = "<GrabUserAgent>k__BackingField" ascii fullword
    condition:
        1 of ($a*) or all of ($b*)
}

// original YARA name: Windows_Trojan_RedLineStealer_f54632eb
private rule Redline3 {
    meta:
        author = "Elastic Security"
        id = "f54632eb-2c66-4aff-802d-ad1c076e5a5e"
        fingerprint = "6a9d45969c4d58181fca50d58647511b68c1e6ee1eeac2a1838292529505a6a0"
        creation_date = "2021-06-12"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.RedLineStealer"
        reference_sample = "d82ad08ebf2c6fac951aaa6d96bdb481aa4eab3cd725ea6358b39b1045789a25"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "ttp://checkip.amazonaws.com/logins.json" wide fullword
        $a2 = "https://ipinfo.io/ip%appdata%\\" wide fullword
        $a3 = "Software\\Valve\\SteamLogin Data" wide fullword
        $a4 = "get_ScannedWallets" ascii fullword
        $a5 = "get_ScanTelegram" ascii fullword
        $a6 = "get_ScanGeckoBrowsersPaths" ascii fullword
        $a7 = "<Processes>k__BackingField" ascii fullword
        $a8 = "<GetWindowsVersion>g__HKLM_GetString|11_0" ascii fullword
        $a9 = "<ScanFTP>k__BackingField" ascii fullword
        $a10 = "DataManager.Data.Credentials" ascii fullword
    condition:
        6 of ($a*)
}

// original YARA name: Windows_Trojan_RedLineStealer_3d9371fd
private rule Redline4 {
    meta:
        author = "Elastic Security"
        id = "3d9371fd-c094-40fc-baf8-f0e9e9a54ff9"
        fingerprint = "2d7ff7894b267ba37a2d376b022bae45c4948ef3a70b1af986e7492949b5ae23"
        creation_date = "2022-02-17"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.RedLineStealer"
        reference_sample = "0ec522dfd9307772bf8b600a8b91fd6facd0bf4090c2b386afd20e955b25206a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "get_encrypted_key" ascii fullword
        $a2 = "get_PassedPaths" ascii fullword
        $a3 = "ChromeGetLocalName" ascii fullword
        $a4 = "GetBrowsers" ascii fullword
        $a5 = "Software\\Valve\\SteamLogin Data" wide fullword
        $a6 = "%appdata%\\" wide fullword
        $a7 = "ScanPasswords" ascii fullword
    condition:
        all of them
}

// original YARA name: Windows_Trojan_RedLineStealer_63e7e006
private rule Redline5 {
    meta:
        author = "Elastic Security"
        id = "63e7e006-6c0c-47d8-8090-a6b36f01f3a3"
        fingerprint = "47c7b9a39a5e0a41f26fdf328231eb173a51adfc00948c68332ce72bc442e19e"
        creation_date = "2023-05-01"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.RedLineStealer"
        reference_sample = "e062c99dc9f3fa780ea9c6249fa4ef96bbe17fd1df38dbe11c664a10a92deece"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 30 68 44 27 25 5B 3D 79 21 54 3A }
        $a2 = { 40 5E 30 33 5D 44 34 4A 5D 48 33 }
        $a3 = { 4B EF 4D FF 44 DD 41 70 44 DC 41 00 44 DC 41 03 43 D9 3E 00 44 }
    condition:
        all of them
}

// original YARA name: Windows_Trojan_RedLineStealer_f07b3cb4
private rule Redline6 {
    meta:
        author = "Elastic Security"
        id = "f07b3cb4-a1c5-42c3-a992-d6d9a48bc7a0"
        fingerprint = "8687fa6f540ccebab6000c0c93be4931d874cd04b0692c6934148938bac0026e"
        creation_date = "2023-05-03"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.RedLineStealer"
        reference_sample = "5e491625475fc25c465fc7f6db98def189c15a133af7d0ac1ecbc8d887c4feb6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 3C 65 6E 63 72 79 70 74 65 64 5F 6B 65 79 3E 6B 5F 5F 42 61 63 6B 69 6E 67 46 69 65 6C 64 }
        $a2 = { 45 42 37 45 46 31 39 37 33 43 44 43 32 39 35 42 37 42 30 38 46 45 36 44 38 32 42 39 45 43 44 41 44 31 31 30 36 41 46 32 }
    condition:
        all of them
}

// original YARA name: Windows_Trojan_RedLineStealer_4df4bcb6
private rule Redline7 {
    meta:
        author = "Elastic Security"
        id = "4df4bcb6-a492-4407-8d8f-bbb835322c98"
        fingerprint = "a9e08bf28e8915615f9b39ab814a46c092b5714ef9133f740a1f1f876bfda2d9"
        creation_date = "2023-05-04"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.RedLineStealer"
        reference_sample = "9389475bd26c1d3fd04a083557f2797d0ee89dfdd1f7de67775fcd19e61dfbb3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 34 42 30 35 43 45 42 44 37 44 37 30 46 31 36 30 37 44 34 37 34 43 41 45 31 37 36 46 45 41 45 42 37 34 33 39 37 39 35 46 }
    condition:
        all of them
}

// original YARA name: Windows_Trojan_RedLineStealer_15ee6903
private rule Redline8 {
    meta:
        author = "Elastic Security"
        id = "15ee6903-757f-462b-8e1c-1ed8ca667910"
        fingerprint = "d3a380f68477b98b3f5adc11cc597042aa95636cfec0b0a5f2e51c201aa61227"
        creation_date = "2023-05-04"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.RedLineStealer"
        reference_sample = "46b506cafb2460ca2969f69bcb0ee0af63b6d65e6b2a6249ef7faa21bde1a6bd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 53 65 65 6E 42 65 66 6F 72 65 33 }
        $a2 = { 73 65 74 5F 53 63 61 6E 47 65 63 6B 6F 42 72 6F 77 73 65 72 73 50 61 74 68 73 }
    condition:
        all of them
}

// original YARA name: Windows_Trojan_RedLineStealer_6dfafd7b
private rule Redline9 {
    meta:
        author = "Elastic Security"
        id = "6dfafd7b-5188-4ec7-9ba4-58b8f05458e5"
        fingerprint = "b7770492fc26ada1e5cb5581221f59b1426332e57eb5e04922f65c25b92ad860"
        creation_date = "2024-01-05"
        last_modified = "2024-01-12"
        threat_name = "Windows.Trojan.RedLineStealer"
        reference_sample = "809e303ba26b894f006b8f2d3983ff697aef13b67c36957d98c56aae9afd8852"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 33 38 46 34 33 31 41 35 34 39 34 31 31 41 45 42 33 32 38 31 30 30 36 38 41 34 43 38 33 32 35 30 42 32 44 33 31 45 31 35 }
    condition:
        all of them
}


////////////////////////////////////////////////////////

////////////////////////////////////////////////////////
// YARA ruleset: win_redline_loader_dec_2023.yar
// repository: embee-research/Yara-detection-rules
// url: https://github.com/embee-research/Yara-detection-rules/blob/ac56d6f6fd2a30c8cb6e5c0455d6519210a8b0f4/Rules/win_redline_loader_dec_2023.yar

// original YARA name: win_redline_loader_dec_2023
private rule Redline10 {
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/12/24"
		description = "Patterns observed in redline loader"
		sha_256 = ""
		
	strings:
	
		$s1 = {8b ?? ?? 0c 30 04 31 46 3b f7 7c ?? 5d 5b 5e 83 ?? ?? 75}
		$s2 = "WritePrivateProfileStringA"
		$s3 = "SetFileShortNameA"
		$s4 = "- Attempt to use MSIL code from this assembly during native code initialization"
	
	condition:
		all of them
		

}


////////////////////////////////////////////////////////

////////////////////////////////////////////////////////
// YARA ruleset: RedLine.yar
// repository: CAPESandbox/community
// url: https://github.com/CAPESandbox/community/blob/ed71b5eb9179e25174c1a2d0fe451e25cbf97dd1/data/yara/CAPE/RedLine.yar

import "pe"

// original YARA name: RedLineDropperAHK
private rule Redline11 {
    meta:
        author = "ditekshen"
        description = "RedLine infostealer payload"
        cape_type = "RedLine Payload"
    strings:
        $s1 = ".SetRequestHeader(\"User-Agent\",\" ( \" OSName \" | \" bit \" | \" CPUNAme \"\"" ascii
        $s2 = ":= \" | Windows Defender\"" ascii
        $s3 = "WindowSpy.ahk" wide
    condition:
        uint16(0) == 0x5a4d and all of them
}

// original YARA name: RedLineDropperEXE
private rule Redline12 {
    meta:
      author = "ditekSHen"
      description = "Detects executables dropping RedLine infostealer"
      cape_type = "RedLineDropperEXE Payload"
    strings:
        $s1 = "Wizutezinod togeto0Rowadufevomuki futenujilazem jic lefogatenezinor" fullword wide
        $s2 = "6Tatafamobevofaj bizafoju peyovavacoco lizine kezakajuj" fullword wide
        $s3 = "Lawuherusozeru kucu zam0Zorizeyuk lepaposupu gala kinarusot ruvasaxehuwo" fullword wide
        $s4 = "ClearEventLogW" fullword ascii
        $s5 = "ProductionVersion" fullword wide
        $s6 = "Vasuko)Yugenizugilobo toxocivoriye yexozoyohuzeb" wide
        $s7 = "Yikezevavuzus gucajanesan#Rolapucededoxu xewulep fuwehofiwifi" wide
    condition:
        uint16(0) == 0x5a4d and (pe.exports("_fgeek@8") and 2 of them) or
        (
            2 of them and
            for any i in (0 .. pe.number_of_sections) : (
                (
                    pe.sections[i].name == ".rig"
                )
            )
        )
}

// original YARA name: RedLine
private rule Redline13 {
    meta:
        author = "ditekSHen"
        description = "Detects RedLine infostealer"
        cape_type = "RedLine Payload"
    strings:
        $s1 = { 23 00 2b 00 33 00 3b 00 43 00 53 00 63 00 73 00 }
        $s2 = { 68 10 84 2d 2c 71 ea 7e 2c 71 ea 7e 2c 71 ea 7e
                32 23 7f 7e 3f 71 ea 7e 0b b7 91 7e 2b 71 ea 7e
                2c 71 eb 7e 5c 71 ea 7e 32 23 6e 7e 1c 71 ea 7e
                32 23 69 7e a2 71 ea 7e 32 23 7b 7e 2d 71 ea 7e }
        $s3 = { 83 ec 38 53 b0 ?? 88 44 24 2b 88 44 24 2f b0 ??
                88 44 24 30 88 44 24 31 88 44 24 33 55 56 8b f1
                b8 0c 00 fe ff 2b c6 89 44 24 14 b8 0d 00 fe ff
                2b c6 89 44 24 1c b8 02 00 fe ff 2b c6 89 44 24
                18 b3 32 b8 0e 00 fe ff 2b c6 88 5c 24 32 88 5c
                24 41 89 44 24 28 57 b1 ?? bb 0b 00 fe ff b8 03
                00 fe ff 2b de 2b c6 bf 00 00 fe ff b2 ?? 2b fe
                88 4c 24 38 88 4c 24 42 88 4c 24 47 c6 44 24 34
                78 c6 44 24 35 61 88 54 24 3a c6 44 24 3e 66 c6
                44 24 41 33 c6 44 24 43 ?? c6 44 24 44 74 88 54
                24 46 c6 44 24 40 ?? c6 44 24 39 62 c7 44 24 10 }
        $s4 = "B|BxBtBpBlBhBdB`B\\BXBTBPBLBHBDB@B<B8B4B0B,B(B$B B" fullword wide
        $s5 = " delete[]" fullword ascii
        $s6 = "constructor or from DllMain." ascii

        $x1 = "RedLine.Reburn" ascii
        $x2 = "RedLine.Client." ascii
        $x3 = "hostIRemotePanel, CommandLine: " fullword wide
        $u1 = "<ParseCoinomi>" ascii
        $u2 = "<ParseBrowsers>" ascii
        $u3 = "<GrabScreenshot>" ascii
        $u4 = "UserLog" ascii nocase
        $u5 = "FingerPrintT" fullword ascii
        $u6 = "InstalledBrowserInfoT" fullword ascii
        $u7 = "RunPE" fullword ascii
        $u8 = "DownloadAndEx" fullword ascii
        $u9 = ".Data.Applications.Wallets" ascii
        $u10 = ".Data.Browsers" ascii
        $u11 = ".Models.WMI" ascii
        $u12 = "DefenderSucks" wide

        $pat1 = "(((([0-9.])\\d)+){1})" fullword wide
        $pat2 = "^(?:2131|1800|35\\\\d{3})\\\\d{11}$" fullword wide
        $pat3 = "6(?:011|5[0-9]{2})[0-9]{12}$/C" fullword wide
        $pat4 = "Telegramprofiles^(6304|6706|6709|6771)[0-9]{12,15}$" fullword wide
        $pat5 = "host_key^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})$" fullword wide
        $pat6 = "^3(?:0[0-5]|[68][0-9])[0-9]{11}$" wide
        $pat7 = "settingsprotocol^(5018|5020|5038|6304|6759|6761|6763)[0-9]{8,15}$" wide
        $pat8 = "Opera GX4[0-9]{12}(?:[0-9]{3})?$cookies" wide
        $pat9 = "^9[0-9]{15}$Coinomi" wide
        $pat10 = "wallets^(62[0-9]{14,17})$" wide
        $pat11 = "hostpasswordUsername_value" wide
        $pat12 = "credit_cards^389[0-9]{11}$" wide
        $pat13 = "NWinordVWinpn.eWinxe*WinhostUsername_value" wide
        $pat14 = /(\/|,\s)CommandLine:/ wide
        // another variant
        $v2_1 = "ListOfProcesses" fullword ascii
        $v2_2 = /get_Scan(ned)?(Browsers|ChromeBrowsersPaths|Discord|FTP|GeckoBrowsersPaths|Screen|Steam|Telegram|VPN|Wallets)/ fullword ascii
        $v2_3 = "GetArguments" fullword ascii
        $v2_4 = "VerifyUpdate" fullword ascii
        $v2_5 = "VerifyScanRequest" fullword ascii
        $v2_6 = "GetUpdates" fullword ascii
        // yet another variant
        $v3_1 = "localhost.IUserServiceu" fullword ascii
        $v3_2 = "ParseNetworkInterfaces" fullword ascii
        $v3_3 = "ReplyAction0http://tempuri.org/IUserService/GetUsersResponse" fullword ascii
        $v3_4 = "Action(http://tempuri.org/IUserService/GetUsersT" fullword ascii
        $v3_5 = "basicCfg" fullword wide
        // more variants
        $vx4_1 = "C:\\\\Windows\\\\Microsoft.NET\\\\Framework\\\\v4.0.30319\\\\AddInProcess32.exe" fullword wide
        $v4_2 = "isWow64" fullword ascii
        $v4_3 = "base64str" fullword ascii
        $v4_4 = "stringKey" fullword ascii
        $v4_5 = "BytesToStringConverted" fullword ascii
        $v4_6 = "FromBase64" fullword ascii
        $v4_7 = "xoredString" fullword ascii
        $v4_8 = "procName" fullword ascii
        $v4_9 = "base64EncodedData" fullword ascii
        // another variant 2021-10-23
        $v5_1 = "DownloadAndExecuteUpdate" fullword ascii
        $v5_2 = "ITaskProcessor" fullword ascii
        $v5_3 = "CommandLineUpdate" fullword ascii
        $v5_4 = "DownloadUpdate" fullword ascii
        $v5_5 = "FileScanning" fullword ascii
        $v5_6 = "GetLenToPosState" fullword ascii
        $v5_7 = "RecordHeaderField" fullword ascii
        $v5_8 = "EndpointConnection" fullword ascii
        $v5_9 = "BCRYPT_KEY_LENGTHS_STRUCT" fullword ascii
        // another variant (v11?)
        $v6_1 = "%localappdata%\\" fullword wide
        $v6_2 = "GetDecoded" fullword ascii
        $v6_3 = "//settinString.Removeg[@name=\\PasswString.Removeord\\]/valuString.RemoveeROOT\\SecurityCenter" fullword wide
        $v6_4 = "AppData\\Roaming\\ //settString.Replaceing[@name=\\UString.Replacesername\\]/vaString.Replaceluemoz_cookies" wide
        $v6_5 = "<GetWindowsVersion>g__HKLM_GetString|11_0" fullword ascii
        $v6_6 = "net.tcp://" fullword wide
    condition:
        (uint16(0) == 0x5a4d and (all of ($s*) or 2 of ($x*) or 7 of ($u*) or 7 of ($pat*) or (1 of ($x*) and (5 of ($u*) or 2 of ($pat*))) or 5 of ($v2*) or 4 of ($v3*) or (3 of ($v2*) and (2 of ($pat*) or 2 of ($u*)) or (1 of ($vx4*) and 5 of ($v4*)) or 5 of ($v4*) or 6 of ($v5*)) or 5 of ($v6*) or (4 of ($v6*) and 3 of them ))) or ((all of ($x*) and 4 of ($s*)) or (4 of ($v6*) and 4 of them))
}

////////////////////////////////////////////////////////

////////////////////////////////////////////////////////
// YARA ruleset: Win32_Trojan_RedLineStealer.yar
// license: MIT License
// repository: netskopeoss/NetskopeThreatLabsIOCs
// url: https://github.com/netskopeoss/NetskopeThreatLabsIOCs/blob/52c780db6106d0c0e8deb04653e036cdd4408e56/Malware/RedLine%20Stealer/Yara/Win32_Trojan_RedLineStealer.yar

import "pe"

// original YARA name: Win32_Trojan_Packed_RedLineStealer
private rule Redline14 {
    meta:
        description = "Identifies a loader used to deploy RedLine Stealer"
        author = "Netskope Threat Labs"
        reference = "4d77e265722624b5d4d1841d45c7c677"

    strings:
        $str00 = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\RegSvcs.exe" wide
        $str01 = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AppLaunch.exe" wide

        $api01 = "VirtualProtect"
        $api02 = "SendMessageA"
        $api03 = "PostMessageA"

        $asm00 = { 8a 8? ?? ?? ?? ?? 30 04 ?e 46 }
        $asm01 = { 8a 8? ?? ?? ?? ?? 30 04 3e e8 }

    condition:
        uint16(0) == 0x5a4d
        and 1 of ($str*)
        and 2 of ($api*)
        and 1 of ($asm*)
}

// original YARA name: Win32_Trojan_RedLineStealer
private rule Redline15 {
    meta:
        description = "Identifies RedLine Stealer samples"
        author = "Netskope Threat Labs"
        reference = "deb95cae4ba26dfba536402318154405"

    strings:
        $str00 = "System.Net.Sockets"
        $str01 = "ListOfPrograms"
        $str02 = "GetDefaultIPv4Address"
        $str03 = "GetWindowsVersion"
        $str04 = "cookies.sqlite" wide
        $str05 = "user.config" wide
        $str06 = "%appdata%\\discord\\Local Storage\\leveldb" wide
        $str07 = "{0}\\FileZilla\\recentservers.xml" wide
        $str08 = "Software\\Valve\\SteamLogin" wide
        $str09 = "NordVpn" wide

    condition:
        uint16(0) == 0x5a4d
        and pe.timestamp > 2210760000
        and all of ($str*)
}

////////////////////////////////////////////////////////

////////////////////////////////////////////////////////
// YARA ruleset: Mal_Stealer_NET_Redline_Aug_2020_1.yar
// repository: StrangerealIntel/DailyIOC
// url: https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-08-24/Redline/Mal_Stealer_NET_Redline_Aug_2020_1.yar

// original YARA name: Mal_Stealer_NET_Redline_Aug_2020_1
private rule Redline16 {
   meta:
      description = "Detect Redline Stealer (August 2020)"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/JAMESWT_MHT/status/1297878628450152448"
      date = "2020-08-24"
      hash1 = "4195430d95ac1ede9bc986728fc4211a1e000a9ba05a3e968dd302c36ab0aca0"
   strings:
      $s1 = { 53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 57 00 68 00 65 00 72 00 65 00 20 00 53 00 65 00 73 00 73 00 69 00 6f 00 6e 00 49 00 64 00 3d 00 27 00 7b 00 30 00 7d } // SELECT * FROM Win32_Process Where SessionId='{0}'
      $s2 = { 28 00 28 00 28 00 28 00 5b 00 30 00 2d 00 39 00 2e 00 5d 00 29 00 5c 00 64 00 29 00 2b 00 29 00 7b 00 31 00 7d 00 29 }  // (((([0-9.])\\d)+){1})
      $s3 = { 7b 00 30 00 7d 00 5c 00 46 00 69 00 6c 00 65 00 5a 00 69 00 6c 00 6c 00 61 00 5c 00 72 00 65 00 63 00 65 00 6e 00 74 00 73 00 65 00 72 00 76 00 65 00 72 00 73 00 2e 00 78 00 6d 00 6c } // {0}\\FileZilla\\recentservers.xml -> Also on QuasarRAT, be careful
      $s4 = { 7b 00 30 00 7d 00 5c 00 46 00 69 00 6c 00 65 00 5a 00 69 00 6c 00 6c 00 61 00 5c 00 73 00 69 00 74 00 65 00 6d 00 61 00 6e 00 61 00 67 00 65 00 72 00 2e 00 78 00 6d 00 6c } // {0}\FileZilla\sitemanager.xml -> Also on QuasarRAT, be careful
      $s5 = { 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 61 00 72 00 74 00 69 00 6e 00 20 00 50 00 72 00 69 00 6b 00 72 00 79 00 6c 00 5c 00 57 00 69 00 6e 00 53 00 43 00 50 00 20 00 32 00 5c 00 53 00 65 00 73 00 73 00 69 00 6f 00 6e 00 73 } // Software\\Martin Prikryl\\WinSCP 2\\Sessions -> common detection session
      $s6 = "<encrypted_key>k__BackingField" fullword ascii
      $s7 = "set_encrypted_key" fullword ascii
      $s8 = "UserAgentDetector" fullword ascii
      $s9 =  "set_encrypted_key" fullword ascii
      $s10 = "set_FtpConnections" fullword ascii
      $s11 = "set_IsProcessElevated" fullword ascii
      $s12 = "SELECT ExecutablePath, ProcessID FROM Win32_Process" fullword wide
      $s13 = "<IsProcessElevated>k__BackingField" fullword ascii
      $s14 = "System.Collections.Generic.IEnumerable<RedLine.Logic.Json.JsonValue>.GetEnumerator" fullword ascii
      $s15 = "System.Collections.Generic.IEnumerator<RedLine.Logic.Json.JsonValue>.get_Current" fullword ascii
      $s16 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\browser.exe" fullword wide
      $s17 = "ProcessExecutablePath" fullword ascii
      $s18 = "IsProcessElevated" fullword ascii
      $s19 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\firefox.exe" fullword wide
      $s20 = "get_encryptedPassword" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 90KB and 15 of them
}

////////////////////////////////////////////////////////



////////////////////////////////////////////////////////
// YARA ruleset: win_redline_payload_dec_2023.yar
// repository: embee-research/Yara-detection-rules
// url: https://github.com/embee-research/Yara-detection-rules/blob/ac56d6f6fd2a30c8cb6e5c0455d6519210a8b0f4/Rules/win_redline_payload_dec_2023.yar

// original YARA name: win_redline_payload_dec_2023
private rule Redline17 {
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/12/24"
		description = "Patterns observed in redline"
		sha_256 = "5790aead07ce0b9b508392b9a2f363ef77055ae16c44231773849c87a1dd15a4"
		
	strings:
	
		$s1 = {16 72 ?? ?? ?? 70 A2 7E ?? ?? ?? 04 17 72 ?? ?? ?? 70 7E ?? ?? ?? 04 16 9A 28 ?? ?? ?? 06 A2 7E ?? ?? ?? 04 18 72 ?? ?? ?? 70 }
	condition:
		all of them
		

}


////////////////////////////////////////////////////////

////////////////////////////////////////////////////////
// YARA ruleset: RedLine.yar
// license: MIT License
// repository: bartblaze/Yara-rules
// url: https://github.com/bartblaze/Yara-rules/blob/2df95022135637808d2a1ff9a49043ffd7f58c5d/rules/crimeware/RedLine.yar

// original YARA name: RedLine_a
private rule Redline18 {
    meta:
        id = "4Eeg9my5Llk67wiTDuBhLS"
        fingerprint = "8ba3c33d3affea6488b4fc056ad672922e243c790f16695bcf27c6dfab4ec611"
        version = "1.0"
        creation_date = "2021-06-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies RedLine stealer."
        category = "MALWARE"
        malware = "REDLINE"
        malware = "INFOSTEALER"

    strings:
        $ = "Account" ascii wide
        $ = "AllWalletsRule" ascii wide
        $ = "ArmoryRule" ascii wide
        $ = "AtomicRule" ascii wide
        $ = "Autofill" ascii wide
        $ = "BrowserExtensionsRule" ascii wide
        $ = "BrowserVersion" ascii wide
        $ = "Chrome" ascii wide
        $ = "CoinomiRule" ascii wide
        $ = "CommandLineUpdate" ascii wide
        $ = "CryptoHelper" ascii wide
        $ = "CryptoProvider" ascii wide
        $ = "DataBaseConnection" ascii wide
        $ = "DesktopMessangerRule" ascii wide
        $ = "DiscordRule" ascii wide
        $ = "DisplayHelper" ascii wide
        $ = "DownloadAndExecuteUpdate" ascii wide
        $ = "DownloadUpdate" ascii wide
        $ = "ElectrumRule" ascii wide
        $ = "EndpointConnection" ascii wide
        $ = "EthRule" ascii wide
        $ = "ExodusRule" ascii wide
        $ = "Extensions" ascii wide
        $ = "FileCopier" ascii wide
        $ = "FileScanner" ascii wide
        $ = "FileScannerArg" ascii wide
        $ = "FileScannerRule" ascii wide
        $ = "FileZilla" ascii wide
        $ = "GameLauncherRule" ascii wide
        $ = "Gecko" ascii wide
        $ = "GeoHelper" ascii wide
        $ = "GeoInfo" ascii wide
        $ = "GeoPlugin" ascii wide
        $ = "GuardaRule" ascii wide
        $ = "HardwareType" ascii wide
        $ = "IpSb" ascii wide
        $ = "IRemoteEndpoint" ascii wide
        $ = "ITaskProcessor" ascii wide
        $ = "JaxxRule" ascii wide
        $ = "NordApp" ascii wide
        $ = "OpenUpdate" ascii wide
        $ = "OpenVPNRule" ascii wide
        $ = "OsCrypt" ascii wide
        $ = "Program" ascii wide
        $ = "ProgramMain" ascii wide
        $ = "ProtonVPNRule" ascii wide
        $ = "RecordHeaderField" ascii wide
        $ = "RecoursiveFileGrabber" ascii wide
        $ = "ResultFactory" ascii wide
        $ = "ScanDetails" ascii wide
        $ = "ScannedBrowser" ascii wide
        $ = "ScannedCookie" ascii wide
        $ = "ScannedFile" ascii wide
        $ = "ScanningArgs" ascii wide
        $ = "ScanResult" ascii wide
        $ = "SqliteMasterEntry" ascii wide
        $ = "StringDecrypt" ascii wide
        $ = "SystemHardware" ascii wide
        $ = "SystemInfoHelper" ascii wide
        $ = "TableEntry" ascii wide
        $ = "TaskResolver" ascii wide
        $ = "UpdateAction" ascii wide
        $ = "UpdateTask" ascii wide
        $ = "XMRRule" ascii wide

    condition:
        45 of them
}

// original YARA name: RedLine_b
private rule Redline19 {
    meta:
        id = "6Ds02SHJ9xqDC5ehVb5PEZ"
        fingerprint = "5ecb15004061205cdea7bcbb6f28455b6801d82395506fd43769d591476c539e"
        version = "1.0"
        creation_date = "2021-10-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies RedLine stealer."
        category = "MALWARE"

    strings:
        $ = "Account" ascii wide
        $ = "AllWallets" ascii wide
        $ = "Autofill" ascii wide
        $ = "Browser" ascii wide
        $ = "BrowserVersion" ascii wide
        $ = "Chr_0_M_e" ascii wide
        $ = "CommandLineUpdate" ascii wide
        $ = "ConfigReader" ascii wide
        $ = "DesktopMessanger" ascii wide
        $ = "Discord" ascii wide
        $ = "DownloadAndExecuteUpdate" ascii wide
        $ = "DownloadUpdate" ascii wide
        $ = "EndpointConnection" ascii wide
        $ = "Extensions" ascii wide
        $ = "FileCopier" ascii wide
        $ = "FileScanner" ascii wide
        $ = "FileScannerArg" ascii wide
        $ = "FileScanning" ascii wide
        $ = "FileSearcher" ascii wide
        $ = "FileZilla" ascii wide
        $ = "FullInfoSender" ascii wide
        $ = "GameLauncher" ascii wide
        $ = "GdiHelper" ascii wide
        $ = "GeoInfo" ascii wide
        $ = "GeoPlugin" ascii wide
        $ = "HardwareType" ascii wide
        $ = "IContract" ascii wide
        $ = "ITaskProcessor" ascii wide
        $ = "IdentitySenderBase" ascii wide
        $ = "LocalState" ascii wide
        $ = "LocatorAPI" ascii wide
        $ = "NativeHelper" ascii wide
        $ = "NordApp" ascii wide
        $ = "OpenUpdate" ascii wide
        $ = "OpenVPN" ascii wide
        $ = "OsCrypt" ascii wide
        $ = "ParsSt" ascii wide
        $ = "PartsSender" ascii wide
        $ = "RecordHeaderField" ascii wide
        $ = "ScanDetails" ascii wide
        $ = "ScanResult" ascii wide
        $ = "ScannedCookie" ascii wide
        $ = "ScannedFile" ascii wide
        $ = "ScanningArgs" ascii wide
        $ = "SenderFactory" ascii wide
        $ = "SqliteMasterEntry" ascii wide
        $ = "StringDecrypt" ascii wide
        $ = "SystemHardware" ascii wide
        $ = "SystemInfoHelper" ascii wide
        $ = "TableEntry" ascii wide
        $ = "TaskResolver" ascii wide
        $ = "UpdateAction" ascii wide
        $ = "UpdateTask" ascii wide
        $ = "WalletConfig" ascii wide

    condition:
        45 of them
}

////////////////////////////////////////////////////////




////////////////////////////////////////////////////////
// YARA ruleset: win_redline_bytecodes_jan_2024.yar
// repository: embee-research/Yara-detection-rules
// url: https://github.com/embee-research/Yara-detection-rules/blob/ac56d6f6fd2a30c8cb6e5c0455d6519210a8b0f4/Rules/win_redline_bytecodes_jan_2024.yar

// original YARA name: win_redline_bytecodes_jan_2024
private rule Redline21 {
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/08/27"
		description = "Bytecodes found in late 2023 Redline malware"
		sha_256 = "ea1271c032046d482ed94c6d2c2c6e3ede9bea57dff13156cabca42b24fb9332"
		
	strings:
	
		$s1 = {00 00 7E ?? ?? ?? 04 7E ?? ?? ?? 04 28 ?? ?? ?? 06 17 8D ?? ?? ?? 01 25 16 1F 7C 9D 6F ?? ?? ?? 0A 13 ?? 16 13 ?? 38 }
		$s2 = "mscoree.dll" ascii
		
	condition:
	
		$s1 and $s2 
		and
		uint16(0) == 0x5a4d

		

}


/*

		 0x0000D683 00           IL_0053: nop
		 0x0000D684 00           IL_0054: nop
		 0x0000D685 7E3B000004   IL_0055: ldsfld    string Arguments::IP
		 0x0000D68A 7E3E000004   IL_005A: ldsfld    string Arguments::Key
		 0x0000D68F 28AC000006   IL_005F: call      string StringDecrypt::Read(string, string)
		 0x0000D694 17           IL_0064: ldc.i4.1
		 0x0000D695 8D7C000001   IL_0065: newarr    [mscorlib]System.Char
		 0x0000D69A 25           IL_006A: dup
		 0x0000D69B 16           IL_006B: ldc.i4.0
		 0x0000D69C 1F7C         IL_006C: ldc.i4.s  124
		 0x0000D69E 9D           IL_006E: stelem.i2
		 0x0000D69F 6FE000000A   IL_006F: callvirt  instance string[] [mscorlib]System.String::Split(char[])
		 0x0000D6A4 1308         IL_0074: stloc.s   V_8
		 0x0000D6A6 16           IL_0076: ldc.i4.0
		 0x0000D6A7 1309         IL_0077: stloc.s   V_9
		 0x0000D6A9 3828000000   IL_0079: br        IL_00A6


*/
////////////////////////////////////////////////////////

rule fsRedline {
    meta:
        description = "FsYARA - Malware Trends"
        vetted_family = "redline"
	condition:
		Redline0 or Redline1 or Redline2 or Redline3 or Redline4 or Redline5 or Redline6 or Redline7 or Redline8 or Redline9 or Redline10 or Redline11 or Redline12 or Redline13 or Redline14 or Redline15 or Redline16 or Redline17 or Redline18 or Redline19 or Redline21
}