rule WindowsCredentialEditor : hardened
{
	meta:
		description = "Windows Credential Editor"
		threat_level = 10
		score = 90
		id = "1542c6e4-36b2-5272-85d0-43226869b43e"

	strings:
		$a = {65 78 74 72 61 63 74 20 74 68 65 20 54 47 54 20 73 65 73 73 69 6f 6e 20 6b 65 79}
		$b = {57 69 6e 64 6f 77 73 20 43 72 65 64 65 6e 74 69 61 6c 73 20 45 64 69 74 6f 72}

	condition:
		all of them
}

rule HKTL_Amplia_Security_Tool : hardened
{
	meta:
		description = "Detects Amplia Security Tool like Windows Credential Editor"
		score = 60
		nodeepdive = 1
		author = "Florian Roth"
		date = "2013-01-01"
		modified = "2023-02-14"
		id = "4ad83f34-561d-53ce-9766-e21700354da7"

	strings:
		$a = {41 6d 70 6c 69 61 20 53 65 63 75 72 69 74 79}
		$c = {67 65 74 6c 73 61 73 72 76 61 64 64 72 2e 65 78 65}
		$d = {43 61 6e 6e 6f 74 20 67 65 74 20 50 49 44 20 6f 66 20 4c 53 41 53 53 2e 45 58 45}
		$e = {65 78 74 72 61 63 74 20 74 68 65 20 54 47 54 20 73 65 73 73 69 6f 6e 20 6b 65 79}
		$f = {50 50 57 44 55 4d 50 5f 44 41 54 41}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 3000KB and ( 2 of them ) or 3 of them
}

rule PwDump : hardened
{
	meta:
		description = "PwDump 6 variant"
		author = "Marc Stroebel"
		date = "2014-04-24"
		score = 70
		id = "e557e548-53e8-5098-93d4-8e899384e67c"

	strings:
		$s5 = {55 73 61 67 65 3a 20 25 73 20 5b 2d 78 5d 5b 2d 6e 5d 5b 2d 68 5d 5b 2d 6f 20 6f 75 74 70 75 74 5f 66 69 6c 65 5d 5b 2d 75 20 75 73 65 72 5d 5b 2d 70 20 70 61 73 73 77 6f 72 64 5d 5b 2d 73 20 73 68 61 72 65 5d 20 6d 61 63 68 69 6e 65 4e 61}
		$s6 = {55 6e 61 62 6c 65 20 74 6f 20 71 75 65 72 79 20 73 65 72 76 69 63 65 20 73 74 61 74 75 73 2e 20 53 6f 6d 65 74 68 69 6e 67 20 69 73 20 77 72 6f 6e 67 2c 20 70 6c 65 61 73 65 20 6d 61 6e 75 61 6c 6c 79 20 63 68 65 63 6b 20 74 68 65 20 73 74}
		$s7 = {70 77 64 75 6d 70 36 20 56 65 72 73 69 6f 6e 20 25 73 20 62 79 20 66 69 7a 7a 67 69 67 20 61 6e 64 20 74 68 65 20 6d 69 67 68 74 79 20 67 72 6f 75 70 20 61 74 20 66 6f 6f 66 75 73 2e 6e 65 74}

	condition:
		1 of them
}

rule PScan_Portscan_1 : hardened
{
	meta:
		description = "PScan - Port Scanner"
		author = "F. Roth"
		score = 50
		id = "54997776-644b-5a72-b08c-7174b7dc7f66"

	strings:
		$a = {30 30 30 35 30 3b 30 46 30 4d 30 58 30 61 30 76 30 7d 30}
		$b = {76 77 67 76 77 67 76 50 37 36}
		$c = {50 72 30 50 68 4f 46 79 50}

	condition:
		all of them
}

rule HackTool_Samples : hardened
{
	meta:
		description = "Hacktool"
		score = 50
		id = "ecacf84a-f66c-5c21-ae4b-fd9bfb5be384"

	strings:
		$a = {55 6e 61 62 6c 65 20 74 6f 20 75 6e 69 6e 73 74 61 6c 6c 20 74 68 65 20 66 67 65 78 65 63 20 73 65 72 76 69 63 65}
		$b = {55 6e 61 62 6c 65 20 74 6f 20 73 65 74 20 73 6f 63 6b 65 74 20 74 6f 20 73 6e 69 66 66}
		$c = {46 61 69 6c 65 64 20 74 6f 20 6c 6f 61 64 20 53 41 4d 20 66 75 6e 63 74 69 6f 6e 73}
		$d = {44 75 6d 70 20 73 79 73 74 65 6d 20 70 61 73 73 77 6f 72 64 73}
		$e = {45 72 72 6f 72 20 6f 70 65 6e 69 6e 67 20 73 61 6d 20 68 69 76 65 20 6f 72 20 6e 6f 74 20 76 61 6c 69 64 20 66 69 6c 65}
		$f = {43 6f 75 6c 64 6e 27 74 20 66 69 6e 64 20 4c 53 41 53 53 20 70 69 64}
		$g = {73 61 6d 64 75 6d 70 2e 64 6c 6c}
		$h = {57 50 45 50 52 4f 20 53 45 4e 44 20 50 41 43 4b 45 54}
		$i = {57 50 45 2d 43 31 34 36 37 32 31 31 2d 37 43 38 39 2d 34 39 63 35 2d 38 30 31 41 2d 31 44 30 34 38 45 34 30 31 34 43 34}
		$j = {55 73 61 67 65 3a 20 75 6e 73 68 61 64 6f 77 20 50 41 53 53 57 4f 52 44 2d 46 49 4c 45 20 53 48 41 44 4f 57 2d 46 49 4c 45}
		$k = {61 72 70 73 70 6f 6f 66 5c 44 65 62 75 67}
		$l = {53 75 63 63 65 73 73 3a 20 54 68 65 20 6c 6f 67 20 68 61 73 20 62 65 65 6e 20 63 6c 65 61 72 65 64}
		$m = {63 6c 65 61 72 6c 6f 67 73 20 5b 5c 5c 63 6f 6d 70 75 74 65 72 6e 61 6d 65}
		$n = {44 75 6d 70 55 73 65 72 73 20 31 2e}
		$o = {64 69 63 74 69 6f 6e 61 72 79 20 61 74 74 61 63 6b 20 77 69 74 68 20 73 70 65 63 69 66 69 65 64 20 64 69 63 74 69 6f 6e 61 72 79 20 66 69 6c 65}
		$p = {62 79 20 4f 62 6a 65 63 74 69 66 20 53 65 63 75 72 69 74 65}
		$q = {6f 62 6a 65 63 74 69 66 2d 73 65 63 75 72 69 74 65}
		$r = {43 61 6e 6e 6f 74 20 71 75 65 72 79 20 4c 53 41 20 53 65 63 72 65 74 20 6f 6e 20 72 65 6d 6f 74 65 20 68 6f 73 74}
		$s = {43 61 6e 6e 6f 74 20 77 72 69 74 65 20 74 6f 20 70 72 6f 63 65 73 73 20 6d 65 6d 6f 72 79 20 6f 6e 20 72 65 6d 6f 74 65 20 68 6f 73 74}
		$t = {43 61 6e 6e 6f 74 20 73 74 61 72 74 20 50 57 44 75 6d 70 58 20 73 65 72 76 69 63 65 20 6f 6e 20 68 6f 73 74}
		$u = {75 73 61 67 65 3a 20 25 73 20 3c 73 79 73 74 65 6d 20 68 69 76 65 3e 20 3c 73 65 63 75 72 69 74 79 20 68 69 76 65 3e}
		$v = {75 73 65 72 6e 61 6d 65 3a 64 6f 6d 61 69 6e 6e 61 6d 65 3a 4c 4d 68 61 73 68 3a 4e 54 68 61 73 68}
		$w = {3c 73 65 72 76 65 72 5f 6e 61 6d 65 5f 6f 72 5f 69 70 3e 20 7c 20 2d 66 20 3c 73 65 72 76 65 72 5f 6c 69 73 74 5f 66 69 6c 65 3e 20 5b 75 73 65 72 6e 61 6d 65 5d 20 5b 70 61 73 73 77 6f 72 64 5d}
		$x = {49 6d 70 65 72 73 6f 6e 61 74 69 6f 6e 20 54 6f 6b 65 6e 73 20 41 76 61 69 6c 61 62 6c 65}
		$y = {66 61 69 6c 65 64 20 74 6f 20 70 61 72 73 65 20 70 77 64 75 6d 70 20 66 6f 72 6d 61 74 20 73 74 72 69 6e 67}
		$z = {44 75 6d 70 69 6e 67 20 70 61 73 73 77 6f 72 64}

	condition:
		1 of them
}

rule Fierce2 : hardened
{
	meta:
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		description = "This signature detects the Fierce2 domain scanner"
		date = "01.07.2014"
		score = 60
		id = "08a72151-48c2-513b-995f-be0d5acba7dd"

	strings:
		$s1 = {24 74 74 5f 78 6d 6c 2d 3e 70 72 6f 63 65 73 73 28 20 27 65 6e 64 5f 64 6f 6d 61 69 6e 73 63 61 6e 2e 74 74 27 2c 20 24 65 6e 64 5f 64 6f 6d 61 69 6e 73 63 61 6e 5f 76 61 72 73 2c}

	condition:
		1 of them
}

rule Ncrack : hardened
{
	meta:
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		description = "This signature detects the Ncrack brute force tool"
		date = "01.07.2014"
		score = 60
		id = "c1c56ee9-7f76-5440-b0e0-86e372c53340"

	strings:
		$s1 = {4e 63 72 61 63 6b 4f 75 74 70 75 74 54 61 62 6c 65 20 6f 6e 6c 79 20 73 75 70 70 6f 72 74 73 20 61 64 64 69 6e 67 20 75 70 20 74 6f 20 34 30 39 36 20 74 6f 20 61 20 63 65 6c 6c 20 76 69 61}

	condition:
		1 of them
}

rule SQLMap : hardened
{
	meta:
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		description = "This signature detects the SQLMap SQL injection tool"
		date = "01.07.2014"
		score = 60
		id = "55a72fe6-f82d-5d55-842f-5d7e1cfcc9fa"

	strings:
		$s1 = {65 78 63 65 70 74 20 53 71 6c 6d 61 70 42 61 73 65 45 78 63 65 70 74 69 6f 6e 2c 20 65 78 3a}

	condition:
		1 of them
}

rule HKTL_PortScanner_Simple_Jan14 : hardened
{
	meta:
		description = "Auto-generated rule on file PortScanner.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "b381b9212282c0c650cb4b0323436c63"
		old_rule_name = "PortScanner"
		id = "3e8960ce-0428-51e1-b992-4fa09fee8520"

	strings:
		$s0 = {53 63 61 6e 20 50 6f 72 74 73 20 45 76 65 72 79}
		$s3 = {53 63 61 6e 20 41 6c 6c 20 50 6f 73 73 69 62 6c 65 20 50 6f 72 74 73 21}

	condition:
		all of them
}

rule iKAT_gpdisable_customcmd_kitrap0d_uacpoc : hardened
{
	meta:
		description = "iKAT hack tool set generic rule - from files gpdisable.exe, customcmd.exe, kitrap0d.exe, uacpoc.exe"
		author = "Florian Roth"
		date = "05.11.14"
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		super_rule = 1
		hash0 = "814c126f21bc5e993499f0c4e15b280bf7c1c77f"
		hash1 = "2725690954c2ad61f5443eb9eec5bd16ab320014"
		hash2 = "75f5aed1e719443a710b70f2004f34b2fe30f2a9"
		hash3 = "b65a460d015fd94830d55e8eeaf6222321e12349"
		score = 60

	strings:
		$s0 = {46 61 69 6c 65 64 20 74 6f 20 67 65 74 20 74 65 6d 70 20 66 69 6c 65 20 66 6f 72 20 73 6f 75 72 63 65 20 41 45 53 20 64 65 63 72 79 70 74 69 6f 6e}
		$s5 = {46 61 69 6c 65 64 20 74 6f 20 67 65 74 20 65 6e 63 72 79 70 74 69 6f 6e 20 68 65 61 64 65 72 20 66 6f 72 20 70 77 64 2d 70 72 6f 74 65 63 74}
		$s17 = {46 61 69 6c 65 64 20 74 6f 20 67 65 74 20 66 69 6c 65 74 69 6d 65}
		$s20 = {46 61 69 6c 65 64 20 74 6f 20 64 65 6c 65 74 65 20 74 65 6d 70 20 66 69 6c 65 20 66 6f 72 20 70 61 73 73 77 6f 72 64 20 64 65 63 6f 64 69 6e 67 20 28 33 29}

	condition:
		all of them
}

rule DomainScanV1_0 : hardened
{
	meta:
		description = "Auto-generated rule on file DomainScanV1_0.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "aefcd73b802e1c2bdc9b2ef206a4f24e"
		id = "94ead827-8b29-5cb5-82b6-a7ca5087bf7e"

	strings:
		$s0 = {64 49 4a 4d 75 58 24 61 4f 2d 45 56}
		$s1 = {58 45 4c 55 78 50 22 2d 5c}
		$s2 = {4b 61 52 22 55 27 7d 2d 4d 2c 2e}
		$s3 = {56 2e 29 5c 5a 44 78 70 4c 53 61 76}
		$s4 = {44 65 63 6f 6d 70 72 65 73 73 20 65 72 72 6f 72}
		$s5 = {43 61 6e 27 74 20 6c 6f 61 64 20 6c 69 62 72 61 72 79}
		$s6 = {43 61 6e 27 74 20 6c 6f 61 64 20 66 75 6e 63 74 69 6f 6e}
		$s7 = {63 6f 6d 30 74 6c 33 32 3a 2e 64}

	condition:
		all of them
}

rule HKTL_MooreR_Port_Scanner : hardened
{
	meta:
		description = "Auto-generated rule on file MooreR Port Scanner.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "376304acdd0b0251c8b19fea20bb6f5b"
		id = "5d8fb83f-bed3-53d2-bd33-2158911dc7c8"

	strings:
		$s0 = {44 65 73 63 72 69 70 74 69 6f 6e 7c}
		$s3 = {73 6f 66 74 20 56 69 73 75 61 6c 20 53 74 75 64 69 6f 5c 56 42 39 79 70}
		$s4 = {61 64 6a 5f 66 70 74 61 6e 3f 34}
		$s7 = {44 4f 57 53 5c 53 79 4d 65 6d 33 32 5c 2f 6f}

	condition:
		all of them
}

rule NetBIOS_Name_Scanner : hardened
{
	meta:
		description = "Auto-generated rule on file NetBIOS Name Scanner.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "888ba1d391e14c0a9c829f5a1964ca2c"
		id = "03716e00-a969-5ab5-9be7-e8fc4272e40f"

	strings:
		$s0 = {49 63 6f 6e 45 78}
		$s2 = {73 6f 66 74 20 56 69 73 75 61 6c 20 53 74 75}
		$s4 = {4e 42 54 53 63 61 6e 6e 65 72 21 79 26}

	condition:
		all of them
}

rule FeliksPack3___Scanners_ipscan : hardened
{
	meta:
		description = "Auto-generated rule on file ipscan.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "6c1bcf0b1297689c8c4c12cc70996a75"
		id = "8360b268-3434-5142-9248-40b7a1589be9"

	strings:
		$s2 = {57 43 41 50 3b 7d 45 43 54 45 44}
		$s4 = {4e 6f 74 53 75 70 70 6f 72 74 65 64}
		$s6 = {53 43 41 4e 2e 56 45 52 53 49 4f 4e 7b 5f}

	condition:
		all of them
}

rule CGISscan_CGIScan : hardened
{
	meta:
		description = "Auto-generated rule on file CGIScan.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "338820e4e8e7c943074d5a5bc832458a"
		id = "60bd5038-a308-55fd-85bb-2c4183f1c951"

	strings:
		$s1 = {57 00 61 00 6e 00 67 00 20 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 73 00}
		$s2 = {57 53 6f 63 6b 65 74 52 65 73 6f 6c 76 65 48 6f 73 74 3a 20 43 61 6e 6e 6f 74 20 63 6f 6e 76 65 72 74 20 68 6f 73 74 20 61 64 64 72 65 73 73 20 27 25 73 27}
		$s3 = {74 63 70 20 69 73 20 74 68 65 20 6f 6e 6c 79 20 70 72 6f 74 6f 63 6f 6c 20 73 75 70 70 6f 72 74 65 64 20 74 68 72 75 20 73 6f 63 6b 73 20 73 65 72 76 65 72}

	condition:
		all of ( $s* )
}

rule IP_Stealing_Utilities : hardened
{
	meta:
		description = "Auto-generated rule on file IP Stealing Utilities.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "65646e10fb15a2940a37c5ab9f59c7fc"
		id = "3a947e9c-d707-5819-88f2-059585750048"

	strings:
		$s0 = {44 61 72 6b 4b 6e 69 67 68 74}
		$s9 = {49 50 53 74 65 61 6c 65 72 55 74 69 6c 69 74 69 65 73}

	condition:
		all of them
}

rule SuperScan4 : hardened
{
	meta:
		description = "Auto-generated rule on file SuperScan4.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "78f76428ede30e555044b83c47bc86f0"
		id = "bd353382-ffa2-56c5-b842-1ffc94d6849e"

	strings:
		$s2 = {20 74 64 20 63 6c 61 73 73 3d 22 73 75 6d 6d 4f 31 22 3e}
		$s6 = {52 45 4d 27 45 42 41 71 52 49 53 45}
		$s7 = {43 6f 72 45 78 69 74 50 72 6f 63 65 73 73 27 6d 73 63 23 65}

	condition:
		all of them
}

rule PortRacer : hardened
{
	meta:
		description = "Auto-generated rule on file PortRacer.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "2834a872a0a8da5b1be5db65dfdef388"
		id = "54717938-2f4c-5442-b0ad-40b9acd1101a"

	strings:
		$s0 = {41 75 74 6f 20 53 63 72 6f 6c 6c 20 42 4f 54 48 20 54 65 78 74 20 42 6f 78 65 73}
		$s4 = {53 74 61 72 74 2f 53 74 6f 70 20 50 6f 72 74 73 63 61 6e 6e 69 6e 67}
		$s6 = {41 75 74 6f 20 53 61 76 65 20 4c 6f 67 46 69 6c 65 20 62 79 20 70 72 65 73 73 69 6e 67 20 53 54 4f 50}

	condition:
		all of them
}

rule scanarator : hardened
{
	meta:
		description = "Auto-generated rule on file scanarator.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "848bd5a518e0b6c05bd29aceb8536c46"
		id = "dfc3ff29-03b4-58ca-bfe0-c6888fddab67"

	strings:
		$s4 = {47 45 54 20 2f 73 63 72 69 70 74 73 2f 2e 2e 25 63 30 25 61 66 2e 2e 2f 77 69 6e 6e 74 2f 73 79 73 74 65 6d 33 32 2f 63 6d 64 2e 65 78 65 3f 2f 63 2b 64 69 72 20 48 54 54 50 2f 31 2e 30}

	condition:
		all of them
}

rule aolipsniffer : hardened
{
	meta:
		description = "Auto-generated rule on file aolipsniffer.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "51565754ea43d2d57b712d9f0a3e62b8"
		id = "f7cc0f31-6ba4-504b-82de-0334257b8a95"

	strings:
		$s0 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 4d 69 63 72 6f 73 6f 66 74 20 56 69 73 75 61 6c 20 53 74 75 64 69 6f 5c 56 42 39 38 5c 56 42 36 2e 4f 4c 42}
		$s1 = {64 77 47 65 74 41 64 64 72 65 73 73 46 6f 72 4f 62 6a 65 63 74}
		$s2 = {43 6f 6c 6f 72 20 54 72 61 6e 73 66 65 72 20 53 65 74 74 69 6e 67 73}
		$s3 = {46 58 20 47 6c 6f 62 61 6c 20 4c 69 67 68 74 69 6e 67 20 41 6e 67 6c 65}
		$s4 = {56 65 72 73 69 6f 6e 20 63 6f 6d 70 61 74 69 62 69 6c 69 74 79 20 69 6e 66 6f}
		$s5 = {4e 65 77 20 57 69 6e 64 6f 77 73 20 54 68 75 6d 62 6e 61 69 6c}
		$s6 = {4c 61 79 65 72 20 49 44 20 47 65 6e 65 72 61 74 6f 72 20 42 61 73 65}
		$s7 = {43 6f 6c 6f 72 20 48 61 6c 66 74 6f 6e 65 20 53 65 74 74 69 6e 67 73}
		$s8 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 5c 4d 53 57 49 4e 53 43 4b 2e 6f 63 61}

	condition:
		all of them
}

rule _Bitchin_Threads_ : hardened
{
	meta:
		description = "Auto-generated rule on file =Bitchin Threads=.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "7491b138c1ee5a0d9d141fbfd1f0071b"
		id = "3a51e76c-b360-5f10-961c-ecc3ea3fa3c9"

	strings:
		$s0 = {44 61 72 4b 50 61 69 4e}
		$s1 = {3d 42 49 54 43 48 49 4e 20 54 48 52 45 41 44 53}

	condition:
		all of them
}

rule cgis4_cgis4 : hardened
{
	meta:
		description = "Auto-generated rule on file cgis4.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "d658dad1cd759d7f7d67da010e47ca23"
		id = "98fbf445-b7a5-58fa-8f06-34be7321e2eb"

	strings:
		$s0 = {29 50 75 4d 42 5f 73 79 4a}
		$s1 = {26 2c 66 41 52 57 3e 79 52}
		$s2 = {6d 33 68 6d 33 74 5f 72 75 6c 6c 61 7a}
		$s3 = {37 50 72 6f 6a 65 63 74 63 31}
		$s4 = {54 65 6e 2d 47 47 6c 22}
		$s5 = {2f 4d 6f 7a 69 71 6c 78 61}

	condition:
		all of them
}

rule portscan : hardened
{
	meta:
		description = "Auto-generated rule on file portscan.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "a8bfdb2a925e89a281956b1e3bb32348"
		id = "967d6e3b-ae0d-5f93-a20d-742fc010608d"

	strings:
		$s5 = {30 20 20 20 20 3a 53 43 41 4e 20 42 45 47 55 4e 20 4f 4e 20 50 4f 52 54 3a}
		$s6 = {30 20 20 20 20 3a 50 4f 52 54 53 43 41 4e 20 52 45 41 44 59 2e}

	condition:
		all of them
}

rule ProPort_zip_Folder_ProPort : hardened
{
	meta:
		description = "Auto-generated rule on file ProPort.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "c1937a86939d4d12d10fc44b7ab9ab27"
		id = "cd611f6c-42ed-5cd3-a6ab-7e0970925e61"

	strings:
		$s0 = {43 6f 72 72 75 70 74 20 44 61 74 61 21}
		$s1 = {4b 34 70 7e 6f 6d 6b 49 7a}
		$s2 = {44 6c 6c 54 72 6f 6a 61 6e 53 63 61 6e}
		$s3 = {47 65 74 44 6c 6c 49 6e 66 6f}
		$s4 = {43 6f 6d 70 72 65 73 73 65 64 20 62 79 20 50 65 74 69 74 65 20 28 63 29 31 39 39 39 20 49 61 6e 20 4c 75 63 6b 2e}
		$s5 = {47 65 74 46 69 6c 65 43 52 43 33 32}
		$s6 = {47 65 74 54 72 6f 6a 61 6e 4e 75 6d 62 65 72}
		$s7 = {54 46 41 4b 41 62 6f 75 74}

	condition:
		all of them
}

rule StealthWasp_s_Basic_PortScanner_v1_2 : hardened
{
	meta:
		description = "Auto-generated rule on file StealthWasp's Basic PortScanner v1.2.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "7c0f2cab134534cd35964fe4c6a1ff00"
		id = "7f706186-f2e2-5d4d-951a-2ec8fc757cec"

	strings:
		$s1 = {42 61 73 69 63 20 50 6f 72 74 53 63 61 6e 6e 65 72}
		$s6 = {4e 6f 77 20 73 63 61 6e 6e 69 6e 67 20 70 6f 72 74 3a}

	condition:
		all of them
}

rule BluesPortScan : hardened
{
	meta:
		description = "Auto-generated rule on file BluesPortScan.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "6292f5fc737511f91af5e35643fc9eef"
		id = "4bcb8b7c-5e22-5496-9a29-66e85e3c3395"

	strings:
		$s0 = {54 68 69 73 20 70 72 6f 67 72 61 6d 20 77 61 73 20 6d 61 64 65 20 62 79 20 56 6f 6c 6b 65 72 20 56 6f 73 73}
		$s1 = {4a 69 42 4f 6f 7e 53 53 42}

	condition:
		all of them
}

rule scanarator_iis : hardened
{
	meta:
		description = "Auto-generated rule on file iis.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "3a8fc02c62c8dd65e038cc03e5451b6e"
		id = "a467147b-53c8-53db-aa33-5f0e4e066988"

	strings:
		$s0 = {65 78 61 6d 70 6c 65 3a 20 69 69 73 20 31 30 2e 31 30 2e 31 30 2e 31 30}
		$s1 = {73 65 6e 64 20 65 72 72 6f 72}

	condition:
		all of them
}

rule stealth_Stealth : hardened
{
	meta:
		description = "Auto-generated rule on file Stealth.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "8ce3a386ce0eae10fc2ce0177bbc8ffa"
		id = "5f45882e-3e27-596d-8725-fad380e1c297"

	strings:
		$s3 = {3c 74 61 62 6c 65 20 77 69 64 74 68 3d 22 36 30 25 22 20 62 67 63 6f 6c 6f 72 3d 22 62 6c 61 63 6b 22 20 63 65 6c 6c 73 70 61 63 69 6e 67 3d 22 30 22 20 63 65 6c 6c 70 61 64 64 69 6e 67 3d 22 32 22 20 62 6f 72 64 65 72 3d 22 31 22 20 62 6f 72 64 65 72 63 6f 6c 6f 72 3d 22 77 68 69 74 65 22 3e 3c 74 72 3e 3c 74 64 3e}
		$s6 = {54 68 69 73 20 74 6f 6f 6c 20 6d 61 79 20 62 65 20 75 73 65 64 20 6f 6e 6c 79 20 62 79 20 73 79 73 74 65 6d 20 61 64 6d 69 6e 69 73 74 72 61 74 6f 72 73 2e 20 49 20 61 6d 20 6e 6f 74 20 72 65 73 70 6f 6e 73 69 62 6c 65 20 66 6f 72 20}

	condition:
		all of them
}

rule Angry_IP_Scanner_v2_08_ipscan : hardened
{
	meta:
		description = "Auto-generated rule on file ipscan.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "70cf2c09776a29c3e837cb79d291514a"
		id = "5fbcbb95-6cd4-5587-bf44-5b5ed133ce5e"

	strings:
		$s0 = {5f 48 2f 45 6e 75 6d 44 69 73 70 6c 61 79 2f}
		$s5 = {45 43 54 45 44 2e 4d 53 56 43 52 54 30 78}
		$s8 = {4e 6f 74 53 75 70 70 6f 72 74 65 64 37}

	condition:
		all of them
}

rule crack_Loader : hardened
{
	meta:
		description = "Auto-generated rule on file Loader.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "f4f79358a6c600c1f0ba1f7e4879a16d"
		id = "0c4c7b69-7739-5c1b-8c7c-4aaa724e4455"

	strings:
		$s0 = {4e 65 6f 57 61 69 74 2e 65 78 65}
		$s1 = {52 52 52 52 52 52 52 57}

	condition:
		all of them
}

rule CN_GUI_Scanner : hardened
{
	meta:
		description = "Detects an unknown GUI scanner tool - CN background"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "3c67bbb1911cdaef5e675c56145e1112"
		score = 65
		date = "04.10.2014"
		id = "ca88d4d3-5d18-5856-874f-e50deceef54f"

	strings:
		$s1 = {67 6f 6f 64 2e 74 78 74}
		$s2 = {49 50 2e 74 78 74}
		$s3 = {78 69 61 6f 79 75 65 72}
		$s0w = {73 00 73 00 68 00 28 00}
		$s1w = {29 00 2e 00 65 00 78 00 65 00}

	condition:
		all of them
}

rule CN_Packed_Scanner : hardened
{
	meta:
		description = "Suspiciously packed executable"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "6323b51c116a77e3fba98f7bb7ff4ac6"
		score = 40
		date = "06.10.2014"
		id = "a11c4ee6-7244-5601-af26-a45f9fdc8e1b"

	strings:
		$s1 = {6b 65 72 6e 65 6c 33 32 2e 64 6c 6c}
		$s2 = {43 52 54 44 4c 4c 2e 44 4c 4c}
		$s3 = {5f 5f 47 65 74 4d 61 69 6e 41 72 67 73}
		$s4 = {57 53 32 5f 33 32 2e 44 4c 4c}

	condition:
		all of them and filesize < 180KB and filesize > 70KB
}

rule Tiny_Network_Tool_Generic : FILE hardened
{
	meta:
		description = "Tiny tool with suspicious function imports. (Rule based on WinEggDrop Scanner samples)"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "08.10.2014"
		score = 40
		hash0 = "9e1ab25a937f39ed8b031cd8cfbc4c07"
		hash1 = "cafc31d39c1e4721af3ba519759884b9"
		hash2 = "8e635b9a1e5aa5ef84bfa619bd2a1f92"
		id = "04b1c2c6-605c-52d5-aa07-f3b77a6c4593"

	strings:
		$s0 = {4b 45 52 4e 45 4c 33 32 2e 44 4c 4c}
		$s1 = {43 52 54 44 4c 4c 2e 44 4c 4c}
		$s3 = {4c 6f 61 64 4c 69 62 72 61 72 79 41}
		$s4 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73}
		$y1 = {57 49 4e 49 4e 45 54 2e 44 4c 4c}
		$y2 = {61 74 6f 69}
		$x1 = {41 44 56 41 50 49 33 32 2e 44 4c 4c}
		$x2 = {55 53 45 52 33 32 2e 44 4c 4c}
		$x3 = {77 73 6f 63 6b 33 32 2e 64 6c 6c}
		$x4 = {46 72 65 65 53 69 64}
		$x5 = {61 74 6f 69}
		$z1 = {41 44 56 41 50 49 33 32 2e 44 4c 4c}
		$z2 = {55 53 45 52 33 32 2e 44 4c 4c}
		$z3 = {46 72 65 65 53 69 64}
		$z4 = {54 6f 41 73 63 69 69}

	condition:
		uint16( 0 ) == 0x5a4d and all of ( $s* ) and ( all of ( $y* ) or all of ( $x* ) or all of ( $z* ) ) and filesize < 15KB
}

rule Beastdoor_Backdoor : hardened
{
	meta:
		description = "Detects the backdoor Beastdoor"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 55
		hash = "5ab10dda548cb821d7c15ebcd0a9f1ec6ef1a14abcc8ad4056944d060c49535a"
		id = "64f67233-6677-53c8-b212-f1a425f78803"

	strings:
		$s0 = {52 65 64 69 72 65 63 74 20 53 50 6f 72 74 20 52 65 6d 6f 74 65 48 6f 73 74 20 52 50 6f 72 74 20 20 2d 2d 3e 50 6f 72 74 20 52 65 64 69 72 65 63 74 6f 72}
		$s1 = {50 4f 53 54 20 2f 73 63 72 69 70 74 73 2f 57 57 50 4d 73 67 2e 64 6c 6c 20 48 54 54 50 2f 31 2e 30}
		$s2 = {68 74 74 70 3a 2f 2f 49 50 2f 61 2e 65 78 65 20 61 2e 65 78 65 20 20 20 20 20 20 20 20 20 20 20 20 2d 2d 3e 44 6f 77 6e 6c 6f 61 64 20 41 20 46 69 6c 65}
		$s7 = {48 6f 73 74 3a 20 77 77 70 2e 6d 69 72 61 62 69 6c 69 73 2e 63 6f 6d 3a 38 30}
		$s8 = {25 73 20 2d 53 65 74 20 50 6f 72 74 20 50 6f 72 74 4e 75 6d 62 65 72 20 20 20 20 20 20 20 20 20 20 20 20 20 20 2d 2d 3e 53 65 74 20 54 68 65 20 53 65 72 76 69 63 65 20 50 6f 72 74}
		$s11 = {53 68 65 6c 6c 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 2d 2d 3e 47 65 74 20 41 20 53 68 65 6c 6c}
		$s14 = {44 65 6c 65 74 65 53 65 72 76 69 63 65 20 53 65 72 76 69 63 65 4e 61 6d 65 20 20 20 20 20 20 20 20 2d 2d 3e 44 65 6c 65 74 65 20 41 20 53 65 72 76 69 63 65}
		$s15 = {47 65 74 74 69 6e 67 20 54 68 65 20 55 73 65 72 4e 61 6d 65 28 25 63 25 73 25 63 29 2d 2d 3e 49 44 28 30 78 25 73 29 20 53 75 63 63 65 73 73 66 75 6c 6c 79}
		$s17 = {25 73 20 2d 53 65 74 20 53 65 72 76 69 63 65 4e 61 6d 65 20 53 65 72 76 69 63 65 4e 61 6d 65 20 20 20 20 20 20 2d 2d 3e 53 65 74 20 54 68 65 20 53 65 72 76 69 63 65 20 4e 61 6d 65}

	condition:
		2 of them
}

rule Powershell_Netcat : hardened
{
	meta:
		description = "Detects a Powershell version of the Netcat network hacking tool"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 60
		date = "10.10.2014"
		id = "e4b018c0-3214-5102-93b1-6a048324f9dd"

	strings:
		$s0 = {5b 56 61 6c 69 64 61 74 65 52 61 6e 67 65 28 31 2c 20 36 35 35 33 35 29 5d}
		$s1 = {24 43 6c 69 65 6e 74 20 3d 20 4e 65 77 2d 4f 62 6a 65 63 74 20 2d 54 79 70 65 4e 61 6d 65 20 53 79 73 74 65 6d 2e 4e 65 74 2e 53 6f 63 6b 65 74 73 2e 54 63 70 43 6c 69 65 6e 74}
		$s2 = {24 42 75 66 66 65 72 20 3d 20 4e 65 77 2d 4f 62 6a 65 63 74 20 2d 54 79 70 65 4e 61 6d 65 20 53 79 73 74 65 6d 2e 42 79 74 65 5b 5d 20 2d 41 72 67 75 6d 65 6e 74 4c 69 73 74 20 24 43 6c 69 65 6e 74 2e 52 65 63 65 69 76 65 42 75 66 66 65 72 53 69 7a 65}

	condition:
		all of them
}

rule Chinese_Hacktool_1014 : hardened
{
	meta:
		description = "Detects a chinese hacktool with unknown use"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 60
		date = "10.10.2014"
		hash = "98c07a62f7f0842bcdbf941170f34990"
		id = "e5db5f58-a1fd-51e0-9037-337fcca71f11"

	strings:
		$s0 = {49 00 45 00 58 00 54 00 32 00 5f 00 49 00 44 00 43 00 5f 00 48 00 4f 00 52 00 5a 00 4c 00 49 00 4e 00 45 00 4d 00 4f 00 56 00 45 00 43 00 55 00 52 00 53 00 4f 00 52 00}
		$s1 = {6d 00 73 00 63 00 74 00 6c 00 73 00 5f 00 70 00 72 00 6f 00 67 00 72 00 65 00 73 00 73 00 33 00 32 00}
		$s2 = {52 65 70 6c 79 2d 54 6f 3a 20 25 73}
		$s3 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 36 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 30 29}
		$s4 = {68 74 6d 6c 20 68 74 6d 20 68 74 78 20 61 73 70}

	condition:
		all of them
}

rule CN_Hacktool_BAT_PortsOpen : hardened
{
	meta:
		description = "Detects a chinese BAT hacktool for local port evaluation"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 60
		date = "12.10.2014"
		id = "55c3f678-ba70-5a4a-b288-9d0953eff968"

	strings:
		$s0 = {66 6f 72 20 2f 66 20 22 73 6b 69 70 3d 34 20 74 6f 6b 65 6e 73 3d 32 2c 35 22 20 25 25 61 20 69 6e 20 28 27 6e 65 74 73 74 61 74 20 2d 61 6e 6f 20 2d 70 20 54 43 50 27 29 20 64 6f 20 28}
		$s1 = {69 6e 20 28 27 74 61 73 6b 6c 69 73 74 20 2f 66 69 20 22 50 49 44 20 65 71 20 25 25 62 22 20 2f 46 4f 20 43 53 56 27 29 20 64 6f 20}
		$s2 = {40 65 63 68 6f 20 6f 66 66}

	condition:
		all of them
}

rule CN_Hacktool_SSPort_Portscanner : hardened
{
	meta:
		description = "Detects a chinese Portscanner named SSPort"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		date = "12.10.2014"
		id = "38cc8830-efd3-51b7-8ac6-c9bf468212cb"

	strings:
		$s0 = {47 00 6f 00 6c 00 64 00 65 00 6e 00 20 00 46 00 6f 00 78 00}
		$s1 = {53 00 79 00 6e 00 20 00 53 00 63 00 61 00 6e 00 20 00 50 00 6f 00 72 00 74 00}
		$s2 = {43 00 5a 00 38 00 38 00 2e 00 4e 00 45 00 54 00}

	condition:
		all of them
}

rule CN_Hacktool_ScanPort_Portscanner : hardened
{
	meta:
		description = "Detects a chinese Portscanner named ScanPort"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		date = "12.10.2014"
		id = "a708283e-339c-599f-9321-3b063d0076a9"

	strings:
		$s0 = {4c 00 53 00 63 00 61 00 6e 00 50 00 6f 00 72 00 74 00}
		$s1 = {4c 00 53 00 63 00 61 00 6e 00 50 00 6f 00 72 00 74 00 20 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00}
		$s2 = {77 00 77 00 77 00 2e 00 79 00 75 00 70 00 73 00 6f 00 66 00 74 00 2e 00 63 00 6f 00 6d 00}

	condition:
		all of them
}

rule CN_Hacktool_S_EXE_Portscanner : hardened
{
	meta:
		description = "Detects a chinese Portscanner named s.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		date = "12.10.2014"
		id = "d6b35d4f-7e25-50dd-bef2-08f7033312e8"

	strings:
		$s0 = {5c 52 65 73 75 6c 74 2e 74 78 74}
		$s1 = {42 79 3a 5a 54 20 51 51 3a 33 37 36 37 38 39 30 35 31}
		$s2 = {28 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 65 00 79 00 75 00 79 00 61 00 6e 00 2e 00 63 00 6f 00 6d 00 29 00}

	condition:
		all of them
}

rule CN_Hacktool_MilkT_BAT : hardened
{
	meta:
		description = "Detects a chinese Portscanner named MilkT - shipped BAT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		date = "12.10.2014"
		id = "d680a5f1-6182-5bc8-99de-c3cba1a61903"

	strings:
		$s0 = {66 6f 72 20 2f 66 20 22 65 6f 6c 3d 50 20 74 6f 6b 65 6e 73 3d 31 20 64 65 6c 69 6d 73 3d 20 22 20 25 25 69 20 69 6e 20 28 73 31 2e 74 78 74 29 20 64 6f 20 65 63 68 6f 20 25 25 69 3e 3e 73 32 2e 74 78 74}
		$s1 = {69 66 20 6e 6f 74 20 22 25 43 68 6f 69 63 65 25 22 3d 3d 22 22 20 73 65 74 20 43 68 6f 69 63 65 3d 25 43 68 6f 69 63 65 3a 7e 30 2c 31 25}

	condition:
		all of them
}

rule CN_Hacktool_MilkT_Scanner : hardened
{
	meta:
		description = "Detects a chinese Portscanner named MilkT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 60
		date = "12.10.2014"
		id = "aa83c983-25c2-5051-88a1-fbc70d947d6e"

	strings:
		$s0 = {42 66 20 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a}
		$s1 = {66 6f 72 6d 69 6e 67 20 54 69 6d 65 3a 20 25 64 2f}
		$s2 = {4b 45 52 4e 45 4c 33 32 2e 44 4c 4c}
		$s3 = {43 52 54 44 4c 4c 2e 44 4c 4c}
		$s4 = {57 53 32 5f 33 32 2e 44 4c 4c}
		$s5 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73}
		$s6 = {61 74 6f 69}

	condition:
		all of them
}

rule CN_Hacktool_1433_Scanner : hardened
{
	meta:
		description = "Detects a chinese MSSQL scanner"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 40
		date = "12.10.2014"
		id = "77712d29-1a32-59e7-999a-a2ef02212886"

	strings:
		$s0 = {31 00 34 00 33 00 33 00}
		$s1 = {31 00 34 00 33 00 33 00 56 00}
		$s2 = {64 65 6c 20 57 65 61 6b 31 2e 74 78 74}
		$s3 = {64 65 6c 20 41 74 74 61 63 6b 2e 74 78 74}
		$s4 = {64 65 6c 20 2f 73 20 2f 51 20 43 3a 5c 57 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 64 6f 6f 72 73 5c}
		$s5 = {21 26 73 74 61 72 74 20 69 65 78 70 6c 6f 72 65 20 68 74 74 70 3a 2f 2f 77 77 77 2e 63 72 73 6b 79 2e 63 6f 6d 2f 73 6f 66 74 2f 34 38 31 38 2e 68 74 6d 6c 29}

	condition:
		uint16( 0 ) == 0x5a4d and all of ( $s* )
}

rule CN_Hacktool_1433_Scanner_Comp2 : hardened
{
	meta:
		description = "Detects a chinese MSSQL scanner - component 2"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 40
		date = "12.10.2014"
		id = "7d707be5-dad0-5d91-965b-908a8603b6c0"

	strings:
		$s0 = {31 00 34 00 33 00 33 00}
		$s1 = {31 00 34 00 33 00 33 00 56 00}
		$s2 = {55 55 55 4d 55 55 55 66 55 55 55 66 55 55 55 66 55 55 55 66 55 55 55 66 55 55 55 66 55 55 55 66 55 55 55 66 55 55 55 66 55 55 55 66 55 55 55 4d 55 55 55}

	condition:
		uint16( 0 ) == 0x5a4d and all of ( $s* )
}

rule WCE_Modified_1_1014 : hardened
{
	meta:
		description = "Modified (packed) version of Windows Credential Editor"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "09a412ac3c85cedce2642a19e99d8f903a2e0354"
		score = 70
		id = "536d1a7f-bda1-5c22-bf72-a177468e7c42"

	strings:
		$s0 = {4c 53 41 53 53 2e 45 58 45}
		$s1 = {5f 43 52 45 44 53}
		$s9 = {55 73 69 6e 67 20 57 43 45 20}

	condition:
		all of them
}

rule ReactOS_cmd_valid : hardened
{
	meta:
		description = "ReactOS cmd.exe with correct file name - maybe packed with software or part of hacker toolset"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "05.11.14"
		reference = "http://www.elifulkerson.com/articles/suzy-sells-cmd-shells.php"
		score = 30
		hash = "b88f050fa69d85af3ff99af90a157435296cbb6e"
		id = "47df12b4-d202-5520-9c7f-9d0196bc2267"

	strings:
		$s1 = {52 00 65 00 61 00 63 00 74 00 4f 00 53 00 20 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 6f 00 72 00}
		$s2 = {43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 28 00 43 00 29 00 20 00 31 00 39 00 39 00 34 00 2d 00 31 00 39 00 39 00 38 00 20 00 54 00 69 00 6d 00 20 00 4e 00 6f 00 72 00 6d 00 61 00 6e 00 20 00 61 00 6e 00 64 00 20 00 6f 00 74 00 68 00 65 00 72 00 73 00}
		$s3 = {45 00 72 00 69 00 63 00 20 00 4b 00 6f 00 68 00 6c 00 20 00 61 00 6e 00 64 00 20 00 6f 00 74 00 68 00 65 00 72 00 73 00}
		$s4 = {52 00 65 00 61 00 63 00 74 00 4f 00 53 00 20 00 4f 00 70 00 65 00 72 00 61 00 74 00 69 00 6e 00 67 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00}

	condition:
		all of ( $s* )
}

rule iKAT_wmi_rundll : hardened
{
	meta:
		description = "This exe will attempt to use WMI to Call the Win32_Process event to spawn rundll - file wmi_rundll.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "05.11.14"
		score = 65
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		hash = "97c4d4e6a644eed5aa12437805e39213e494d120"
		id = "e3d80c95-d333-53cf-8165-b3a1e66ed00d"

	strings:
		$s0 = {54 68 69 73 20 6f 70 65 72 61 74 69 6e 67 20 73 79 73 74 65 6d 20 69 73 20 6e 6f 74 20 73 75 70 70 6f 72 74 65 64 2e}
		$s1 = {45 72 72 6f 72 21}
		$s2 = {57 69 6e 33 32 20 6f 6e 6c 79 21}
		$s3 = {43 4f 4d 43 54 4c 33 32 2e 64 6c 6c}
		$s4 = {5b 4c 6f 72 64 50 45 5d}
		$s5 = {43 52 54 44 4c 4c 2e 64 6c 6c}
		$s6 = {56 42 53 63 72 69 70 74}
		$s7 = {43 6f 55 6e 69 6e 69 74 69 61 6c 69 7a 65}

	condition:
		all of them and filesize < 15KB
}

rule iKAT_revelations : hardened
{
	meta:
		description = "iKAT hack tool showing the content of password fields - file revelations.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "05.11.14"
		score = 75
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		hash = "c4e217a8f2a2433297961561c5926cbd522f7996"
		id = "c5ef2c2a-c9c0-5c3a-bbcc-0b0949527850"

	strings:
		$s0 = {54 68 65 20 52 65 76 65 6c 61 74 69 6f 6e 48 65 6c 70 65 72 2e 44 4c 4c 20 66 69 6c 65 20 69 73 20 63 6f 72 72 75 70 74 20 6f 72 20 6d 69 73 73 69 6e 67 2e}
		$s8 = {42 00 45 00 54 00 41 00 73 00 75 00 70 00 70 00 6f 00 72 00 74 00 40 00 73 00 6e 00 61 00 64 00 62 00 6f 00 79 00 2e 00 63 00 6f 00 6d 00}
		$s9 = {73 00 75 00 70 00 70 00 6f 00 72 00 74 00 40 00 73 00 6e 00 61 00 64 00 62 00 6f 00 79 00 2e 00 63 00 6f 00 6d 00}
		$s14 = {52 65 76 65 6c 61 74 69 6f 6e 48 65 6c 70 65 72 2e 64 6c 6c}

	condition:
		all of them
}

rule iKAT_priv_esc_tasksch : hardened
{
	meta:
		description = "Task Schedulder Local Exploit - Windows local priv-esc using Task Scheduler, published by webDevil. Supports Windows 7 and Vista."
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "05.11.14"
		score = 75
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		hash = "84ab94bff7abf10ffe4446ff280f071f9702cf8b"
		id = "0786b313-3154-536b-b7eb-c4d8444a309f"

	strings:
		$s0 = {6f 62 6a 53 68 65 6c 6c 2e 52 75 6e 20 22 73 63 68 74 61 73 6b 73 20 2f 63 68 61 6e 67 65 20 2f 54 4e 20 77 44 77 30 30 74 20 2f 64 69 73 61 62 6c 65 22 2c 2c 54 72 75 65}
		$s3 = {6f 62 6a 53 68 65 6c 6c 2e 52 75 6e 20 22 73 63 68 74 61 73 6b 73 20 2f 72 75 6e 20 2f 54 4e 20 77 44 77 30 30 74 22 2c 2c 54 72 75 65}
		$s4 = {27 6f 62 6a 53 68 65 6c 6c 2e 52 75 6e 20 22 63 6d 64 20 2f 63 20 63 6f 70 79 20 43 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 74 61 73 6b 73 5c 77 44 77 30 30 74 20 2e 22 2c 2c 54 72 75 65}
		$s6 = {61 2e 57 72 69 74 65 4c 69 6e 65 20 28 22 73 63 68 74 61 73 6b 73 20 2f 64 65 6c 65 74 65 20 2f 66 20 2f 54 4e 20 77 44 77 30 30 74 22 29}
		$s7 = {61 2e 57 72 69 74 65 4c 69 6e 65 20 28 22 6e 65 74 20 75 73 65 72 20 2f 61 64 64 20 69 6b 61 74 20 69 6b 61 74 22 29}
		$s8 = {61 2e 57 72 69 74 65 4c 69 6e 65 20 28 22 63 6d 64 2e 65 78 65 22 29}
		$s9 = {73 74 72 46 69 6c 65 4e 61 6d 65 3d 22 43 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 74 61 73 6b 73 5c 77 44 77 30 30 74 22}
		$s10 = {46 6f 72 20 6e 20 3d 20 31 20 54 6f 20 28 4c 65 6e 20 28 68 65 78 58 4d 4c 29 20 2d 20 31 29 20 73 74 65 70 20 32}
		$s13 = {6f 75 74 70 75 74 2e 77 72 69 74 65 6c 69 6e 65 20 22 20 53 68 6f 75 6c 64 20 77 6f 72 6b 20 6f 6e 20 56 69 73 74 61 2f 57 69 6e 37 2f 32 30 30 38 20 78 38 36 2f 78 36 34 22}
		$s11 = {53 65 74 20 6f 62 6a 45 78 65 63 4f 62 6a 65 63 74 20 3d 20 6f 62 6a 53 68 65 6c 6c 2e 45 78 65 63 28 22 63 6d 64 20 2f 63 20 73 63 68 74 61 73 6b 73 20 2f 71 75 65 72 79 20 2f 58 4d 4c 20 2f 54 4e 20 77 44 77 30 30 74 22 29}
		$s12 = {6f 62 6a 53 68 65 6c 6c 2e 52 75 6e 20 22 73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 54 4e 20 77 44 77 30 30 74 20 2f 73 63 20 6d 6f 6e 74 68 6c 79 20 2f 74 72 20 22 22 22 2b 62 69 61 74 63 68 46 69 6c 65 2b 22}
		$s14 = {61 2e 57 72 69 74 65 4c 69 6e 65 20 28 22 6e 65 74 20 6c 6f 63 61 6c 67 72 6f 75 70 20 61 64 6d 69 6e 69 73 74 72 61 74 6f 72 73 20 2f 61 64 64 20 76 34 6c 22 29}
		$s20 = {53 65 74 20 74 73 20 3d 20 66 73 6f 2e 63 72 65 61 74 65 74 65 78 74 66 69 6c 65 20 28 22 77 44 77 30 30 74 2e 78 6d 6c 22 29}

	condition:
		2 of them
}

rule iKAT_command_lines_agent : hardened
{
	meta:
		description = "iKAT hack tools set agent - file ikat.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "05.11.14"
		score = 75
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		hash = "c802ee1e49c0eae2a3fc22d2e82589d857f96d94"
		id = "35068d59-272d-55a6-b211-2c138276914c"

	strings:
		$s0 = {45 78 74 65 6e 64 65 64 20 4d 6f 64 75 6c 65 3a 20 73 75 70 65 72 20 6d 61 72 69 6f 20 62 72 6f 74 68 65 72 73}
		$s1 = {45 78 74 65 6e 64 65 64 20 4d 6f 64 75 6c 65 3a 20}
		$s3 = {6f 66 70 75 72 65 6e 6f 73 74 61 6c 67 69 63 66 65 65 6c 69 6e 67}
		$s8 = {2d 73 75 70 65 72 6d 61 72 69 6f 62 72 6f 74 68 65 72 65 74 69 63}
		$s9 = {21 68 74 74 70 3a 2f 2f 31 33 32 2e 31 34 37 2e 39 36 2e 32 30 32 3a 38 30}
		$s12 = {69 4b 41 54 20 45 78 65 20 54 65 6d 70 6c 61 74 65}
		$s15 = {77 69 74 68 61 64 61 6e 63 79 66 6c 61 76 6f 75 72 2e 2e}
		$s16 = {46 61 73 74 54 72 61 63 6b 65 72 20 76 32 2e 30 30 20 20 20}

	condition:
		4 of them
}

rule iKAT_cmd_as_dll : hardened limited
{
	meta:
		description = "iKAT toolset file cmd.dll ReactOS file cloaked"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "05.11.14"
		score = 65
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		hash = "b5d0ba941efbc3b5c97fe70f70c14b2050b8336a"
		id = "8d15b4b6-25f3-556c-bfa8-eba503c9c649"

	strings:
		$s1 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00}
		$s2 = {52 00 65 00 61 00 63 00 74 00 4f 00 53 00 20 00 44 00 65 00 76 00 65 00 6c 00 6f 00 70 00 6d 00 65 00 6e 00 74 00 20 00 54 00 65 00 61 00 6d 00}
		$s3 = {52 00 65 00 61 00 63 00 74 00 4f 00 53 00 20 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 6f 00 72 00}
		$ext = {65 78 74 65 6e 73 69 6f 6e 3a 20 2e 64 6c 6c}

	condition:
		all of ( $s* ) and $ext
}

rule iKAT_tools_nmap : hardened limited
{
	meta:
		description = "Generic rule for NMAP - based on NMAP 4 standalone"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "05.11.14"
		score = 50
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		hash = "d0543f365df61e6ebb5e345943577cc40fca8682"
		id = "be4858e6-a8f3-55eb-9c04-f4def838dde1"

	strings:
		$s0 = {49 00 6e 00 73 00 65 00 63 00 75 00 72 00 65 00 2e 00 4f 00 72 00 67 00}
		$s1 = {43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 28 00 63 00 29 00 20 00 49 00 6e 00 73 00 65 00 63 00 75 00 72 00 65 00 2e 00 43 00 6f 00 6d 00}
		$s2 = {6e 6d 61 70}
		$s3 = {41 72 65 20 79 6f 75 20 61 6c 65 72 74 20 65 6e 6f 75 67 68 20 74 6f 20 62 65 20 75 73 69 6e 67 20 4e 6d 61 70 3f 20 20 48 61 76 65 20 73 6f 6d 65 20 63 6f 66 66 65 65 20 6f 72 20 4a 6f 6c 74 28 74 6d 29 2e}

	condition:
		all of them
}

rule iKAT_startbar : hardened
{
	meta:
		description = "Tool to hide unhide the windows startbar from command line - iKAT hack tools - file startbar.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "05.11.14"
		score = 50
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		hash = "0cac59b80b5427a8780168e1b85c540efffaf74f"
		id = "f29f15e9-aa29-519a-b4ad-c018aac68fd6"

	strings:
		$s2 = {53 68 69 6e 79 73 6f 66 74 20 4c 69 6d 69 74 65 64 31}
		$s3 = {53 68 69 6e 79 73 6f 66 74 20 4c 69 6d 69 74 65 64 30}
		$s4 = {57 65 6c 6c 69 6e 67 74 6f 6e 31}
		$s6 = {57 61 69 6e 75 69 6f 6d 61 74 61 31}
		$s8 = {35 36 20 57 72 69 67 68 74 20 53 74 31}
		$s9 = {55 54 4e 2d 55 53 45 52 46 69 72 73 74 2d 4f 62 6a 65 63 74}
		$s10 = {4e 65 77 20 5a 65 61 6c 61 6e 64 31}

	condition:
		all of them
}

rule iKAT_Tool_Generic : hardened
{
	meta:
		description = "Generic Rule for hack tool iKAT files gpdisable.exe, kitrap0d.exe, uacpoc.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "05.11.14"
		score = 55
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		super_rule = 1
		hash0 = "814c126f21bc5e993499f0c4e15b280bf7c1c77f"
		hash1 = "75f5aed1e719443a710b70f2004f34b2fe30f2a9"
		hash2 = "b65a460d015fd94830d55e8eeaf6222321e12349"
		id = "a8064a26-09c0-59f1-bdf9-628a445014ff"

	strings:
		$s0 = {3c 49 63 6f 6e 46 69 6c 65 3e 43 3a 5c 57 49 4e 44 4f 57 53 5c 41 70 70 2e 69 63 6f 3c 2f 49 63 6f 6e 46 69 6c 65 3e}
		$s1 = {46 61 69 6c 65 64 20 74 6f 20 72 65 61 64 20 74 68 65 20 65 6e 74 69 72 65 20 66 69 6c 65}
		$s4 = {3c 56 65 72 73 69 6f 6e 43 72 65 61 74 65 64 42 79 3e 31 34 2e 34 2e 30 3c 2f 56 65 72 73 69 6f 6e 43 72 65 61 74 65 64 42 79 3e}
		$s8 = {3c 50 72 6f 67 72 65 73 73 43 61 70 74 69 6f 6e 3e 52 75 6e 20 26 71 75 6f 74 3b 65 78 65 63 75 74 6f 72 2e 62 61 74 26 71 75 6f 74 3b 20 6f 6e 63 65 20 74 68 65 20 73 68 65 6c 6c 20 68 61 73 20 73 70 61 77 6e 65 64 2e 3c 2f 50}
		$s9 = {52 75 6e 6e 69 6e 67 20 5a 69 70 20 70 69 70 65 6c 69 6e 65 2e 2e 2e}
		$s10 = {3c 46 69 6e 54 69 74 6c 65 20 2f 3e}
		$s12 = {3c 41 75 74 6f 54 65 6d 70 3e 30 3c 2f 41 75 74 6f 54 65 6d 70 3e}
		$s14 = {3c 44 65 66 61 75 6c 74 44 69 72 3e 25 54 45 4d 50 25 3c 2f 44 65 66 61 75 6c 74 44 69 72 3e}
		$s15 = {41 45 53 20 45 6e 63 72 79 70 74 69 6e 67 2e 2e 2e}
		$s20 = {3c 55 6e 7a 69 70 44 69 72 3e 25 54 45 4d 50 25 3c 2f 55 6e 7a 69 70 44 69 72 3e}

	condition:
		all of them
}

rule BypassUac2 : hardened
{
	meta:
		description = "Auto-generated rule - file BypassUac2.zip"
		author = "yarGen Yara Rule Generator"
		hash = "ef3e7dd2d1384ecec1a37254303959a43695df61"
		id = "8b7e49de-9b0a-5dc4-86af-1a854dc649cc"

	strings:
		$s0 = {2f 42 79 70 61 73 73 55 61 63 2f 42 79 70 61 73 73 55 61 63 2f 42 79 70 61 73 73 55 61 63 5f 55 74 69 6c 73 2e 63 70 70}
		$s1 = {2f 42 79 70 61 73 73 55 61 63 2f 42 79 70 61 73 73 55 61 63 44 6c 6c 2f 42 79 70 61 73 73 55 61 63 44 6c 6c 2e 61 70 73}
		$s3 = {2f 42 79 70 61 73 73 55 61 63 2f 42 79 70 61 73 73 55 61 63 2f 42 79 70 61 73 73 55 61 63 2e 69 63 6f}

	condition:
		all of them
}

rule BypassUac_3 : hardened
{
	meta:
		description = "Auto-generated rule - file BypassUacDll.dll"
		author = "yarGen Yara Rule Generator"
		hash = "1974aacd0ed987119999735cad8413031115ce35"
		id = "407a8e12-1160-584d-94c8-7aa78e29c754"

	strings:
		$s0 = {42 00 79 00 70 00 61 00 73 00 73 00 55 00 61 00 63 00 44 00 4c 00 4c 00 2e 00 64 00 6c 00 6c 00}
		$s1 = {5c 52 65 6c 65 61 73 65 5c 42 79 70 61 73 73 55 61 63 44 6c 6c}
		$s3 = {57 00 69 00 6e 00 37 00 45 00 6c 00 65 00 76 00 61 00 74 00 65 00 44 00 4c 00 4c 00}
		$s7 = {42 00 79 00 70 00 61 00 73 00 73 00 55 00 61 00 63 00 44 00 4c 00 4c 00}

	condition:
		3 of them
}

rule BypassUac_9 : hardened
{
	meta:
		description = "Auto-generated rule - file BypassUac.zip"
		author = "yarGen Yara Rule Generator"
		hash = "93c2375b2e4f75fc780553600fbdfd3cb344e69d"
		id = "a5751d7d-d135-51bc-8351-40374a2d57bf"

	strings:
		$s0 = {2f 78 38 36 2f 42 79 70 61 73 73 55 61 63 2e 65 78 65}
		$s1 = {2f 78 36 34 2f 42 79 70 61 73 73 55 61 63 2e 65 78 65}
		$s2 = {2f 78 38 36 2f 42 79 70 61 73 73 55 61 63 44 6c 6c 2e 64 6c 6c}
		$s3 = {2f 78 36 34 2f 42 79 70 61 73 73 55 61 63 44 6c 6c 2e 64 6c 6c}
		$s15 = {42 79 70 61 73 73 55 61 63}

	condition:
		all of them
}

rule BypassUacDll_6 : hardened
{
	meta:
		description = "Auto-generated rule - file BypassUacDll.aps"
		author = "yarGen Yara Rule Generator"
		hash = "58d7b24b6870cb7f1ec4807d2f77dd984077e531"
		id = "5be27053-446f-5ea3-a242-2661aeffa3df"

	strings:
		$s3 = {42 00 79 00 70 00 61 00 73 00 73 00 55 00 61 00 63 00 44 00 4c 00 4c 00 2e 00 64 00 6c 00 6c 00}
		$s4 = {41 46 58 5f 49 44 50 5f 43 4f 4d 4d 41 4e 44 5f 46 41 49 4c 55 52 45}

	condition:
		all of them
}

rule BypassUac_EXE : hardened
{
	meta:
		description = "Auto-generated rule - file BypassUacDll.aps"
		author = "yarGen Yara Rule Generator"
		hash = "58d7b24b6870cb7f1ec4807d2f77dd984077e531"
		id = "b88aded5-7dfb-5cdf-bb42-cd8b069259e0"

	strings:
		$s1 = {57 00 6f 00 6c 00 65 00 33 00 32 00 2e 00 64 00 6c 00 6c 00}
		$s3 = {53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 6d 00 69 00 67 00 77 00 69 00 7a 00}
		$s4 = {53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 6d 00 69 00 67 00 77 00 69 00 7a 00 5c 00 43 00 52 00 59 00 50 00 54 00 42 00 41 00 53 00 45 00 2e 00 64 00 6c 00 6c 00}
		$s5 = {45 00 6c 00 65 00 76 00 61 00 74 00 69 00 6f 00 6e 00 3a 00 41 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00 21 00 6e 00 65 00 77 00 3a 00}
		$s6 = {42 00 79 00 70 00 61 00 73 00 73 00 55 00 61 00 63 00}

	condition:
		all of them
}

rule APT_Proxy_Malware_Packed_dev : hardened
{
	meta:
		author = "FRoth"
		date = "2014-11-10"
		description = "APT Malware - Proxy"
		hash = "6b6a86ceeab64a6cb273debfa82aec58"
		score = 50
		id = "0b81b6c9-86fa-59c1-b58c-80310f6c0680"

	strings:
		$string0 = {50 45 43 6f 6d 70 61 63 74 32}
		$string1 = {5b 4c 6f 72 64 50 45 5d}
		$string2 = {73 74 65 61 6d 5f 6b 65 72 2e 64 6c 6c}

	condition:
		all of them
}

rule Tzddos_DDoS_Tool_CN : hardened
{
	meta:
		description = "Disclosed hacktool set - file tzddos"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "17.11.14"
		score = 60
		hash = "d4c517eda5458247edae59309453e0ae7d812f8e"
		id = "bf2bfc7b-4db8-5d35-a312-2530a42985d5"

	strings:
		$s0 = {66 6f 72 20 2f 66 20 25 25 61 20 69 6e 20 28 68 6f 73 74 2e 74 78 74 29 20 64 6f 20 28}
		$s1 = {66 6f 72 20 2f 66 20 22 65 6f 6c 3d 53 20 74 6f 6b 65 6e 73 3d 31 20 64 65 6c 69 6d 73 3d 20 22 20 25 25 69 20 69 6e 20 28 73 32 2e 74 78 74 29 20 64 6f 20 65 63 68 6f 20 25 25 69 3e 3e 68 6f 73 74 2e 74 78 74}
		$s2 = {64 65 6c 20 68 6f 73 74 2e 74 78 74 20 2f 71}
		$s3 = {66 6f 72 20 2f 66 20 22 65 6f 6c 3d 2d 20 74 6f 6b 65 6e 73 3d 31 20 64 65 6c 69 6d 73 3d 20 22 20 25 25 69 20 69 6e 20 28 72 65 73 75 6c 74 2e 74 78 74 29 20 64 6f 20 65 63 68 6f 20 25 25 69 3e 3e 73 31 2e 74 78 74}
		$s4 = {73 74 61 72 74 20 48 74 74 70 2e 65 78 65 20 25 25 61 20 25 68 74 74 70 25}
		$s5 = {66 6f 72 20 2f 66 20 22 65 6f 6c 3d 50 20 74 6f 6b 65 6e 73 3d 31 20 64 65 6c 69 6d 73 3d 20 22 20 25 25 69 20 69 6e 20 28 73 31 2e 74 78 74 29 20 64 6f 20 65 63 68 6f 20 25 25 69 3e 3e 73 32 2e 74 78 74}
		$s6 = {64 65 6c 20 52 65 73 75 6c 74 2e 74 78 74 20 73 32 2e 74 78 74 20 73 31 2e 74 78 74 20}

	condition:
		all of them
}

rule Ncat_Hacktools_CN : hardened
{
	meta:
		description = "Disclosed hacktool set - file nc.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "17.11.14"
		score = 60
		hash = "001c0c01c96fa56216159f83f6f298755366e528"
		id = "bdbfaf75-f8c0-508e-b6b1-9ddea179a325"

	strings:
		$s0 = {6e 63 20 2d 6c 20 2d 70 20 70 6f 72 74 20 5b 6f 70 74 69 6f 6e 73 5d 20 5b 68 6f 73 74 6e 61 6d 65 5d 20 5b 70 6f 72 74 5d}
		$s2 = {6e 63 20 5b 2d 6f 70 74 69 6f 6e 73 5d 20 68 6f 73 74 6e 61 6d 65 20 70 6f 72 74 5b 73 5d 20 5b 70 6f 72 74 73 5d 20 2e 2e 2e 20}
		$s3 = {67 65 74 68 6f 73 74 70 6f 6f 70 20 66 75 78 6f 72 65 64}
		$s6 = {56 45 52 4e 4f 54 53 55 50 50 4f 52 54 45 44}
		$s7 = {25 73 20 5b 25 73 5d 20 25 64 20 28 25 73 29}
		$s12 = {20 60 2d 2d 25 73 27 20 64 6f 65 73 6e 27 74 20 61 6c 6c 6f 77 20 61 6e 20 61 72 67 75 6d 65 6e 74}

	condition:
		all of them
}

rule MS08_067_Exploit_Hacktools_CN : hardened
{
	meta:
		description = "Disclosed hacktool set - file cs.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "17.11.14"
		score = 60
		hash = "a3e9e0655447494253a1a60dbc763d9661181322"
		id = "c15836c7-e739-5cc0-9d41-d651ea3e4738"

	strings:
		$s0 = {4d 53 30 38 2d 30 36 37 20 45 78 70 6c 6f 69 74 20 66 6f 72 20 43 4e 20 62 79 20 45 4d 4d 40 70 68 34 6e 74 30 6d 2e 6f 72 67}
		$s3 = {4d 61 6b 65 20 53 4d 42 20 43 6f 6e 6e 65 63 74 69 6f 6e 20 65 72 72 6f 72 3a 25 64}
		$s5 = {53 65 6e 64 20 50 61 79 6c 6f 61 64 20 4f 76 65 72 21}
		$s7 = {4d 61 79 62 65 20 50 61 74 63 68 65 64 21}
		$s8 = {52 70 63 45 78 63 65 70 74 69 6f 6e 43 6f 64 65 28 29 20 3d 20 25 75}
		$s11 = {70 00 68 00 34 00 6e 00 74 00 30 00 6d 00}
		$s12 = {5c 5c 25 73 5c 49 50 43}

	condition:
		4 of them
}

rule Hacktools_CN_Burst_sql : hardened
{
	meta:
		description = "Disclosed hacktool set - file sql.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "17.11.14"
		score = 60
		hash = "d5139b865e99b7a276af7ae11b14096adb928245"
		id = "77ea95fc-7a6a-522b-8a72-1832598c4d2d"

	strings:
		$s0 = {73 2e 65 78 65 20 25 73 20 25 73 20 25 73 20 25 73 20 25 64 20 2f 73 61 76 65}
		$s2 = {73 2e 65 78 65 20 73 74 61 72 74 20 65 72 72 6f 72 2e 2e 2e 25 64}
		$s4 = {45 58 45 43 20 73 70 5f 61 64 64 65 78 74 65 6e 64 65 64 70 72 6f 63 20 78 70 5f 63 6d 64 73 68 65 6c 6c 2c 27 78 70 6c 6f 67 37 30 2e 64 6c 6c 27}
		$s7 = {45 58 45 43 20 6d 61 73 74 65 72 2e 2e 78 70 5f 63 6d 64 73 68 65 6c 6c 20 27 77 73 63 72 69 70 74 2e 65 78 65 20 63 63 2e 6a 73 27}
		$s10 = {52 65 73 75 6c 74 2e 74 78 74}
		$s11 = {55 73 61 67 65 3a 73 71 6c 2e 65 78 65 20 5b 6f 70 74 69 6f 6e 73 5d}
		$s17 = {25 73 20 72 6f 6f 74 20 25 73 20 25 64 20 65 72 72 6f 72}
		$s18 = {50 61 73 73 2e 74 78 74}
		$s20 = {53 45 4c 45 43 54 20 73 69 6c 6c 79 72 5f 61 74 5f 67 6d 61 69 6c 5f 64 6f 74 5f 63 6f 6d 20 49 4e 54 4f 20 44 55 4d 50 46 49 4c 45 20 27 25 73 5c 5c 73 69 6c 6c 79 72 5f 78 2e 73 6f 27 20 46 52 4f 4d 20 73 69 6c 6c 79 72 5f 78}

	condition:
		6 of them
}

rule Hacktools_CN_Panda_445TOOL : hardened
{
	meta:
		description = "Disclosed hacktool set - file 445TOOL.rar"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "17.11.14"
		score = 60
		hash = "92050ba43029f914696289598cf3b18e34457a11"
		id = "02075631-49cc-5b97-ad8e-92d734a26d34"

	strings:
		$s0 = {73 63 61 6e 2e 62 61 74}
		$s1 = {48 74 74 70 2e 65 78 65}
		$s2 = {47 4f 47 4f 47 4f 2e 62 61 74}
		$s3 = {69 70 2e 74 78 74}

	condition:
		all of them
}

rule Hacktools_CN_Panda_445 : hardened
{
	meta:
		description = "Disclosed hacktool set - file 445.rar"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "17.11.14"
		score = 60
		hash = "a61316578bcbde66f39d88e7fc113c134b5b966b"
		id = "02075631-49cc-5b97-ad8e-92d734a26d34"

	strings:
		$s0 = {66 6f 72 20 2f 66 20 25 25 69 20 69 6e 20 28 69 70 73 2e 74 78 74 29 20 64 6f 20 28 73 74 61 72 74 20 63 6d 64 2e 62 61 74 20 25 25 69 29}
		$s1 = {34 34 35 5c 6e 63 2e 65 78 65}
		$s2 = {34 34 35 5c 73 2e 65 78 65}
		$s3 = {63 73 2e 65 78 65 20 25 31}
		$s4 = {34 34 35 5c 63 73 2e 65 78 65}
		$s5 = {34 34 35 5c 69 70 2e 74 78 74}
		$s6 = {34 34 35 5c 63 6d 64 2e 62 61 74}
		$s9 = {40 65 63 68 6f 20 6f 66 66}

	condition:
		all of them
}

rule Hacktools_CN_WinEggDrop : hardened
{
	meta:
		description = "Disclosed hacktool set - file s.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "17.11.14"
		score = 60
		hash = "7665011742ce01f57e8dc0a85d35ec556035145d"
		id = "9b6244ee-5ace-5caa-bfa2-732bcfcfc998"

	strings:
		$s0 = {4e 6f 72 6d 61 6c 20 53 63 61 6e 3a 20 41 62 6f 75 74 20 54 6f 20 53 63 61 6e 20 25 75 20 49 50 20 46 6f 72 20 25 75 20 50 6f 72 74 73 20 55 73 69 6e 67 20 25 64 20 54 68 72 65 61 64}
		$s2 = {53 59 4e 20 53 63 61 6e 3a 20 41 62 6f 75 74 20 54 6f 20 53 63 61 6e 20 25 75 20 49 50 20 46 6f 72 20 25 75 20 50 6f 72 74 73 20 55 73 69 6e 67 20 25 64 20 54 68 72 65 61 64}
		$s6 = {45 78 61 6d 70 6c 65 3a 20 25 73 20 54 43 50 20 31 32 2e 31 32 2e 31 32 2e 31 32 20 31 32 2e 31 32 2e 31 32 2e 32 35 34 20 32 31 20 35 31 32 20 2f 42 61 6e 6e 65 72}
		$s8 = {53 6f 6d 65 74 68 69 6e 67 20 57 72 6f 6e 67 20 41 62 6f 75 74 20 54 68 65 20 50 6f 72 74 73}
		$s9 = {50 65 72 66 6f 72 6d 69 6e 67 20 54 69 6d 65 3a 20 25 64 2f 25 64 2f 25 64 20 25 64 3a 25 64 3a 25 64 20 2d 2d 3e 20}
		$s10 = {45 78 61 6d 70 6c 65 3a 20 25 73 20 54 43 50 20 31 32 2e 31 32 2e 31 32 2e 31 32 2f 32 34 20 38 30 20 35 31 32 20 2f 54 38 20 2f 53 61 76 65}
		$s12 = {25 75 20 50 6f 72 74 73 20 53 63 61 6e 6e 65 64 2e 54 61 6b 69 6e 67 20 25 64 20 54 68 72 65 61 64 73 20}
		$s13 = {25 2d 31 36 73 20 25 2d 35 64 20 2d 3e 20 22 25 73 22}
		$s14 = {53 59 4e 20 53 63 61 6e 20 43 61 6e 20 4f 6e 6c 79 20 50 65 72 66 6f 72 6d 20 4f 6e 20 57 49 4e 20 32 4b 20 4f 72 20 41 62 6f 76 65}
		$s17 = {53 59 4e 20 53 63 61 6e 3a 20 41 62 6f 75 74 20 54 6f 20 53 63 61 6e 20 25 73 3a 25 64 20 55 73 69 6e 67 20 25 64 20 54 68 72 65 61 64}
		$s18 = {53 63 61 6e 20 25 73 20 43 6f 6d 70 6c 65 74 65 20 49 6e 20 25 64 20 48 6f 75 72 73 20 25 64 20 4d 69 6e 75 74 65 73 20 25 64 20 53 65 63 6f 6e 64 73 2e 20 46 6f 75 6e 64 20 25 75 20 4f 70 65 6e 20 50 6f 72 74 73}

	condition:
		5 of them
}

rule Hacktools_CN_Scan_BAT : hardened
{
	meta:
		description = "Disclosed hacktool set - file scan.bat"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "17.11.14"
		score = 60
		hash = "6517d7c245f1300e42f7354b0fe5d9666e5ce52a"
		id = "836e0618-93c7-5519-bbc4-705ff5c2e127"

	strings:
		$s0 = {66 6f 72 20 2f 66 20 25 25 61 20 69 6e 20 28 68 6f 73 74 2e 74 78 74 29 20 64 6f 20 28}
		$s1 = {66 6f 72 20 2f 66 20 22 65 6f 6c 3d 53 20 74 6f 6b 65 6e 73 3d 31 20 64 65 6c 69 6d 73 3d 20 22 20 25 25 69 20 69 6e 20 28 73 32 2e 74 78 74 29 20 64 6f 20 65 63 68 6f 20 25 25 69 3e 3e 68 6f 73 74 2e 74 78 74}
		$s2 = {64 65 6c 20 68 6f 73 74 2e 74 78 74 20 2f 71}
		$s3 = {66 6f 72 20 2f 66 20 22 65 6f 6c 3d 2d 20 74 6f 6b 65 6e 73 3d 31 20 64 65 6c 69 6d 73 3d 20 22 20 25 25 69 20 69 6e 20 28 72 65 73 75 6c 74 2e 74 78 74 29 20 64 6f 20 65 63 68 6f 20 25 25 69 3e 3e 73 31 2e 74 78 74}
		$s4 = {73 74 61 72 74 20 48 74 74 70 2e 65 78 65 20 25 25 61 20 25 68 74 74 70 25}
		$s5 = {66 6f 72 20 2f 66 20 22 65 6f 6c 3d 50 20 74 6f 6b 65 6e 73 3d 31 20 64 65 6c 69 6d 73 3d 20 22 20 25 25 69 20 69 6e 20 28 73 31 2e 74 78 74 29 20 64 6f 20 65 63 68 6f 20 25 25 69 3e 3e 73 32 2e 74 78 74}

	condition:
		5 of them
}

rule Hacktools_CN_Panda_Burst : hardened
{
	meta:
		description = "Disclosed hacktool set - file Burst.rar"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "17.11.14"
		score = 60
		hash = "ce8e3d95f89fb887d284015ff2953dbdb1f16776"
		id = "e07c66d1-958e-5ad2-9d5b-380d48af8360"

	strings:
		$s0 = {40 73 71 6c 2e 65 78 65 20 2d 66 20 69 70 2e 74 78 74 20 2d 6d 20 73 79 6e 20 2d 74 20 33 33 30 36 20 2d 63 20 35 30 30 30 20 2d 75 20 68 74 74 70 3a 2f 2f 36 30 2e 31 35 2e 31 32 34 2e 31 30 36 3a 36 33 33 38 39 2f 74 61 73 6b 73 76 72 2e}

	condition:
		all of them
}

rule Hacktools_CN_445_cmd : hardened
{
	meta:
		description = "Disclosed hacktool set - file cmd.bat"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "17.11.14"
		score = 60
		hash = "69b105a3aec3234819868c1a913772c40c6b727a"
		id = "b9693f51-26ac-5bf1-8c4d-ca852a154636"

	strings:
		$bat = {40 65 63 68 6f 20 6f 66 66}
		$s0 = {63 73 2e 65 78 65 20 25 31}
		$s2 = {6e 63 20 25 31 20 34 34 34 34}

	condition:
		uint32( 0 ) == 0x68636540 and $bat at 0 and all of ( $s* )
}

rule Hacktools_CN_GOGOGO_Bat : hardened
{
	meta:
		description = "Disclosed hacktool set - file GOGOGO.bat"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "17.11.14"
		score = 60
		hash = "4bd4f5b070acf7fe70460d7eefb3623366074bbd"
		id = "b52cc150-81d4-5895-8f83-ee2006f75617"

	strings:
		$s0 = {66 6f 72 20 2f 66 20 22 64 65 6c 69 6d 73 3d 22 20 25 25 78 20 69 6e 20 28 65 6e 64 65 6e 64 2e 74 78 74 29 20 64 6f 20 63 61 6c 6c 20 3a 6c 69 73 6f 6f 62 20 25 25 78}
		$s1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 74 7a 64 64 6f 73 2e 63 6f 6d 2f 20 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 3e 62 79 65 62 79 65 2e 74 78 74}
		$s2 = {72 65 6e 20 25 73 79 73 74 65 6d 72 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 74 63 70 69 70 2e 73 79 73 20 74 63 70 69 70 2e 73 79 73 2e 62 61 6b}
		$s4 = {49 46 20 2f 49 20 22 25 77 61 6e 67 6c 65 25 22 3d 3d 22 22 20 28 20 67 6f 74 6f 20 73 74 61 72 74 20 29 20 65 6c 73 65 20 28 20 67 6f 74 6f 20 65 72 72 6f 6d 6d 20 29}
		$s5 = {63 6f 70 79 20 2a 2e 74 7a 64 64 6f 73 20 73 63 61 6e 2e 62 61 74 26 64 65 6c 20 2a 2e 74 7a 64 64 6f 73}
		$s6 = {64 65 6c 20 2f 66 20 74 63 70 69 70 2e 73 79 73}
		$s9 = {69 66 20 2f 69 20 22 25 43 42 25 22 3d 3d 22 77 77 77 2e 74 7a 64 64 6f 73 2e 63 6f 6d 22 20 28 20 67 6f 74 6f 20 6d 6d 62 61 74 20 29 20 65 6c 73 65 20 28 20 67 6f 74 6f 20 77 61 6e 67 6c 65 20 29}
		$s10 = {63 61 6c 6c 20 73 63 61 6e 2e 62 61 74}
		$s12 = {49 46 20 2f 49 20 22 25 65 72 72 6f 6d 6d 25 22 3d 3d 22 22 20 28 20 67 6f 74 6f 20 73 74 61 72 74 20 29 20 65 6c 73 65 20 28 20 67 6f 74 6f 20 7a 75 69 68 6f 75 6a 68 20 29}
		$s13 = {49 46 20 2f 49 20 22 25 7a 75 69 68 6f 75 6a 68 25 22 3d 3d 22 22 20 28 20 67 6f 74 6f 20 73 74 61 72 74 20 29 20 65 6c 73 65 20 28 20 67 6f 74 6f 20 6c 61 6a 69 20 29}
		$s18 = {73 63 20 63 6f 6e 66 69 67 20 4c 6d 48 6f 73 74 73 20 73 74 61 72 74 3d 20 61 75 74 6f}
		$s19 = {63 6f 70 79 20 74 63 70 69 70 2e 73 79 73 20 25 73 79 73 74 65 6d 72 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 74 63 70 69 70 2e 73 79 73 20 3e 20 6e 75 6c}
		$s20 = {72 65 6e 20 25 73 79 73 74 65 6d 72 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 64 6c 6c 63 61 63 68 65 5c 74 63 70 69 70 2e 73 79 73 20 74 63 70 69 70 2e 73 79 73 2e 62 61 6b}

	condition:
		3 of them
}

rule Hacktools_CN_Burst_pass : hardened
{
	meta:
		description = "Disclosed hacktool set - file pass.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "17.11.14"
		score = 60
		hash = "55a05cf93dbd274355d798534be471dff26803f9"
		id = "d8f6784f-80c8-51e2-9d86-40022cd8705d"

	strings:
		$s0 = {31 32 33 34 35 36 2e 63 6f 6d}
		$s1 = {31 32 33 31 32 33 2e 63 6f 6d}
		$s2 = {33 36 30 2e 63 6f 6d}
		$s3 = {31 32 33 2e 63 6f 6d}
		$s4 = {6a 75 73 6f 2e 63 6f 6d}
		$s5 = {73 69 6e 61 2e 63 6f 6d}
		$s7 = {63 68 61 6e 67 65 6d 65}
		$s8 = {6d 61 73 74 65 72}
		$s9 = {67 6f 6f 67 6c 65 2e 63 6f 6d}
		$s10 = {63 68 69 6e 61 6e 65 74}
		$s12 = {6c 69 6f 6e 6b 69 6e 67}

	condition:
		all of them
}

rule Hacktools_CN_JoHor_Posts_Killer : hardened
{
	meta:
		description = "Disclosed hacktool set - file JoHor_Posts_Killer.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "17.11.14"
		score = 60
		hash = "d157f9a76f9d72dba020887d7b861a05f2e56b6a"
		id = "68bba78e-f3a0-5eaa-9c63-e5f23a76b328"

	strings:
		$s0 = {4d 75 6c 74 69 74 68 72 65 61 64 69 6e 67 20 50 6f 73 74 73 5f 53 65 6e 64 20 4b 69 6c 6c 65 72}
		$s3 = {47 45 54 20 5b 41 63 63 65 73 73 20 50 6f 69 6e 74 5d 20 48 54 54 50 2f 31 2e 31}
		$s6 = {54 68 65 20 70 72 6f 67 72 61 6d 27 73 20 6e 65 65 64 20 66 69 6c 65 73 20 77 61 73 20 6e 6f 74 20 65 78 69 73 74 21}
		$s7 = {4a 00 6f 00 48 00 6f 00 72 00 5f 00 50 00 6f 00 73 00 74 00 73 00 5f 00 4b 00 69 00 6c 00 6c 00 65 00 72 00}
		$s8 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 36 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 31 3b 20 53 56 31 29}
		$s10 = {20 20 28 20 2f 73 20 29 20 3a}
		$s11 = {66 6f 72 6d 73 2e 76 62 70}
		$s12 = {66 6f 72 6d 73 2e 76 63 70}
		$s13 = {53 6f 66 74 77 61 72 65 5c 46 6c 79 53 6b 79 5c 45 5c 49 6e 73 74 61 6c 6c}

	condition:
		5 of them
}

rule Hacktools_CN_Panda_tesksd : hardened
{
	meta:
		description = "Disclosed hacktool set - file tesksd.jpg"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "17.11.14"
		score = 60
		hash = "922147b3e1e6cf1f5dd5f64a4e34d28bdc9128cb"
		id = "399ff307-c2e8-57bb-b792-a2c599e8686e"

	strings:
		$s0 = {6e 61 6d 65 3d 22 4d 69 63 72 6f 73 6f 66 74 2e 57 69 6e 64 6f 77 73 2e 43 6f 6d 6d 6f 6e 2d 43 6f 6e 74 72 6f 6c 73 22 20}
		$s1 = {45 00 78 00 65 00 4d 00 69 00 6e 00 69 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 2e 00 65 00 78 00 65 00}
		$s16 = {50 4f 53 54 20 25 48 73}

	condition:
		all of them
}

rule Hacktools_CN_Http : hardened
{
	meta:
		description = "Disclosed hacktool set - file Http.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "17.11.14"
		score = 60
		hash = "788bf0fdb2f15e0c628da7056b4e7b1a66340338"
		id = "bbff6ff6-8cef-5a83-afd3-34f306e8e715"

	strings:
		$s0 = {52 50 43 52 54 34 2e 44 4c 4c}
		$s1 = {57 4e 65 74 41 64 64 43 6f 6e 6e 65 63 74 69 6f 6e 32 41}
		$s2 = {4e 64 72 50 6f 69 6e 74 65 72 42 75 66 66 65 72 53 69 7a 65}
		$s3 = {5f 63 6f 6e 74 72 6f 6c 66 70}

	condition:
		all of them and filesize < 10KB
}

rule Hacktools_CN_Burst_Start : hardened
{
	meta:
		description = "Disclosed hacktool set - file Start.bat - DoS tool"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014-11-17"
		modified = "2023-01-27"
		score = 60
		hash = "75d194d53ccc37a68286d246f2a84af6b070e30c"
		id = "1291fbc5-fbb3-5425-bb9a-e45f4d7cf562"

	strings:
		$s0 = {66 6f 72 20 2f 66 20 22 65 6f 6c 3d 20 74 6f 6b 65 6e 73 3d 31 2c 32 20 64 65 6c 69 6d 73 3d 20 22 20 25 25 69 20 69 6e 20 28 69 70 2e 74 78 74 29 20 64 6f 20 28}
		$s1 = {42 6c 61 73 74 2e 62 61 74 20 2f 72 20 36 30 30}
		$s2 = {42 6c 61 73 74 2e 62 61 74 20 2f 6c 20 42 6c 61 73 74 2e 62 61 74}
		$s3 = {42 6c 61 73 74 2e 62 61 74 20 2f 63 20 36 30 30}
		$s4 = {73 74 61 72 74 20 43 6c 65 61 72 2e 62 61 74}
		$s5 = {64 65 6c 20 52 65 73 75 6c 74 2e 74 78 74}
		$s6 = {73 20 73 79 6e 20 25 25 69 20 25 25 6a 20 33 33 30 36 20 2f 73 61 76 65}
		$s7 = {73 74 61 72 74 20 54 68 65 63 61 72 64 2e 62 61 74}
		$s10 = {73 65 74 6c 6f 63 61 6c 20 65 6e 61 62 6c 65 64 65 6c 61 79 65 64 65 78 70 61 6e 73 69 6f 6e}

	condition:
		5 of them
}

rule Hacktools_CN_Panda_tasksvr : hardened
{
	meta:
		description = "Disclosed hacktool set - file tasksvr.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "17.11.14"
		score = 60
		hash = "a73fc74086c8bb583b1e3dcfd326e7a383007dc0"
		id = "5c85b382-551a-5e9e-9af8-d106cbe26f74"

	strings:
		$s2 = {43 6f 6e 73 79 73 32 31 2e 64 6c 6c}
		$s4 = {33 00 36 00 30 00 45 00 6e 00 74 00 43 00 61 00 6c 00 6c 00 2e 00 65 00 78 00 65 00}
		$s15 = {42 65 69 6a 69 6e 67 31}

	condition:
		all of them
}

rule Hacktools_CN_Burst_Clear : hardened
{
	meta:
		description = "Disclosed hacktool set - file Clear.bat"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "17.11.14"
		score = 60
		hash = "148c574a4e6e661aeadaf3a4c9eafa92a00b68e4"
		id = "21f33a36-779e-5eac-819c-ef79f291b43c"

	strings:
		$s0 = {64 65 6c 20 2f 66 20 2f 73 20 2f 71 20 25 73 79 73 74 65 6d 64 72 69 76 65 25 5c 2a 2e 6c 6f 67 20 20 20 20}
		$s1 = {64 65 6c 20 2f 66 20 2f 73 20 2f 71 20 25 77 69 6e 64 69 72 25 5c 2a 2e 62 61 6b 20 20 20 20}
		$s4 = {64 65 6c 20 2f 66 20 2f 73 20 2f 71 20 25 73 79 73 74 65 6d 64 72 69 76 65 25 5c 2a 2e 63 68 6b 20 20 20 20}
		$s5 = {64 65 6c 20 2f 66 20 2f 73 20 2f 71 20 25 73 79 73 74 65 6d 64 72 69 76 65 25 5c 2a 2e 74 6d 70 20 20 20 20}
		$s8 = {64 65 6c 20 2f 66 20 2f 71 20 25 75 73 65 72 70 72 6f 66 69 6c 65 25 5c 43 4f 4f 4b 49 45 53 20 73 5c 2a 2e 2a 20 20 20 20}
		$s9 = {72 64 20 2f 73 20 2f 71 20 25 77 69 6e 64 69 72 25 5c 74 65 6d 70 20 26 20 6d 64 20 25 77 69 6e 64 69 72 25 5c 74 65 6d 70 20 20 20 20}
		$s11 = {64 65 6c 20 2f 66 20 2f 73 20 2f 71 20 25 73 79 73 74 65 6d 64 72 69 76 65 25 5c 72 65 63 79 63 6c 65 64 5c 2a 2e 2a 20 20 20 20}
		$s12 = {64 65 6c 20 2f 66 20 2f 73 20 2f 71 20 22 25 75 73 65 72 70 72 6f 66 69 6c 65 25 5c 4c 6f 63 61 6c 20 53 65 74 74 69 6e 67 73 5c 54 65 6d 70 5c 2a 2e 2a 22 20 20 20 20}
		$s19 = {64 65 6c 20 2f 66 20 2f 73 20 2f 71 20 22 25 75 73 65 72 70 72 6f 66 69 6c 65 25 5c 4c 6f 63 61 6c 20 53 65 74 74 69 6e 67 73 5c 54 65 6d 70 6f 72 61 72 79 20 49 6e 74 65 72 6e 65 74 20 46 69 6c 65 73 5c 2a 2e 2a 22 20 20 20}

	condition:
		5 of them
}

rule Hacktools_CN_Burst_Thecard : hardened
{
	meta:
		description = "Disclosed hacktool set - file Thecard.bat"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "17.11.14"
		score = 60
		hash = "50b01ea0bfa5ded855b19b024d39a3d632bacb4c"
		id = "a9946aeb-2042-522f-8d91-f8b96341bb64"

	strings:
		$s0 = {74 61 73 6b 6c 69 73 74 20 7c 66 69 6e 64 20 22 43 6c 65 61 72 2e 62 61 74 22 7c 7c 73 74 61 72 74 20 43 6c 65 61 72 2e 62 61 74}
		$s1 = {48 74 74 70 3a 2f 2f 77 77 77 2e 63 6f 66 66 65 65 77 6c 2e 63 6f 6d}
		$s2 = {70 69 6e 67 20 2d 6e 20 32 20 6c 6f 63 61 6c 68 6f 73 74 20 31 3e 6e 75 6c 20 32 3e 6e 75 6c}
		$s3 = {66 6f 72 20 2f 4c 20 25 25 61 20 69 6e 20 28}
		$s4 = {4d 4f 44 45 20 63 6f 6e 3a 20 43 4f 4c 53 3d 34 32 20 6c 69 6e 65 73 3d 35}

	condition:
		all of them
}

rule Hacktools_CN_Burst_Blast : hardened
{
	meta:
		description = "Disclosed hacktool set - file Blast.bat"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "17.11.14"
		score = 60
		hash = "b07702a381fa2eaee40b96ae2443918209674051"
		id = "9ac723c4-e88d-5fb3-b18f-c8b764c8acf3"

	strings:
		$s0 = {40 73 71 6c 2e 65 78 65 20 2d 66 20 69 70 2e 74 78 74 20 2d 6d 20 73 79 6e 20 2d 74 20 33 33 30 36 20 2d 63 20 35 30 30 30 20 2d 75 20 68 74 74 70 3a}
		$s1 = {40 65 63 68 6f 20 6f 66 66}

	condition:
		all of them
}

rule VUBrute_VUBrute : hardened
{
	meta:
		description = "PoS Scammer Toolbox - http://goo.gl/xiIphp - file VUBrute.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "22.11.14"
		score = 70
		hash = "166fa8c5a0ebb216c832ab61bf8872da556576a7"
		id = "7ac74c85-465c-5eb5-8e91-004f28cabb75"

	strings:
		$s0 = {54 65 78 74 20 46 69 6c 65 73 20 28 2a 2e 74 78 74 29 3b 3b 41 6c 6c 20 46 69 6c 65 73 20 28 2a 29}
		$s1 = {68 74 74 70 3a 2f 2f 75 62 72 75 74 65 2e 63 6f 6d}
		$s11 = {49 50 20 2d 20 25 64 3b 20 50 61 73 73 77 6f 72 64 20 2d 20 25 64 3b 20 43 6f 6d 62 69 6e 61 74 69 6f 6e 20 2d 20 25 64}
		$s14 = {65 72 72 6f 72 2e 74 78 74}

	condition:
		all of them
}

rule DK_Brute : hardened
{
	meta:
		description = "PoS Scammer Toolbox - http://goo.gl/xiIphp - file DK Brute.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "22.11.14"
		score = 70
		reference = "http://goo.gl/xiIphp"
		hash = "93b7c3a01c41baecfbe42461cb455265f33fbc3d"
		id = "c9ea0dcf-10f3-5161-aebc-2db04c24b0a5"

	strings:
		$s6 = {67 65 74 5f 43 72 61 63 6b 65 64 43 72 65 64 65 6e 74 69 61 6c 73}
		$s13 = {53 00 61 00 6d 00 65 00 20 00 70 00 6f 00 72 00 74 00 20 00 75 00 73 00 65 00 64 00 20 00 66 00 6f 00 72 00 20 00 74 00 77 00 6f 00 20 00 64 00 69 00 66 00 66 00 65 00 72 00 65 00 6e 00 74 00 20 00 70 00 72 00 6f 00 74 00 6f 00 63 00 6f 00 6c 00 73 00 3a 00}
		$s18 = {63 6f 64 65 64 20 62 79 20 66 4c 61 53 68}
		$s19 = {67 65 74 5f 67 72 62 54 6f 6f 6c 73 53 63 61 6e 69 6e 67 43 72 61 63 6b 69 6e 67}

	condition:
		all of them
}

rule VUBrute_config : hardened
{
	meta:
		description = "PoS Scammer Toolbox - http://goo.gl/xiIphp - file config.ini"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "22.11.14"
		score = 70
		reference = "http://goo.gl/xiIphp"
		hash = "b9f66b9265d2370dab887604921167c11f7d93e9"
		id = "25cad108-b2d6-5886-bb2f-e614e05649fa"

	strings:
		$s2 = {52 65 73 74 6f 72 65 3d 31}
		$s6 = {54 68 72 65 61 64 3d}
		$s7 = {52 75 6e 6e 69 6e 67 3d 31}
		$s8 = {43 68 65 63 6b 43 6f 6d 62 69 6e 61 74 69 6f 6e 3d}
		$s10 = {41 75 74 6f 53 61 76 65 3d 31 2e 30 30 30 30 30 30}
		$s12 = {54 72 79 43 6f 6e 6e 65 63 74 3d}
		$s13 = {54 72 61 79 3d}

	condition:
		all of them
}

rule sig_238_hunt : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file hunt.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "f9f059380d95c7f8d26152b1cb361d93492077ca"
		id = "5d9d1f99-2f12-51e9-a554-b349e19d00fb"

	strings:
		$s1 = {50 72 6f 67 72 61 6d 6d 69 6e 67 20 62 79 20 4a 44 20 47 6c 61 73 65 72 20 2d 20 41 6c 6c 20 52 69 67 68 74 73 20 52 65 73 65 72 76 65 64}
		$s3 = {55 73 61 67 65 20 2d 20 68 75 6e 74 20 5c 5c 73 65 72 76 65 72 6e 61 6d 65}
		$s4 = {2e 00 73 00 68 00 61 00 72 00 65 00 20 00 3d 00 20 00 25 00 53 00 20 00 2d 00 20 00 25 00 53 00}
		$s5 = {53 4d 42 20 73 68 61 72 65 20 65 6e 75 6d 65 72 61 74 6f 72 20 61 6e 64 20 61 64 6d 69 6e 20 66 69 6e 64 65 72 20}
		$s7 = {48 75 6e 74 20 6f 6e 6c 79 20 72 75 6e 73 20 6f 6e 20 57 69 6e 64 6f 77 73 20 4e 54 2e 2e 2e}
		$s8 = {55 73 65 72 20 3d 20 25 53}
		$s9 = {41 64 6d 69 6e 20 69 73 20 25 73 5c 25 73}

	condition:
		all of them
}

rule sig_238_listip : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file listip.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "f32a0c5bf787c10eb494eb3b83d0c7a035e7172b"
		id = "417faf20-ee07-5c3e-bfcf-89599e38e62e"

	strings:
		$s0 = {45 52 52 4f 52 21 21 21 20 42 61 64 20 68 6f 73 74 20 6c 6f 6f 6b 75 70 2e 20 50 72 6f 67 72 61 6d 20 54 65 72 6d 69 6e 61 74 65 2e}
		$s2 = {45 52 52 4f 52 20 4e 6f 2e 32 21 21 21 20 50 72 6f 67 72 61 6d 20 54 65 72 6d 69 6e 61 74 65 2e}
		$s4 = {4c 6f 63 61 6c 20 48 6f 73 74 20 4e 61 6d 65 3a 20 25 73}
		$s5 = {50 61 63 6b 65 64 20 62 79 20 65 78 65 33 32 70 61 63 6b 20 31 2e 33 38}
		$s7 = {4c 6f 63 61 6c 20 43 6f 6d 70 75 74 65 72 20 4e 61 6d 65 3a 20 25 73}
		$s8 = {4c 6f 63 61 6c 20 49 50 20 41 64 72 65 73 73 3a 20 25 73}

	condition:
		all of them
}

rule ArtTrayHookDll : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file ArtTrayHookDll.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "4867214a3d96095d14aa8575f0adbb81a9381e6c"
		id = "324561fc-024c-5583-aa25-6b13e9616898"

	strings:
		$s0 = {41 72 74 54 72 61 79 48 6f 6f 6b 44 6c 6c 2e 64 6c 6c}
		$s7 = {3f 54 65 72 6d 69 6e 61 74 65 48 6f 6f 6b 40 40 59 41 58 58 5a}

	condition:
		all of them
}

rule sig_238_eee : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file eee.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "236916ce2980c359ff1d5001af6dacb99227d9cb"
		id = "9d3ad3a9-0498-5ca3-ac19-f250cb10c4d3"

	strings:
		$s0 = {73 00 7a 00 6a 00 31 00 32 00 33 00 30 00 40 00 79 00 65 00 73 00 6b 00 79 00 2e 00 63 00 6f 00 6d 00}
		$s3 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 44 65 76 53 74 75 64 69 6f 5c 56 42 5c 56 42 35 2e 4f 4c 42}
		$s4 = {4d 00 61 00 69 00 6c 00 54 00 6f 00 3a 00 73 00 7a 00 6a 00 31 00 32 00 33 00 30 00 40 00 79 00 65 00 73 00 6b 00 79 00 2e 00 63 00 6f 00 6d 00}
		$s5 = {43 6f 6d 6d 61 6e 64 31 5f 43 6c 69 63 6b}
		$s7 = {73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 69 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5c 00 74 00 79 00 70 00 65 00 64 00 75 00 72 00 6c 00 73 00}
		$s11 = {76 62 35 63 68 73 2e 64 6c 6c}
		$s12 = {4d 53 56 42 56 4d 35 30 2e 44 4c 4c}

	condition:
		all of them
}

rule aspbackdoor_asp4 : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file asp4.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "faf991664fd82a8755feb65334e5130f791baa8c"
		id = "7718aa71-fc0f-505c-a035-b78ae0438653"

	strings:
		$s0 = {73 79 73 74 65 6d 2e 64 6c 6c}
		$s2 = {73 65 74 20 73 79 73 3d 73 65 72 76 65 72 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 20 28 22 73 79 73 74 65 6d 2e 63 6f 6e 74 72 61 6c 22 29 20}
		$s3 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 72 65 62 6f 6f 74 28 61 74 79 70 65 20 41 73 20 56 61 72 69 61 6e 74 29}
		$s4 = {74 26 20 3d 20 45 78 69 74 57 69 6e 64 6f 77 73 45 78 28 31 2c 20 61 74 79 70 65 29}
		$s5 = {61 74 79 70 65 3d 72 65 71 75 65 73 74 28 22 61 74 79 70 65 22 29 20}
		$s7 = {41 63 65 69 76 65 58 20 64 6c 6c}
		$s8 = {44 65 63 6c 61 72 65 20 46 75 6e 63 74 69 6f 6e 20 45 78 69 74 57 69 6e 64 6f 77 73 45 78 20 4c 69 62 20 22 75 73 65 72 33 32 22 20 28 42 79 56 61 6c 20 75 46 6c 61 67 73 20 41 73 20 4c 6f 6e 67 2c 20 42 79 56 61 6c 20}
		$s10 = {73 79 73 2e 72 65 62 6f 6f 74 28 61 74 79 70 65 29}

	condition:
		all of them
}

rule aspfile1 : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file aspfile1.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "77b1e3a6e8f67bd6d16b7ace73dca383725ac0af"
		id = "1b66dec0-22c8-5937-a0b2-22cbc68241ef"

	strings:
		$s0 = {27 20 2d 2d 20 63 68 65 63 6b 20 66 6f 72 20 61 20 63 6f 6d 6d 61 6e 64 20 74 68 61 74 20 77 65 20 68 61 76 65 20 70 6f 73 74 65 64 20 2d 2d 20 27}
		$s1 = {73 7a 54 65 6d 70 46 69 6c 65 20 3d 20 22 43 3a 5c 5c 22 20 26 20 6f 46 69 6c 65 53 79 73 2e 47 65 74 54 65 6d 70 4e 61 6d 65 28 20 29}
		$s5 = {3c 6d 65 74 61 20 68 74 74 70 2d 65 71 75 69 76 3d 22 43 6f 6e 74 65 6e 74 2d 54 79 70 65 22 20 63 6f 6e 74 65 6e 74 3d 22 74 65 78 74 2f 68 74 6d 6c 3b 20 63 68 61 72 73 65 74 3d 67 62 32 33 31 32 22 3e 3c 42 4f 44 59 3e}
		$s6 = {3c 69 6e 70 75 74 20 74 79 70 65 3d 74 65 78 74 20 6e 61 6d 65 3d 22 2e 43 4d 44 22 20 73 69 7a 65 3d 34 35 20 76 61 6c 75 65 3d 22 3c 25 3d 20 73 7a 43 4d 44 20 25 3e 22 3e}
		$s8 = {43 61 6c 6c 20 6f 53 63 72 69 70 74 2e 52 75 6e 20 28 22 63 6d 64 2e 65 78 65 20 2f 63 20 22 20 26 20 73 7a 43 4d 44 20 26 20 22 20 3e 20 22 20 26 20 73 7a 54 65 6d 70 46 69 6c 65 2c 20 30 2c 20 54 72 75 65 29}
		$s15 = {73 7a 43 4d 44 20 3d 20 52 65 71 75 65 73 74 2e 46 6f 72 6d 28 22 2e 43 4d 44 22 29}

	condition:
		3 of them
}

rule EditServer : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file EditServer.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "87b29c9121cac6ae780237f7e04ee3bc1a9777d3"
		id = "de6bf995-1c7c-561f-98df-e8748d5fb157"

	strings:
		$s0 = {25 73 20 53 65 72 76 65 72 2e 65 78 65}
		$s1 = {53 65 72 76 69 63 65 20 50 6f 72 74 3a 20 25 73}
		$s2 = {54 68 65 20 50 6f 72 74 20 4d 75 73 74 20 42 65 65 6e 20 3e 30 20 26 20 3c 36 35 35 33 35}
		$s8 = {33 2d 2d 53 65 74 20 53 65 72 76 65 72 20 50 6f 72 74}
		$s9 = {54 68 65 20 53 65 72 76 65 72 20 50 61 73 73 77 6f 72 64 20 45 78 63 65 65 64 73 20 33 32 20 43 68 61 72 61 63 74 65 72 73}
		$s13 = {53 65 72 76 69 63 65 20 4e 61 6d 65 3a 20 25 73}
		$s14 = {53 65 72 76 65 72 20 50 61 73 73 77 6f 72 64 3a 20 25 73}
		$s17 = {49 6e 6a 65 63 74 20 50 72 6f 63 65 73 73 20 4e 61 6d 65 3a 20 25 73}
		$x1 = {57 69 6e 45 67 67 44 72 6f 70 20 53 68 65 6c 6c 20 43 6f 6e 67 69 72 61 74 6f 72}

	condition:
		5 of ( $s* ) or $x1
}

rule sig_238_letmein : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file letmein.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "74d223a56f97b223a640e4139bb9b94d8faa895d"
		id = "5dba055f-1928-534a-8d0e-11dda56d93b7"

	strings:
		$s1 = {45 72 72 6f 72 20 67 65 74 20 67 6c 6f 62 61 6c 67 72 6f 75 70 20 6d 65 6d 65 62 65 72 73 3a 20 4e 45 52 52 5f 49 6e 76 61 6c 69 64 43 6f 6d 70 75 74 65 72}
		$s6 = {45 72 72 6f 72 20 67 65 74 20 75 73 65 72 73 20 66 72 6f 6d 20 73 65 72 76 65 72 21}
		$s7 = {67 65 74 20 69 6e 20 6e 74 20 62 79 20 6e 61 6d 65 20 61 6e 64 20 6e 75 6c 6c}
		$s16 = {67 65 74 20 73 6f 6d 65 74 68 69 6e 67 20 66 72 6f 6d 20 6e 74 2c 20 68 6f 6c 64 20 62 79 20 6b 69 6c 6c 75 73 61 2e}

	condition:
		all of them
}

rule sig_238_token : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file token.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "c52bc6543d4281aa75a3e6e2da33cfb4b7c34b14"
		id = "9d0ac24b-2078-5455-8d9e-a642c71f7b2d"

	strings:
		$s0 = {4c 6f 67 6f 6e 2e 65 78 65}
		$s1 = {44 6f 6d 61 69 6e 20 41 6e 64 20 55 73 65 72 3a}
		$s2 = {50 49 44 3d 47 65 74 20 41 64 64 72 24 28 29 3a 20 4f 6e 65}
		$s3 = {50 72 6f 63 65 73 73 20}
		$s4 = {70 73 61 70 69 2e 64 6c 6c 4b}

	condition:
		all of them
}

rule sig_238_TELNET : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file TELNET.EXE from Windows ME"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "50d02d77dc6cc4dc2674f90762a2622e861d79b1"
		id = "fae22e0f-2f69-5dc6-984c-2c07530ad11a"

	strings:
		$s0 = {54 00 45 00 4c 00 4e 00 45 00 54 00 20 00 5b 00 68 00 6f 00 73 00 74 00 20 00 5b 00 70 00 6f 00 72 00 74 00 5d 00 5d 00}
		$s2 = {54 00 45 00 4c 00 4e 00 45 00 54 00 2e 00 45 00 58 00 45 00}
		$s4 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 28 00 52 00 29 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 28 00 52 00 29 00 20 00 4d 00 69 00 6c 00 6c 00 65 00 6e 00 6e 00 69 00 75 00 6d 00 20 00 4f 00 70 00 65 00 72 00 61 00 74 00 69 00 6e 00 67 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00}
		$s14 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 54 00 65 00 6c 00 6e 00 65 00 74 00}

	condition:
		all of them
}

rule snifferport : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file snifferport.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "d14133b5eaced9b7039048d0767c544419473144"
		id = "5b903344-18d2-5d3d-be66-7260a5f3ea4b"

	strings:
		$s0 = {69 70 68 6c 70 61 70 69 2e 44 4c 4c}
		$s5 = {79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 72 6f 6c 53 65 74 5c}
		$s11 = {50 6f 72 74 2e 54 58}
		$s12 = {33 32 4e 65 78 74}
		$s13 = {56 31 2e 32 20 42}

	condition:
		all of them
}

rule sig_238_webget : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file webget.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "36b5a5dee093aa846f906bbecf872a4e66989e42"
		id = "b03a2463-94fe-5050-8e3d-269101a03cda"

	strings:
		$s0 = {50 61 63 6b 65 64 20 62 79 20 65 78 65 33 32 70 61 63 6b}
		$s1 = {47 45 54 20 41 20 48 54 54 50 2f 31 2e 30}
		$s2 = {20 65 72 72 6f 72 20}
		$s13 = {44 6f 77 6e 6c 6f 61}

	condition:
		all of them
}

rule XYZCmd_zip_Folder_XYZCmd : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file XYZCmd.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "bbea5a94950b0e8aab4a12ad80e09b630dd98115"
		id = "c3d70b93-1d53-5403-bd22-d1e4bad5042b"

	strings:
		$s0 = {45 00 78 00 65 00 63 00 75 00 74 00 65 00 73 00 20 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00 52 00 65 00 6d 00 6f 00 74 00 65 00 6c 00 79 00}
		$s2 = {58 00 59 00 5a 00 43 00 6d 00 64 00 2e 00 65 00 78 00 65 00}
		$s6 = {4e 00 6f 00 20 00 43 00 6c 00 69 00 65 00 6e 00 74 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00}
		$s19 = {58 59 5a 43 6d 64 20 56 31 2e 30 20 46 6f 72 20 4e 54 20 53}

	condition:
		all of them
}

rule ASPack_Chinese : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file ASPack Chinese.ini"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "02a9394bc2ec385876c4b4f61d72471ac8251a8e"
		id = "ac821117-7534-5dec-9477-25be87361900"

	strings:
		$s0 = {3d 20 43 6c 69 63 6b 20 68 65 72 65 20 69 66 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 67 65 74 20 79 6f 75 72 20 72 65 67 69 73 74 65 72 65 64 20 63 6f 70 79 20 6f 66 20 41 53 50 61 63 6b}
		$s1 = {3b 20 20 46 6f 72 20 62 65 67 69 6e 6e 69 6e 67 20 6f 66 20 74 72 61 6e 73 6c 61 74 65 20 2d 20 63 6f 70 79 20 65 6e 67 6c 69 73 68 2e 69 6e 69 20 69 6e 74 6f 20 74 68 65 20 79 6f 75 72 6c 61 6e 67 75 61 67 65 2e 69 6e 69}
		$s2 = {45 2d 4d 61 69 6c 3a 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 73 68 69 6e 6c 61 6e 40 6b 6d 31 36 39 2e 6e 65 74}
		$s8 = {3b 20 20 50 6c 65 61 73 65 2c 20 74 72 61 6e 73 6c 61 74 65 20 74 65 78 74 20 6f 6e 6c 79 20 61 66 74 65 72 20 73 69 6d 62 6f 6c 20 27 3d 27}
		$s19 = {3d 20 43 6f 6d 70 72 65 73 73 20 77 69 74 68 20 41 53 50 61 63 6b}

	condition:
		all of them
}

rule aspbackdoor_EDIR : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file EDIR.ASP"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "03367ad891b1580cfc864e8a03850368cbf3e0bb"
		id = "0895091a-b620-5746-8245-d44716ec2bbe"

	strings:
		$s1 = {72 65 73 70 6f 6e 73 65 2e 77 72 69 74 65 20 22 3c 61 20 68 72 65 66 3d 27 69 6e 64 65 78 2e 61 73 70 27 3e}
		$s3 = {69 66 20 52 65 71 75 65 73 74 2e 43 6f 6f 6b 69 65 73 28 22 70 61 73 73 77 6f 72 64 22 29 3d 22}
		$s6 = {77 68 69 63 68 64 69 72 3d 73 65 72 76 65 72 2e 6d 61 70 70 61 74 68 28 52 65 71 75 65 73 74 28 22 70 61 74 68 22 29 29}
		$s7 = {53 65 74 20 66 73 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29}
		$s19 = {77 68 69 63 68 64 69 72 3d 52 65 71 75 65 73 74 28 22 70 61 74 68 22 29}

	condition:
		all of them
}

rule ByPassFireWall_zip_Folder_Ie : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file Ie.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "d1b9058f16399e182c9b78314ad18b975d882131"
		id = "7bd10fa1-be2d-5882-b4c7-b696612343e5"

	strings:
		$s0 = {64 3a 5c 64 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 73 65 74 74 69 6e 67 73 5c 6c 6f 76 65 65 6e 67 65 6e 67 5c 64 65 73 6b 74 6f 70 5c 73 6f 75 72 63 65 5c 62 79 70 61 73 73 5c 6c 63 63 5c 69 65 2e 64 6c 6c}
		$s1 = {4c 4f 41 44 45 52 20 45 52 52 4f 52}
		$s5 = {54 68 65 20 70 72 6f 63 65 64 75 72 65 20 65 6e 74 72 79 20 70 6f 69 6e 74 20 25 73 20 63 6f 75 6c 64 20 6e 6f 74 20 62 65 20 6c 6f 63 61 74 65 64 20 69 6e 20 74 68 65 20 64 79 6e 61 6d 69 63 20 6c 69 6e 6b 20 6c 69 62 72 61 72 79 20 25 73}
		$s7 = {54 68 65 20 6f 72 64 69 6e 61 6c 20 25 75 20 63 6f 75 6c 64 20 6e 6f 74 20 62 65 20 6c 6f 63 61 74 65 64 20 69 6e 20 74 68 65 20 64 79 6e 61 6d 69 63 20 6c 69 6e 6b 20 6c 69 62 72 61 72 79 20 25 73}

	condition:
		all of them
}

rule EditKeyLogReadMe : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file EditKeyLogReadMe.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "dfa90540b0e58346f4b6ea12e30c1404e15fbe5a"
		id = "db083c04-9e5c-5cfd-b4d4-eecf28191b6b"

	strings:
		$s0 = {65 64 69 74 4b 65 79 4c 6f 67 2e 65 78 65 20 4b 65 79 4c 6f 67 2e 65 78 65 2c}
		$s1 = {57 69 6e 45 67 67 44 72 6f 70 2e 44 4c 4c}
		$s2 = {6e 63 2e 65 78 65}
		$s3 = {4b 65 79 4c 6f 67 2e 65 78 65}
		$s4 = {45 64 69 74 4b 65 79 4c 6f 67 2e 65 78 65}
		$s5 = {77 69 6e 65 67 67 64 72 6f 70}

	condition:
		3 of them
}

rule PassSniffer_zip_Folder_readme : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file readme.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "a52545ae62ddb0ea52905cbb61d895a51bfe9bcd"
		id = "f5965aa8-0f78-56fd-8e3e-6dc013942cb3"

	strings:
		$s0 = {50 61 73 73 53 6e 69 66 66 65 72 2e 65 78 65}
		$s1 = {50 4f 50 33 2f 46 54 50 20 53 6e 69 66 66 65 72}
		$s2 = {50 61 73 73 77 6f 72 64 20 53 6e 69 66 66 65 72 20 56 31 2e 30}

	condition:
		1 of them
}

rule sig_238_gina : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file gina.reg"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "324acc52566baf4afdb0f3e4aaf76e42899e0cf6"
		id = "85c19493-e6d4-55e8-8526-6817243e90cf"

	strings:
		$s0 = {22 67 69 6e 61 22 3d 22 67 69 6e 61 2e 64 6c 6c 22}
		$s1 = {52 45 47 45 44 49 54 34}
		$s2 = {5b 48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 5d}

	condition:
		all of them
}

rule splitjoin : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file splitjoin.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "e4a9ef5d417038c4c76b72b5a636769a98bd2f8c"
		id = "2f1a69cd-34b3-5af0-a054-fe19d9becb25"

	strings:
		$s0 = {4e 00 6f 00 74 00 20 00 66 00 6f 00 72 00 20 00 64 00 69 00 73 00 74 00 72 00 69 00 62 00 75 00 74 00 69 00 6f 00 6e 00 20 00 77 00 69 00 74 00 68 00 6f 00 75 00 74 00 20 00 74 00 68 00 65 00 20 00 61 00 75 00 74 00 68 00 6f 00 72 00 73 00 20 00 70 00 65 00 72 00 6d 00 69 00 73 00 73 00 69 00 6f 00 6e 00}
		$s2 = {55 00 74 00 69 00 6c 00 69 00 74 00 79 00 20 00 74 00 6f 00 20 00 73 00 70 00 6c 00 69 00 74 00 20 00 61 00 6e 00 64 00 20 00 72 00 65 00 6a 00 6f 00 69 00 6e 00 20 00 66 00 69 00 6c 00 65 00 73 00 2e 00 30 00}
		$s5 = {43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 28 00 63 00 29 00 20 00 41 00 6e 00 67 00 75 00 73 00 20 00 4a 00 6f 00 68 00 6e 00 73 00 6f 00 6e 00 20 00 32 00 30 00 30 00 31 00 2d 00 32 00 30 00 30 00 32 00}
		$s19 = {53 00 70 00 6c 00 69 00 74 00 4a 00 6f 00 69 00 6e 00}

	condition:
		all of them
}

rule EditKeyLog : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file EditKeyLog.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "a450c31f13c23426b24624f53873e4fc3777dc6b"
		id = "db083c04-9e5c-5cfd-b4d4-eecf28191b6b"

	strings:
		$s1 = {50 72 65 73 73 20 41 6e 79 20 4b 65}
		$s2 = {45 6e 74 65 72 20 31 20 4f}
		$s3 = {42 6f 6e 20 3e 30 20 26 20 3c 36 35 35 33 35 4c}
		$s4 = {2d 2d 43 68 6f 6f 73 65 20}

	condition:
		all of them
}

rule PassSniffer : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file PassSniffer.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "dcce4c577728e8edf7ed38ac6ef6a1e68afb2c9f"
		id = "f5965aa8-0f78-56fd-8e3e-6dc013942cb3"

	strings:
		$s2 = {53 6e 69 66 66}
		$s3 = {47 65 74 4c 61 73}
		$s4 = {56 65 72 73 69 6f 6e 45 78 41}
		$s10 = {20 4f 6e 6c 79 20 52 75 6e 74 55 5a}
		$s12 = {65 6d 63 70 79 73 65 74 70 72 69 6e 74 66 5c}
		$s13 = {57 53 46 74 61 72 74 75 70}

	condition:
		all of them
}

rule aspfile2 : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file aspfile2.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "14efbc6cb01b809ad75a535d32b9da4df517ff29"
		id = "42bbcc16-a6d7-53d7-8651-1a28c6b26ee8"

	strings:
		$s0 = {72 65 73 70 6f 6e 73 65 2e 77 72 69 74 65 20 22 63 6f 6d 6d 61 6e 64 20 63 6f 6d 70 6c 65 74 65 64 20 73 75 63 63 65 73 73 21 22 20}
		$s1 = {66 6f 72 20 65 61 63 68 20 63 6f 20 69 6e 20 66 6f 64 69 74 65 6d 73 20}
		$s3 = {3c 69 6e 70 75 74 20 74 79 70 65 3d 74 65 78 74 20 6e 61 6d 65 3d 74 65 78 74 36 20 76 61 6c 75 65 3d 22 3c 25 3d 20 73 7a 43 4d 44 36 20 25 3e 22 3e 3c 62 72 3e 20}
		$s19 = {3c 74 69 74 6c 65 3e 48 65 6c 6c 6f 21 20 57 65 6c 63 6f 6d 65 20 3c 2f 74 69 74 6c 65 3e}

	condition:
		all of them
}

rule UnPack_rar_Folder_InjectT : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file InjectT.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "80f39e77d4a34ecc6621ae0f4d5be7563ab27ea6"
		id = "cc7d1a36-1214-5a14-8589-9eb2339a8700"

	strings:
		$s0 = {25 73 20 2d 49 6e 73 74 61 6c 6c 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 2d 2d 3e 54 6f 20 49 6e 73 74 61 6c 6c 20 54 68 65 20 53 65 72 76 69 63 65}
		$s1 = {45 78 70 6c 6f 72 65 72 2e 65 78 65}
		$s2 = {25 73 20 2d 53 74 61 72 74 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 2d 2d 3e 54 6f 20 53 74 61 72 74 20 54 68 65 20 53 65 72 76 69 63 65}
		$s3 = {25 73 20 2d 53 74 6f 70 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 2d 2d 3e 54 6f 20 53 74 6f 70 20 54 68 65 20 53 65 72 76 69 63 65}
		$s4 = {54 68 65 20 50 6f 72 74 20 49 73 20 4f 75 74 20 4f 66 20 52 61 6e 67 65}
		$s7 = {46 61 69 6c 20 54 6f 20 53 65 74 20 54 68 65 20 50 6f 72 74}
		$s11 = {5c 70 73 61 70 69 2e 64 6c 6c}
		$s20 = {54 49 6e 6a 65 63 74 2e 44 6c 6c}
		$x1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 57 69 6e 45 67 67 44 72 6f 70 53 68 65 6c 6c}
		$x2 = {69 6e 6a 65 63 74 74 2e 65 78 65}

	condition:
		(1 of ( $x* ) ) and ( 3 of ( $s* ) )
}

rule Jc_WinEggDrop_Shell : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file Jc.WinEggDrop Shell.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "820674b59f32f2cf72df50ba4411d7132d863ad2"
		id = "219df3a1-fe1c-5d33-ab3e-1b3cbd104c9e"

	strings:
		$s0 = {53 6e 69 66 66 65 72 2e 64 6c 6c}
		$s4 = {3a 45 78 65 63 75 74 65 20 6e 65 74 2e 65 78 65 20 75 73 65 72 20 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 20 70 61 73 73}
		$s5 = {46 70 6f 72 74 2e 65 78 65 20 6f 72 20 6d 70 6f 72 74 2e 65 78 65 20}
		$s6 = {3a 50 61 73 73 77 6f 72 64 20 53 6e 69 66 66 65 72 69 6e 67 20 49 73 20 52 75 6e 6e 69 6e 67 20 7c 4e 6f 74 20 52 75 6e 6e 69 6e 67 20}
		$s9 = {3a 20 54 68 65 20 54 65 72 6d 69 6e 61 6c 20 53 65 72 76 69 63 65 20 50 6f 72 74 20 48 61 73 20 42 65 65 6e 20 53 65 74 20 54 6f 20 4e 65 77 50 6f 72 74}
		$s15 = {3a 20 44 65 6c 20 77 77 77 2e 65 78 65 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20}
		$s20 = {3a 44 69 72 20 2a 2e 65 78 65 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20}

	condition:
		2 of them
}

rule aspbackdoor_asp1 : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file asp1.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "9ef9f34392a673c64525fcd56449a9fb1d1f3c50"
		id = "fa5128c5-efd5-55dd-880a-2952942e2035"

	strings:
		$s0 = {70 61 72 61 6d 20 3d 20 22 64 72 69 76 65 72 3d 7b 4d 69 63 72 6f 73 6f 66 74 20 41 63 63 65 73 73 20 44 72 69 76 65 72 20 28 2a 2e 6d 64 62 29 7d 22 20}
		$s1 = {63 6f 6e 6e 2e 4f 70 65 6e 20 70 61 72 61 6d 20 26 20 22 3b 64 62 71 3d 22 20 26 20 53 65 72 76 65 72 2e 4d 61 70 50 61 74 68 28 22 73 63 6a 68 2e 6d 64 62 22 29 20}
		$s6 = {73 65 74 20 72 73 3d 63 6f 6e 6e 2e 65 78 65 63 75 74 65 20 28 73 71 6c 29 25 3e 20}
		$s7 = {3c 25 73 65 74 20 43 6f 6e 6e 20 3d 20 53 65 72 76 65 72 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 41 44 4f 44 42 2e 43 6f 6e 6e 65 63 74 69 6f 6e 22 29 20}
		$s10 = {3c 25 64 69 6d 20 6b 74 64 68 2c 73 63 70 68 2c 73 63 74 73 2c 6a 68 71 74 73 6a 2c 79 68 78 64 73 6a 2c 79 78 6a 2c 72 77 62 68 20}
		$s15 = {73 71 6c 3d 22 73 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 73 63 6a 68 22 20}

	condition:
		all of them
}

rule QQ_zip_Folder_QQ : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file QQ.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "9f8e3f40f1ac8c1fa15a6621b49413d815f46cfb"
		id = "30da6292-f670-5b73-985a-3028e20607be"

	strings:
		$s0 = {45 00 4d 00 41 00 49 00 4c 00 3a 00 68 00 61 00 6f 00 71 00 40 00 6e 00 65 00 75 00 73 00 6f 00 66 00 74 00 2e 00 63 00 6f 00 6d 00}
		$s1 = {45 00 4d 00 41 00 49 00 4c 00 3a 00 68 00 61 00 6f 00 71 00 40 00 6e 00 65 00 75 00 73 00 6f 00 66 00 74 00 2e 00 63 00 6f 00 6d 00}
		$s4 = {51 00 51 00 32 00 30 00 30 00 30 00 62 00 2e 00 65 00 78 00 65 00}
		$s5 = {68 61 6f 71 40 6e 65 75 73 6f 66 74 2e 63 6f 6d}
		$s9 = {51 51 32 30 30 30 62 2e 65 78 65}
		$s10 = {5c 71 71 32 30 30 30 62 2e 65 78 65}
		$s12 = {57 00 49 00 4e 00 44 00 53 00 48 00 45 00 4c 00 4c 00 20 00 53 00 54 00 55 00 44 00 49 00 4f 00 5b 00 57 00 49 00 4e 00 44 00 53 00 48 00 45 00 4c 00 4c 00 20 00}
		$s17 = {53 4f 46 54 57 41 52 45 5c 48 41 4f 51 49 41 4e 47 5c}

	condition:
		5 of them
}

rule UnPack_rar_Folder_TBack : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file TBack.DLL"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "30fc9b00c093cec54fcbd753f96d0ca9e1b2660f"
		id = "f672f987-0d43-53df-8338-084907b6da16"

	strings:
		$s0 = {52 65 64 69 72 65 63 74 20 53 50 6f 72 74 20 52 65 6d 6f 74 65 48 6f 73 74 20 52 50 6f 72 74 20 20 20 20 20 20 20 2d 2d 3e 50 6f 72 74 20 52 65 64 69 72 65 63 74 6f 72}
		$s1 = {68 74 74 70 3a 2f 2f 49 50 2f 61 2e 65 78 65 20 61 2e 65 78 65 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 2d 2d 3e 44 6f 77 6e 6c 6f 61 64 20 41 20 46 69 6c 65}
		$s2 = {53 74 6f 70 53 6e 69 66 66 65 72 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 2d 2d 3e 53 74 6f 70 20 50 61 73 73 20 53 6e 69 66 66 65 72}
		$s3 = {54 65 72 6d 69 6e 61 6c 50 6f 72 74 20 50 6f 72 74 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 2d 2d 3e 53 65 74 20 4e 65 77 20 54 65 72 6d 69 6e 61 6c 20 50 6f 72 74}
		$s4 = {45 78 61 6d 70 6c 65 3a 20 48 74 74 70 3a 2f 2f 31 32 2e 31 32 2e 31 32 2e 31 32 2f 61 2e 65 78 65 20 61 62 63 2e 65 78 65}
		$s6 = {43 72 65 61 74 65 20 50 61 73 73 77 6f 72 64 20 53 6e 69 66 66 65 72 69 6e 67 20 54 68 72 65 61 64 20 53 75 63 63 65 73 73 66 75 6c 6c 79 2e 20 53 74 61 74 75 73 3a 4c 6f 67 67 69 6e 67}
		$s7 = {53 74 61 72 74 53 6e 69 66 66 65 72 20 4e 49 43 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 2d 2d 3e 53 74 61 72 74 20 53 6e 69 66 66 65 72}
		$s8 = {53 68 65 6c 6c 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 2d 2d 3e 47 65 74 20 41 20 53 68 65 6c 6c}
		$s11 = {44 65 6c 65 74 65 53 65 72 76 69 63 65 20 53 65 72 76 69 63 65 4e 61 6d 65 20 20 20 20 20 20 20 20 20 20 20 20 20 2d 2d 3e 44 65 6c 65 74 65 20 41 20 53 65 72 76 69 63 65}
		$s12 = {44 69 73 63 6f 6e 6e 65 63 74 20 54 68 72 65 61 64 4e 75 6d 62 65 72 7c 41 6c 6c 20 20 20 20 20 20 20 20 20 20 20 2d 2d 3e 44 69 73 63 6f 6e 6e 65 63 74 20 4f 74 68 65 72 73}
		$s13 = {4f 6e 6c 69 6e 65 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 2d 2d 3e 4c 69 73 74 20 41 6c 6c 20 43 6f 6e 6e 65 63 74 65 64 20 49 50}
		$s15 = {47 65 74 74 69 6e 67 20 54 68 65 20 55 73 65 72 4e 61 6d 65 28 25 63 25 73 25 63 29 2d 2d 3e 49 44 28 30 78 25 73 29 20 53 75 63 63 65 73 73 66 75 6c 6c 79}
		$s16 = {45 78 61 6d 70 6c 65 3a 20 53 65 74 20 52 45 47 5f 53 5a 20 54 65 73 74 20 54 72 6f 6a 61 6e 2e 65 78 65}
		$s18 = {45 78 65 63 75 74 65 20 50 72 6f 67 72 61 6d 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 2d 2d 3e 45 78 65 63 75 74 65 20 41 20 50 72 6f 67 72 61 6d}
		$s19 = {52 65 62 6f 6f 74 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 2d 2d 3e 52 65 62 6f 6f 74 20 54 68 65 20 53 79 73 74 65 6d}
		$s20 = {50 61 73 73 77 6f 72 64 20 53 6e 69 66 66 65 72 69 6e 67 20 49 73 20 4e 6f 74 20 52 75 6e 6e 69 6e 67}

	condition:
		4 of them
}

rule sig_238_cmd_2 : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file cmd.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "be4073188879dacc6665b6532b03db9f87cfc2bb"
		id = "5fae3c4a-aeeb-5e02-9071-3980a39a19a9"

	strings:
		$s0 = {50 72 6f 63 65 73 73 20 63 68 69 6c 64 20 3d 20 52 75 6e 74 69 6d 65 2e 67 65 74 52 75 6e 74 69 6d 65 28 29 2e 65 78 65 63 28}
		$s1 = {49 6e 70 75 74 53 74 72 65 61 6d 20 69 6e 20 3d 20 63 68 69 6c 64 2e 67 65 74 49 6e 70 75 74 53 74 72 65 61 6d 28 29 3b}
		$s2 = {53 74 72 69 6e 67 20 63 6d 64 20 3d 20 72 65 71 75 65 73 74 2e 67 65 74 50 61 72 61 6d 65 74 65 72 28 22}
		$s3 = {77 68 69 6c 65 20 28 28 63 20 3d 20 69 6e 2e 72 65 61 64 28 29 29 20 21 3d 20 2d 31 29 20 7b}
		$s4 = {3c 25 40 20 70 61 67 65 20 69 6d 70 6f 72 74 3d 22 6a 61 76 61 2e 69 6f 2e 2a 22 20 25 3e}

	condition:
		all of them
}

rule RangeScan : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file RangeScan.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "bace2c65ea67ac4725cb24aa9aee7c2bec6465d7"
		id = "143d9e1e-41e2-579a-beee-30da2cf068f7"

	strings:
		$s0 = {52 00 61 00 6e 00 67 00 65 00 53 00 63 00 61 00 6e 00 2e 00 45 00 58 00 45 00}
		$s4 = {3c 62 72 3e 3c 70 20 61 6c 69 67 6e 3d 22 63 65 6e 74 65 72 22 3e 3c 62 3e 52 61 6e 67 65 53 63 61 6e 20}
		$s9 = {50 72 6f 64 75 63 65 64 20 62 79 20 69 73 6e 30}
		$s10 = {52 00 61 00 6e 00 67 00 65 00 53 00 63 00 61 00 6e 00}
		$s20 = {25 64 2d 25 64 2d 25 64 20 25 64 3a 25 64 3a 25 64}

	condition:
		3 of them
}

rule XYZCmd_zip_Folder_Readme : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file Readme.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "967cb87090acd000d22e337b8ce4d9bdb7c17f70"
		id = "cee0f8c3-f947-50a5-ae8c-4ce83ef5e433"

	strings:
		$s3 = {33 2e 78 79 7a 63 6d 64 20 5c 5c 52 65 6d 6f 74 65 49 50 20 2f 75 73 65 72 3a 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 20 2f 70 77 64 3a 31 32 33 34 20 2f 6e 6f 77 61 69 74 20 74 72 6f 6a 61 6e 2e 65 78 65}
		$s20 = {58 59 5a 43 6d 64 20 56 31 2e 30}

	condition:
		all of them
}

rule ByPassFireWall_zip_Folder_Inject : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file Inject.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "34f564301da528ce2b3e5907fd4b1acb7cb70728"
		id = "bb31dc53-f3c1-5f8b-84f9-c231a4e1675b"

	strings:
		$s6 = {46 61 69 6c 20 54 6f 20 49 6e 6a 65 63 74}
		$s7 = {42 74 47 52 65 6d 6f 74 65 20 50 72 6f 3b 20 56 31 2e 35 20 42 2f 7b}
		$s11 = {20 53 75 63 63 65 73 73 66 75 6c 6c 79}

	condition:
		all of them
}

rule sig_238_sqlcmd : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file sqlcmd.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 40
		hash = "b6e356ce6ca5b3c932fa6028d206b1085a2e1a9a"
		id = "0efdfac7-5a89-5251-b583-12b0a58c48ff"

	strings:
		$s0 = {50 65 72 6d 69 73 73 69 6f 6e 20 64 65 6e 69 61 6c 20 74 6f 20 45 58 45 43 20 63 6f 6d 6d 61 6e 64 2e 3a 28}
		$s3 = {62 79 20 45 79 61 73 3c 63 6f 6f 6c 65 79 61 73 40 32 31 63 6e 2e 63 6f 6d 3e}
		$s4 = {43 6f 6e 6e 65 63 74 20 74 6f 20 25 73 20 4d 53 53 51 4c 20 73 65 72 76 65 72 20 73 75 63 63 65 73 73 2e 45 6e 6a 6f 79 20 74 68 65 20 73 68 65 6c 6c 2e 5e 5f 5e}
		$s5 = {55 73 61 67 65 3a 20 25 73 20 3c 68 6f 73 74 3e 20 3c 75 69 64 3e 20 3c 70 77 64 3e}
		$s6 = {53 71 6c 43 6d 64 32 2e 65 78 65 20 49 6e 73 69 64 65 20 45 64 69 74 69 6f 6e 2e}
		$s7 = {48 74 74 70 3a 2f 2f 77 77 77 2e 70 61 74 63 68 69 6e 67 2e 6e 65 74 20 20 32 30 30 30 2f 31 32 2f 31 34}
		$s11 = {45 78 61 6d 70 6c 65 3a 20 25 73 20 31 39 32 2e 31 36 38 2e 30 2e 31 20 73 61 20 22 22}

	condition:
		4 of them
}

rule ASPack_ASPACK : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file ASPACK.EXE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "c589e6fd48cfca99d6335e720f516e163f6f3f42"
		id = "ca9a25f9-a94b-5e10-b935-c6e2d38d999c"

	strings:
		$s0 = {41 00 53 00 50 00 41 00 43 00 4b 00 2e 00 45 00 58 00 45 00}
		$s5 = {43 00 4c 00 4f 00 53 00 45 00 44 00 46 00 4f 00 4c 00 44 00 45 00 52 00}
		$s10 = {41 00 53 00 50 00 61 00 63 00 6b 00 20 00 63 00 6f 00 6d 00 70 00 72 00 65 00 73 00 73 00 6f 00 72 00}

	condition:
		all of them
}

rule sig_238_2323 : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file 2323.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "21812186a9e92ee7ddc6e91e4ec42991f0143763"
		id = "445f6a49-51e6-5eb8-ae08-e5989aafb6c4"

	strings:
		$s0 = {70 6f 72 74 20 2d 20 50 6f 72 74 20 74 6f 20 6c 69 73 74 65 6e 20 6f 6e 2c 20 64 65 66 61 75 6c 74 73 20 74 6f 20 32 33 32 33}
		$s1 = {55 73 61 67 65 3a 20 73 72 76 63 6d 64 2e 65 78 65 20 5b 2f 68 5d 20 5b 70 6f 72 74 5d}
		$s3 = {46 61 69 6c 65 64 20 74 6f 20 65 78 65 63 75 74 65 20 73 68 65 6c 6c}
		$s5 = {2f 68 20 20 20 2d 20 48 69 64 65 20 57 69 6e 64 6f 77}
		$s7 = {41 63 63 65 70 74 65 64 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 66 72 6f 6d 20 63 6c 69 65 6e 74 20 61 74 20 25 73}
		$s9 = {45 72 72 6f 72 20 25 64 3a 20 25 73}

	condition:
		all of them
}

rule Jc_ALL_WinEggDropShell_rar_Folder_Install_2 : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file Install.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "95866e917f699ee74d4735300568640ea1a05afd"
		id = "ebfc8e53-328c-5deb-bf9b-e0270f171c68"

	strings:
		$s1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 67 00 6f 00 2e 00 31 00 36 00 33 00 2e 00 63 00 6f 00 6d 00 2f 00 73 00 64 00 65 00 6d 00 6f 00}
		$s2 = {50 6c 61 79 65 72 2e 74 6d 70}
		$s3 = {50 00 6c 00 61 00 79 00 65 00 72 00 2e 00 45 00 58 00 45 00}
		$s4 = {6d 61 69 6c 74 6f 3a 73 64 65 6d 6f 40 32 36 33 2e 6e 65 74}
		$s5 = {53 2d 50 6c 61 79 65 72 2e 65 78 65}
		$s9 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 42 00 61 00 69 00 58 00 75 00 65 00 2e 00 6e 00 65 00 74 00 20 00 28 00}

	condition:
		all of them
}

rule sig_238_TFTPD32 : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file TFTPD32.EXE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "5c5f8c1a2fa8c26f015e37db7505f7c9e0431fe8"
		id = "071fba15-affe-539a-bcc0-c14943fff51a"

	strings:
		$s0 = {20 68 74 74 70 3a 2f 2f 61 72 6d 2e 35 33 33 2e 6e 65 74}
		$s1 = {54 66 74 70 64 33 32 2e 68 6c 70}
		$s2 = {54 69 6d 65 6f 75 74 73 20 61 6e 64 20 50 6f 72 74 73 20 73 68 6f 75 6c 64 20 62 65 20 6e 75 6d 65 72 69 63 61 6c 20 61 6e 64 20 63 61 6e 20 6e 6f 74 20 62 65 20 30}
		$s3 = {54 00 46 00 54 00 50 00 44 00 33 00 32 00 20 00 2d 00 2d 00 20 00}
		$s4 = {25 64 20 2d 2d 20 25 73}
		$s5 = {54 49 4d 45 4f 55 54 20 77 68 69 6c 65 20 77 61 69 74 69 6e 67 20 66 6f 72 20 41 63 6b 20 62 6c 6f 63 6b 20 25 64 2e 20 66 69 6c 65 20 3c 25 73 3e}
		$s12 = {54 66 74 70 50 6f 72 74}
		$s13 = {54 74 66 74 70 64 33 32 42 61 63 6b 47 72 6f 75 6e 64}
		$s17 = {53 4f 46 54 57 41 52 45 5c 54 46 54 50 44 33 32}

	condition:
		all of them
}

rule sig_238_iecv : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file iecv.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "6e6e75350a33f799039e7a024722cde463328b6d"
		id = "08126db3-267b-5289-b562-40bc264f6e3e"

	strings:
		$s1 = {45 00 64 00 69 00 74 00 20 00 54 00 68 00 65 00 20 00 43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 20 00 4f 00 66 00 20 00 43 00 6f 00 6f 00 6b 00 69 00 65 00 20 00}
		$s3 = {41 63 63 65 73 73 6f 72 69 65 73 5c 77 6f 72 64 70 61 64 2e 65 78 65}
		$s4 = {67 6f 72 69 6c 6c 61 6e 61 74 69 6f 6e 2e 63 6f 6d}
		$s5 = {42 65 66 6f 72 65 20 65 64 69 74 69 6e 67 20 74 68 65 20 63 6f 6e 74 65 6e 74 20 6f 66 20 61 20 63 6f 6f 6b 69 65 2c 20 79 6f 75 20 73 68 6f 75 6c 64 20 63 6c 6f 73 65 20 61 6c 6c 20 77 69 6e 64 6f 77 73 20 6f 66 20 49 6e 74 65 72 6e 65 74}
		$s12 = {68 74 74 70 3a 2f 2f 6e 69 72 73 6f 66 74 2e 63 6a 62 2e 6e 65 74}

	condition:
		all of them
}

rule Antiy_Ports_1_21 : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file Antiy Ports 1.21.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "ebf4bcc7b6b1c42df6048d198cbe7e11cb4ae3f0"
		id = "eb53fc91-4dec-5416-a2c7-1e8256297886"

	strings:
		$s0 = {41 00 6e 00 74 00 69 00 79 00 50 00 6f 00 72 00 74 00 73 00 2e 00 45 00 58 00 45 00}
		$s7 = {41 00 6e 00 74 00 69 00 79 00 50 00 6f 00 72 00 74 00 73 00 20 00 4d 00 46 00 43 00 20 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00}
		$s20 = {20 40 53 74 65 67 6f 3a}

	condition:
		all of them
}

rule perlcmd_zip_Folder_cmd : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file cmd.cgi"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "21b5dc36e72be5aca5969e221abfbbdd54053dd8"
		id = "19e4eca0-bd56-57af-afd2-ee2fc5c7c0df"

	strings:
		$s0 = {73 79 73 77 72 69 74 65 28 53 54 44 4f 55 54 2c 20 22 43 6f 6e 74 65 6e 74 2d 74 79 70 65 3a 20 74 65 78 74 2f 68 74 6d 6c 5c 72 5c 6e 5c 72 5c 6e 22 2c 20 32 37 29 3b}
		$s1 = {73 2f 25 32 30 2f 20 2f 69 67 3b}
		$s2 = {73 79 73 77 72 69 74 65 28 53 54 44 4f 55 54 2c 20 22 5c 72 5c 6e 3c 2f 50 52 45 3e 3c 2f 48 54 4d 4c 3e 5c 72 5c 6e 22 2c 20 31 37 29 3b}
		$s4 = {6f 70 65 6e 28 53 54 44 45 52 52 2c 20 22 3e 26 53 54 44 4f 55 54 22 29 20 7c 7c 20 64 69 65 20 22 43 61 6e 27 74 20 72 65 64 69 72 65 63 74 20 53 54 44 45 52 52 22 3b}
		$s5 = {24 5f 20 3d 20 24 45 4e 56 7b 51 55 45 52 59 5f 53 54 52 49 4e 47 7d 3b}
		$s6 = {24 65 78 65 63 74 68 69 73 20 3d 20 24 5f 3b}
		$s7 = {73 79 73 74 65 6d 28 24 65 78 65 63 74 68 69 73 29 3b}
		$s12 = {73 2f 25 32 66 2f 5c 2f 2f 69 67 3b}

	condition:
		6 of them
}

rule aspbackdoor_asp3 : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file asp3.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "e5588665ca6d52259f7d9d0f13de6640c4e6439c"
		id = "ed86e829-449b-5088-a105-f1fe79547540"

	strings:
		$s0 = {3c 66 6f 72 6d 20 61 63 74 69 6f 6e 3d 22 63 68 61 6e 67 65 70 77 64 2e 61 73 70 22 20 6d 65 74 68 6f 64 3d 22 70 6f 73 74 22 3e 20}
		$s1 = {20 20 53 65 74 20 6f 55 73 65 72 20 3d 20 47 65 74 4f 62 6a 65 63 74 28 22 57 69 6e 4e 54 3a 2f 2f 43 6f 6d 70 75 74 65 72 4e 61 6d 65 2f 22 20 26 20 55 73 65 72 4e 61 6d 65 29 20}
		$s2 = {20 20 20 20 76 61 6c 75 65 3d 22 3c 25 3d 52 65 71 75 65 73 74 2e 53 65 72 76 65 72 56 61 72 69 61 62 6c 65 73 28 22 4c 4f 47 49 4e 5f 55 53 45 52 22 29 25 3e 22 3e 20}
		$s14 = {20 57 69 6e 64 6f 77 73 20 4e 54 20}
		$s16 = {20 57 49 6e 64 6f 77 73 20 32 30 30 30 20}
		$s18 = {4f 6c 64 50 77 64 20 3d 20 52 65 71 75 65 73 74 2e 46 6f 72 6d 28 22 4f 6c 64 50 77 64 22 29 20}
		$s19 = {4e 65 77 50 77 64 32 20 3d 20 52 65 71 75 65 73 74 2e 46 6f 72 6d 28 22 4e 65 77 50 77 64 32 22 29 20}
		$s20 = {4e 65 77 50 77 64 31 20 3d 20 52 65 71 75 65 73 74 2e 46 6f 72 6d 28 22 4e 65 77 50 77 64 31 22 29 20}

	condition:
		all of them
}

rule sig_238_FPipe : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file FPipe.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "41d57d356098ff55fe0e1f0bcaa9317df5a2a45c"
		id = "0b2f11d9-a919-5790-8724-d2f028e4fa3a"

	strings:
		$s0 = {6d 61 64 65 20 74 6f 20 70 6f 72 74 20 38 30 20 6f 66 20 74 68 65 20 72 65 6d 6f 74 65 20 6d 61 63 68 69 6e 65 20 61 74 20 31 39 32 2e 31 36 38 2e 31 2e 31 30 31 20 77 69 74 68 20 74 68 65}
		$s1 = {55 6e 61 62 6c 65 20 74 6f 20 72 65 73 6f 6c 76 65 20 68 6f 73 74 6e 61 6d 65 20 22 25 73 22}
		$s2 = {73 6f 75 72 63 65 20 70 6f 72 74 20 66 6f 72 20 74 68 61 74 20 6f 75 74 62 6f 75 6e 64 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 62 65 69 6e 67 20 73 65 74 20 74 6f 20 35 33 20 61 6c 73 6f 2e}
		$s3 = {20 2d 73 20 20 20 20 2d 20 6f 75 74 62 6f 75 6e 64 20 73 6f 75 72 63 65 20 70 6f 72 74 20 6e 75 6d 62 65 72}
		$s5 = {68 74 74 70 3a 2f 2f 77 77 77 2e 66 6f 75 6e 64 73 74 6f 6e 65 2e 63 6f 6d}
		$s20 = {41 74 74 65 6d 70 74 69 6e 67 20 74 6f 20 63 6f 6e 6e 65 63 74 20 74 6f 20 25 73 20 70 6f 72 74 20 25 64}

	condition:
		all of them
}

rule sig_238_concon : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file concon.com"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "816b69eae66ba2dfe08a37fff077e79d02b95cc1"
		id = "ca7862cc-1053-5fce-a569-6ecc069314df"

	strings:
		$s0 = {55 73 61 67 65 3a 20 63 6f 6e 63 6f 6e 20 5c 5c 69 70 5c 73 68 61 72 65 6e 61 6d 65 5c 63 6f 6e 5c 63 6f 6e}

	condition:
		all of them
}

rule aspbackdoor_regdll : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file regdll.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "5c5e16a00bcb1437bfe519b707e0f5c5f63a488d"
		id = "37096c50-68d0-5412-847a-022062a5ff2a"

	strings:
		$s1 = {65 78 69 74 63 6f 64 65 20 3d 20 6f 53 68 65 6c 6c 2e 52 75 6e 28 22 63 3a 5c 57 49 4e 4e 54 5c 73 79 73 74 65 6d 33 32 5c 72 65 67 73 76 72 33 32 2e 65 78 65 20 2f 75 2f 73 20 22 20 26 20 73 74 72 46 69 6c 65 2c 20 30 2c 20}
		$s3 = {6f 53 68 65 6c 6c 2e 52 75 6e 20 22 63 3a 5c 57 49 4e 4e 54 5c 73 79 73 74 65 6d 33 32 5c 72 65 67 73 76 72 33 32 2e 65 78 65 20 2f 75 2f 73 20 22 20 26 20 73 74 72 46 69 6c 65 2c 20 30 2c 20 46 61 6c 73 65}
		$s4 = {45 63 68 6f 42 28 22 72 65 67 73 76 72 33 32 2e 65 78 65 20 65 78 69 74 63 6f 64 65 20 3d 20 22 20 26 20 65 78 69 74 63 6f 64 65 29}
		$s5 = {50 75 62 6c 69 63 20 50 72 6f 70 65 72 74 79 20 47 65 74 20 6f 46 53 28 29}

	condition:
		all of them
}

rule CleanIISLog : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file CleanIISLog.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "827cd898bfe8aa7e9aaefbe949d26298f9e24094"
		id = "439726c6-3262-59ef-9a54-7dcd98cf924d"

	strings:
		$s1 = {43 6c 65 61 6e 49 50 20 2d 20 53 70 65 63 69 66 79 20 49 50 20 41 64 64 72 65 73 73 20 57 68 69 63 68 20 59 6f 75 20 57 61 6e 74 20 43 6c 65 61 72 2e}
		$s2 = {4c 6f 67 46 69 6c 65 20 2d 20 53 70 65 63 69 66 79 20 4c 6f 67 20 46 69 6c 65 20 57 68 69 63 68 20 59 6f 75 20 57 61 6e 74 20 50 72 6f 63 65 73 73 2e}
		$s8 = {43 6c 65 61 6e 49 49 53 4c 6f 67 20 56 65 72}
		$s9 = {6d 73 66 74 70 73 76 63}
		$s10 = {46 61 74 61 6c 20 45 72 72 6f 72 3a 20 4d 46 43 20 69 6e 69 74 69 61 6c 69 7a 61 74 69 6f 6e 20 66 61 69 6c 65 64}
		$s11 = {53 70 65 63 69 66 69 65 64 20 22 41 4c 4c 22 20 57 69 6c 6c 20 50 72 6f 63 65 73 73 20 41 6c 6c 20 4c 6f 67 20 46 69 6c 65 73 2e}
		$s12 = {53 70 65 63 69 66 69 65 64 20 22 2e 22 20 57 69 6c 6c 20 43 6c 65 61 6e 20 41 6c 6c 20 49 50 20 52 65 63 6f 72 64 2e}
		$s16 = {53 65 72 76 69 63 65 20 25 73 20 53 74 6f 70 70 65 64 2e}
		$s20 = {50 72 6f 63 65 73 73 20 4c 6f 67 20 46 69 6c 65 20 25 73 2e 2e 2e}

	condition:
		5 of them
}

rule sqlcheck : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file sqlcheck.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "5a5778ac200078b627db84fdc35bf5bcee232dc7"
		id = "a72d38ef-b2e7-5051-8538-724d9e95fa6a"

	strings:
		$s0 = {50 6f 77 65 72 20 62 79 20 65 79 61 73 3c 63 6f 6f 6c 65 79 61 73 40 32 31 63 6e 2e 63 6f 6d 3e}
		$s3 = {5c 69 70 63 24 20 22 22 20 2f 75 73 65 72 3a 22 22}
		$s4 = {53 51 4c 43 68 65 63 6b 20 63 61 6e 20 6f 6e 6c 79 20 73 63 61 6e 20 61 20 63 6c 61 73 73 20 42 20 6e 65 74 77 6f 72 6b 2e 20 54 72 79 20 61 67 61 69 6e 2e}
		$s14 = {45 78 61 6d 70 6c 65 3a 20 53 51 4c 43 68 65 63 6b 20 31 39 32 2e 31 36 38 2e 30 2e 31 20 31 39 32 2e 31 36 38 2e 30 2e 32 35 34}
		$s20 = {55 73 61 67 65 3a 20 53 51 4c 43 68 65 63 6b 20 3c 53 74 61 72 74 49 50 3e 20 3c 45 6e 64 49 50 3e}

	condition:
		3 of them
}

rule sig_238_RunAsEx : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file RunAsEx.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "a22fa4e38d4bf82041d67b4ac5a6c655b2e98d35"
		id = "5fe349db-c0fc-5a49-97ee-3142f4e0e4c1"

	strings:
		$s0 = {52 75 6e 41 73 45 78 20 42 79 20 41 73 73 61 73 73 69 6e 20 32 30 30 30 2e 20 41 6c 6c 20 52 69 67 68 74 73 20 52 65 73 65 72 76 65 64 2e 20 68 74 74 70 3a 2f 2f 77 77 77 2e 6e 65 74 58 65 79 65 73 2e 63 6f 6d}
		$s8 = {63 6d 64 2e 62 61 74}
		$s9 = {4e 6f 74 65 3a 20 54 68 69 73 20 50 72 6f 67 72 61 6d 20 43 61 6e 27 6e 74 20 52 75 6e 20 57 69 74 68 20 4c 6f 63 61 6c 20 4d 61 63 68 69 6e 65 2e}
		$s11 = {25 73 20 45 78 65 63 75 74 65 20 53 75 63 63 75 73 73 69 66 75 6c 6c 79 2e}
		$s12 = {77 69 6e 73 74 61 30}
		$s15 = {55 73 61 67 65 3a 20 52 75 6e 41 73 45 78 20 3c 55 73 65 72 4e 61 6d 65 3e 20 3c 50 61 73 73 77 6f 72 64 3e 20 3c 45 78 65 63 75 74 65 20 46 69 6c 65 3e 20 5b 22 45 78 65 63 75 74 65 20 4f 70 74 69 6f 6e 22 5d}

	condition:
		4 of them
}

rule sig_238_nbtdump : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file nbtdump.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "cfe82aad5fc4d79cf3f551b9b12eaf9889ebafd8"
		id = "fe490f72-a07d-57c2-b9bb-d791fab10ec6"

	strings:
		$s0 = {43 72 65 61 74 69 6f 6e 20 6f 66 20 72 65 73 75 6c 74 73 20 66 69 6c 65 20 2d 20 22 25 73 22 20 66 61 69 6c 65 64 2e}
		$s1 = {63 3a 5c 3e 6e 62 74 64 75 6d 70 20 72 65 6d 6f 74 65 2d 6d 61 63 68 69 6e 65}
		$s7 = {43 65 72 62 65 72 75 73 20 4e 42 54 44 55 4d 50}
		$s11 = {3c 43 45 4e 54 45 52 3e 3c 48 31 3e 43 65 72 62 65 72 75 73 20 49 6e 74 65 72 6e 65 74 20 53 63 61 6e 6e 65 72 3c 2f 48 31 3e}
		$s18 = {3c 00 50 00 3e 00 3c 00 48 00 33 00 3e 00 41 00 63 00 63 00 6f 00 75 00 6e 00 74 00 20 00 49 00 6e 00 66 00 6f 00 72 00 6d 00 61 00 74 00 69 00 6f 00 6e 00 3c 00 2f 00 48 00 33 00 3e 00 3c 00 50 00 52 00 45 00 3e 00}
		$s19 = {25 00 73 00 27 00 73 00 20 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 20 00 69 00 73 00 20 00 25 00 73 00 3c 00 2f 00 48 00 33 00 3e 00}
		$s20 = {25 00 73 00 27 00 73 00 20 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 20 00 69 00 73 00 20 00 62 00 6c 00 61 00 6e 00 6b 00 3c 00 2f 00 48 00 33 00 3e 00}

	condition:
		5 of them
}

rule sig_238_Glass2k : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file Glass2k.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "b05455a1ecc6bc7fc8ddef312a670f2013704f1a"
		id = "7a2ad37a-6b55-5710-b07d-7c289cdbb04e"

	strings:
		$s0 = {50 6f 72 74 69 6f 6e 73 20 43 6f 70 79 72 69 67 68 74 20 28 63 29 20 31 39 39 37 2d 31 39 39 39 20 4c 65 65 20 48 61 73 69 75 6b}
		$s1 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 4d 69 63 72 6f 73 6f 66 74 20 56 69 73 75 61 6c 20 53 74 75 64 69 6f 5c 56 42 39 38}
		$s3 = {57 49 4e 4e 54 5c 53 79 73 74 65 6d 33 32 5c 73 74 64 6f 6c 65 32 2e 74 6c 62}
		$s4 = {47 00 6c 00 61 00 73 00 73 00 32 00 6b 00 2e 00 65 00 78 00 65 00}
		$s7 = {4e 65 6f 4c 69 74 65 20 45 78 65 63 75 74 61 62 6c 65 20 46 69 6c 65 20 43 6f 6d 70 72 65 73 73 6f 72}

	condition:
		all of them
}

rule SplitJoin_V1_3_3_rar_Folder_3 : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file splitjoin.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "21409117b536664a913dcd159d6f4d8758f43435"
		id = "4ffd7501-339c-52b7-8661-2c3ca57dfa1f"

	strings:
		$s2 = {69 65 36 38 36 40 73 6f 68 75 2e 63 6f 6d}
		$s3 = {73 70 6c 69 74 6a 6f 69 6e 2e 65 78 65}
		$s7 = {53 70 6c 69 74 4a 6f 69 6e}

	condition:
		all of them
}

rule aspbackdoor_EDIT : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file EDIT.ASP"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "12196cf62931cde7b6cb979c07bb5cc6a7535cbb"
		id = "cdcec370-97af-51c0-b81a-35a788f16ef4"

	strings:
		$s1 = {3c 6d 65 74 61 20 48 54 54 50 2d 45 51 55 49 56 3d 22 43 6f 6e 74 65 6e 74 2d 54 79 70 65 22 20 43 4f 4e 54 45 4e 54 3d 22 74 65 78 74 2f 68 74 6d 6c 3b 63 68 61 72 73 65 74 3d 67 62 5f 32 33 31 32 2d 38 30 22 3e}
		$s2 = {53 65 74 20 74 68 69 73 66 69 6c 65 20 3d 20 66 73 2e 47 65 74 46 69 6c 65 28 77 68 69 63 68 66 69 6c 65 29}
		$s3 = {72 65 73 70 6f 6e 73 65 2e 77 72 69 74 65 20 22 3c 61 20 68 72 65 66 3d 27 69 6e 64 65 78 2e 61 73 70 27 3e}
		$s5 = {69 66 20 52 65 71 75 65 73 74 2e 43 6f 6f 6b 69 65 73 28 22 70 61 73 73 77 6f 72 64 22 29 3d 22 6a 75 63 68 65 6e 22 20 74 68 65 6e 20}
		$s6 = {53 65 74 20 74 68 69 73 66 69 6c 65 20 3d 20 66 73 2e 4f 70 65 6e 54 65 78 74 46 69 6c 65 28 77 68 69 63 68 66 69 6c 65 2c 20 31 2c 20 46 61 6c 73 65 29}
		$s7 = {63 6f 6c 6f 72 3a 20 72 67 62 28 32 35 35 2c 30 2c 30 29 3b 20 74 65 78 74 2d 64 65 63 6f 72 61 74 69 6f 6e 3a 20 75 6e 64 65 72 6c 69 6e 65 20 7d}
		$s13 = {69 66 20 52 65 71 75 65 73 74 28 22 63 72 65 61 74 22 29 3c 3e 22 79 65 73 22 20 74 68 65 6e}

	condition:
		5 of them
}

rule aspbackdoor_entice : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file entice.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "e273a1b9ef4a00ae4a5d435c3c9c99ee887cb183"
		id = "68c61920-9c3c-5bfe-976c-346b258bb406"

	strings:
		$s0 = {3c 46 6f 72 6d 20 4e 61 6d 65 3d 22 46 6f 72 6d 50 73 74 22 20 4d 65 74 68 6f 64 3d 22 50 6f 73 74 22 20 41 63 74 69 6f 6e 3d 22 65 6e 74 69 63 65 2e 61 73 70 22 3e}
		$s2 = {69 66 20 6c 65 66 74 28 74 72 69 6d 28 72 65 71 75 65 73 74 28 22 73 71 6c 6c 61 6e 67 75 61 67 65 22 29 29 2c 36 29 3d 22 73 65 6c 65 63 74 22 20 74 68 65 6e}
		$s4 = {63 6f 6e 6e 64 62 2e 45 78 65 63 75 74 65 28 73 71 6c 6c 61 6e 67 75 61 67 65 29}
		$s5 = {3c 21 2d 2d 23 69 6e 63 6c 75 64 65 20 66 69 6c 65 3d 73 71 6c 63 6f 6e 6e 2e 61 73 70 2d 2d 3e}
		$s6 = {72 73 74 73 71 6c 3d 22 73 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 22 26 72 73 74 61 62 6c 65 28 22 74 61 62 6c 65 5f 6e 61 6d 65 22 29}

	condition:
		all of them
}

rule FPipe2_0 : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file FPipe2.0.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "891609db7a6787575641154e7aab7757e74d837b"
		id = "7e104cf6-69d2-590e-8999-4f0d448719f2"

	strings:
		$s0 = {6d 61 64 65 20 74 6f 20 70 6f 72 74 20 38 30 20 6f 66 20 74 68 65 20 72 65 6d 6f 74 65 20 6d 61 63 68 69 6e 65 20 61 74 20 31 39 32 2e 31 36 38 2e 31 2e 31 30 31 20 77 69 74 68 20 74 68 65}
		$s1 = {55 6e 61 62 6c 65 20 74 6f 20 72 65 73 6f 6c 76 65 20 68 6f 73 74 6e 61 6d 65 20 22 25 73 22}
		$s2 = {20 2d 73 20 20 20 20 2d 20 6f 75 74 62 6f 75 6e 64 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 73 6f 75 72 63 65 20 70 6f 72 74 20 6e 75 6d 62 65 72}
		$s3 = {73 6f 75 72 63 65 20 70 6f 72 74 20 66 6f 72 20 74 68 61 74 20 6f 75 74 62 6f 75 6e 64 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 62 65 69 6e 67 20 73 65 74 20 74 6f 20 35 33 20 61 6c 73 6f 2e}
		$s4 = {68 74 74 70 3a 2f 2f 77 77 77 2e 66 6f 75 6e 64 73 74 6f 6e 65 2e 63 6f 6d}
		$s19 = {46 50 69 70 65}

	condition:
		all of them
}

rule InstGina : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file InstGina.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "5317fbc39508708534246ef4241e78da41a4f31c"
		id = "ccbda689-e61a-501d-a8ed-62e3c1c20289"

	strings:
		$s0 = {54 6f 20 4f 70 65 6e 20 52 65 67 69 73 74 72 79}
		$s4 = {49 20 6c 6f 76 65 20 43 61 6e 64 79 20 76 65 72 79 20 6d 75 63 68 21 21}
		$s5 = {47 69 6e 61 44 4c 4c}

	condition:
		all of them
}

rule ArtTray_zip_Folder_ArtTray : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file ArtTray.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "ee1edc8c4458c71573b5f555d32043cbc600a120"
		id = "d29909a4-8663-54c7-8f0e-68b15def869f"

	strings:
		$s0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 62 00 72 00 69 00 67 00 73 00 6f 00 66 00 74 00 2e 00 63 00 6f 00 6d 00}
		$s2 = {41 72 74 54 72 61 79 48 6f 6f 6b 44 6c 6c 2e 64 6c 6c}
		$s3 = {41 00 72 00 74 00 54 00 72 00 61 00 79 00 20 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 20 00 31 00 2e 00 30 00 20 00}
		$s16 = {54 52 4d 5f 48 4f 4f 4b 43 41 4c 4c 42 41 43 4b}

	condition:
		all of them
}

rule sig_238_findoor : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file findoor.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "cdb1ececceade0ecdd4479ecf55b0cc1cf11cdce"
		id = "61215a76-8c29-505d-bfef-a5f13fec476c"

	strings:
		$s0 = {28 6e 6f 6e 2d 57 69 6e 33 32 20 2e 45 58 45 20 6f 72 20 65 72 72 6f 72 20 69 6e 20 2e 45 58 45 20 69 6d 61 67 65 29 2e}
		$s8 = {50 41 53 53 20 68 61 63 6b 65 72 40 68 61 63 6b 65 72 2e 63 6f 6d}
		$s9 = {2f 73 63 72 69 70 74 73 2f 2e 2e 25 63 31 25 31 63 2e 2e 2f 77 69 6e 6e 74 2f 73 79 73 74 65 6d 33 32 2f 63 6d 64 2e 65 78 65}
		$s10 = {4d 41 49 4c 20 46 52 4f 4d 3a 68 61 63 6b 65 72 40 68 61 63 6b 65 72 2e 63 6f 6d}
		$s11 = {68 74 74 70 3a 2f 2f 69 73 6e 6f 2e 79 65 61 68 2e 6e 65 74}

	condition:
		4 of them
}

rule aspbackdoor_ipclear : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file ipclear.vbs"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "9f8fdfde4b729516330eaeb9141fb2a7ff7d0098"
		id = "71ebecea-721f-5c5d-9997-6a57f070d91c"

	strings:
		$s0 = {53 65 74 20 53 65 72 76 69 63 65 4f 62 6a 20 3d 20 47 65 74 4f 62 6a 65 63 74 28 22 57 69 6e 4e 54 3a 2f 2f 22 20 26 20 6f 62 6a 4e 65 74 2e 43 6f 6d 70 75 74 65 72 4e 61 6d 65 20 26 20 22 2f 77 33 73 76 63 22 29}
		$s1 = {77 73 63 72 69 70 74 2e 45 63 68 6f 20 22 55 53 41 47 45 3a 4b 69 6c 6c 4c 6f 67 2e 76 62 73 20 4c 6f 67 46 69 6c 65 4e 61 6d 65 20 59 6f 75 72 49 50 2e 22}
		$s2 = {53 65 74 20 74 78 74 53 74 72 65 61 6d 4f 75 74 20 3d 20 66 73 6f 2e 4f 70 65 6e 54 65 78 74 46 69 6c 65 28 64 65 73 74 66 69 6c 65 2c 20 46 6f 72 57 72 69 74 69 6e 67 2c 20 54 72 75 65 29}
		$s3 = {53 65 74 20 6f 62 6a 4e 65 74 20 3d 20 57 53 63 72 69 70 74 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 20 22 57 53 63 72 69 70 74 2e 4e 65 74 77 6f 72 6b 22 20 29}
		$s4 = {53 65 74 20 66 73 6f 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29}

	condition:
		all of them
}

rule WinEggDropShellFinal_zip_Folder_InjectT : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file InjectT.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "516e80e4a25660954de8c12313e2d7642bdb79dd"
		id = "16f04551-050f-5a07-a35b-a3a7dbba6803"

	strings:
		$s0 = {50 61 63 6b 65 64 20 62 79 20 65 78 65 33 32 70 61 63 6b}
		$s1 = {32 54 49 6e 6a 65 63 74 2e 44 6c 6c}
		$s2 = {57 69 6e 64 6f 77 73 20 53 65 72 76 69 63 65 73}
		$s3 = {46 69 6e 64 72 73 74 36}
		$s4 = {50 72 65 73 73 20 41 6e 79 20 4b 65 79 20 54 6f 20 43 6f 6e 74 69 6e 75 65 2e 2e 2e 2e 2e 2e}

	condition:
		all of them
}

rule gina_zip_Folder_gina : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file gina.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "e0429e1b59989cbab6646ba905ac312710f5ed30"
		id = "7ebc7218-9c7b-5595-ae7b-f316fc99d1f6"

	strings:
		$s0 = {4e 45 57 47 49 4e 41 2e 64 6c 6c}
		$s1 = {4c 4f 41 44 45 52 20 45 52 52 4f 52}
		$s3 = {57 6c 78 41 63 74 69 76 61 74 65 55 73 65 72 53 68 65 6c 6c}
		$s6 = {57 6c 78 57 6b 73 74 61 4c 6f 63 6b 65 64 53 41 53}
		$s13 = {57 6c 78 49 73 4c 6f 63 6b 4f 6b}
		$s14 = {54 68 65 20 70 72 6f 63 65 64 75 72 65 20 65 6e 74 72 79 20 70 6f 69 6e 74 20 25 73 20 63 6f 75 6c 64 20 6e 6f 74 20 62 65 20 6c 6f 63 61 74 65 64 20 69 6e 20 74 68 65 20 64 79 6e 61 6d 69 63 20 6c 69 6e 6b 20 6c 69 62 72 61 72 79 20 25 73}
		$s16 = {57 6c 78 53 68 75 74 64 6f 77 6e}
		$s17 = {54 68 65 20 6f 72 64 69 6e 61 6c 20 25 75 20 63 6f 75 6c 64 20 6e 6f 74 20 62 65 20 6c 6f 63 61 74 65 64 20 69 6e 20 74 68 65 20 64 79 6e 61 6d 69 63 20 6c 69 6e 6b 20 6c 69 62 72 61 72 79 20 25 73}

	condition:
		all of them
}

rule superscan3_0 : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file superscan3.0.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "a9a02a14ea4e78af30b8b4a7e1c6ed500a36bc4d"
		id = "d22aa3ae-4c62-5007-896d-7c473f0421a6"

	strings:
		$s0 = {5c 73 63 61 6e 6e 65 72 2e 69 6e 69}
		$s1 = {5c 73 63 61 6e 6e 65 72 2e 65 78 65}
		$s2 = {5c 73 63 61 6e 6e 65 72 2e 6c 73 74}
		$s4 = {5c 68 65 6e 73 73 73 2e 6c 73 74}
		$s5 = {53 00 54 00 55 00 42 00 33 00 32 00 2e 00 45 00 58 00 45 00}
		$s6 = {53 00 54 00 55 00 42 00 2e 00 45 00 58 00 45 00}
		$s8 = {5c 77 73 32 63 68 65 63 6b 2e 65 78 65}
		$s9 = {5c 74 72 6f 6a 61 6e 73 2e 6c 73 74}
		$s10 = {31 00 39 00 39 00 36 00 20 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 53 00 68 00 69 00 65 00 6c 00 64 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00}

	condition:
		all of them
}

rule sig_238_xsniff : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file xsniff.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "d61d7329ac74f66245a92c4505a327c85875c577"
		id = "1e61a732-8691-5f84-beb0-c9f7e6d46538"

	strings:
		$s2 = {78 73 69 66 66 2e 65 78 65 20 2d 70 61 73 73 20 2d 68 69 64 65 20 2d 6c 6f 67 20 70 61 73 73 2e 6c 6f 67}
		$s3 = {25 73 20 2d 20 73 69 6d 70 6c 65 20 73 6e 69 66 66 65 72 20 66 6f 72 20 77 69 6e 32 30 30 30}
		$s4 = {78 73 69 66 66 2e 65 78 65 20 2d 74 63 70 20 2d 75 64 70 20 2d 61 73 63 20 2d 61 64 64 72 20 31 39 32 2e 31 36 38 2e 31 2e 31}
		$s5 = {48 4f 53 54 3a 20 25 73 20 55 53 45 52 3a 20 25 73 2c 20 50 41 53 53 3a 20 25 73}
		$s7 = {68 74 74 70 3a 2f 2f 77 77 77 2e 78 66 6f 63 75 73 2e 6f 72 67}
		$s9 = {20 20 2d 70 61 73 73 20 20 20 20 20 20 20 20 3a 20 46 69 6c 74 65 72 20 75 73 65 72 6e 61 6d 65 2f 70 61 73 73 77 6f 72 64}
		$s18 = {20 20 2d 75 64 70 20 20 20 20 20 20 20 20 20 3a 20 4f 75 74 70 75 74 20 75 64 70 20 70 61 63 6b 65 74 73}
		$s19 = {43 6f 64 65 20 62 79 20 67 6c 61 63 69 65 72 20 3c 67 6c 61 63 69 65 72 40 78 66 6f 63 75 73 2e 6f 72 67 3e}
		$s20 = {20 20 2d 74 63 70 20 20 20 20 20 20 20 20 20 3a 20 4f 75 74 70 75 74 20 74 63 70 20 70 61 63 6b 65 74 73}

	condition:
		6 of them
}

rule sig_238_fscan : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file fscan.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		hash = "d5646e86b5257f9c83ea23eca3d86de336224e55"
		id = "7af4d38a-bc88-57ba-b602-4e01d3d95015"

	strings:
		$s0 = {46 53 63 61 6e 20 76 31 2e 31 32 20 2d 20 43 6f 6d 6d 61 6e 64 20 6c 69 6e 65 20 70 6f 72 74 20 73 63 61 6e 6e 65 72 2e}
		$s2 = {20 2d 6e 20 20 20 20 2d 20 6e 6f 20 70 6f 72 74 20 73 63 61 6e 6e 69 6e 67 20 2d 20 6f 6e 6c 79 20 70 69 6e 67 69 6e 67 20 28 75 6e 6c 65 73 73 20 79 6f 75 20 75 73 65 20 2d 71 29}
		$s5 = {45 78 61 6d 70 6c 65 3a 20 66 73 63 61 6e 20 2d 62 70 20 38 30 2c 31 30 30 2d 32 30 30 2c 34 34 33 20 31 30 2e 30 2e 30 2e 31 2d 31 30 2e 30 2e 31 2e 32 30 30}
		$s6 = {20 2d 7a 20 20 20 20 2d 20 6d 61 78 69 6d 75 6d 20 73 69 6d 75 6c 74 61 6e 65 6f 75 73 20 74 68 72 65 61 64 73 20 74 6f 20 75 73 65 20 66 6f 72 20 73 63 61 6e 6e 69 6e 67}
		$s12 = {46 61 69 6c 65 64 20 74 6f 20 6f 70 65 6e 20 74 68 65 20 49 50 20 6c 69 73 74 20 66 69 6c 65 20 22 25 73 22}
		$s13 = {68 74 74 70 3a 2f 2f 77 77 77 2e 66 6f 75 6e 64 73 74 6f 6e 65 2e 63 6f 6d}
		$s16 = {20 2d 70 20 20 20 20 2d 20 54 43 50 20 70 6f 72 74 28 73 29 20 74 6f 20 73 63 61 6e 20 28 61 20 63 6f 6d 6d 61 20 73 65 70 61 72 61 74 65 64 20 6c 69 73 74 20 6f 66 20 70 6f 72 74 73 2f 72 61 6e 67 65 73 29 20}
		$s18 = {42 69 6e 64 20 70 6f 72 74 20 6e 75 6d 62 65 72 20 6f 75 74 20 6f 66 20 72 61 6e 67 65 2e 20 55 73 69 6e 67 20 73 79 73 74 65 6d 20 64 65 66 61 75 6c 74 2e}
		$s19 = {66 00 73 00 63 00 61 00 6e 00 2e 00 65 00 78 00 65 00}

	condition:
		4 of them
}

rule _iissample_nesscan_twwwscan : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - from files iissample.exe, nesscan.exe, twwwscan.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		super_rule = 1
		hash0 = "7f20962bbc6890bf48ee81de85d7d76a8464b862"
		hash1 = "c0b1a2196e82eea4ca8b8c25c57ec88e4478c25b"
		hash2 = "548f0d71ef6ffcc00c0b44367ec4b3bb0671d92f"
		id = "a710ca8e-54dc-5a98-b173-c87b22af745f"

	strings:
		$s0 = {43 6f 6e 6e 65 63 74 69 6e 67 20 48 54 54 50 20 50 6f 72 74 20 2d 20 52 65 73 75 6c 74 3a 20}
		$s1 = {4e 6f 20 73 70 61 63 65 20 66 6f 72 20 63 6f 6d 6d 61 6e 64 20 6c 69 6e 65 20 61 72 67 75 6d 65 6e 74 20 76 65 63 74 6f 72}
		$s3 = {4d 69 63 72 6f 73 6f 66 74 28 4a 75 6c 79 2f 31 39 39 39 7e 29 20 68 74 74 70 3a 2f 2f 77 77 77 2e 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d 2f 74 65 63 68 6e 65 74 2f 73 65 63 75 72 69 74 79 2f 63 75 72 72 65 6e 74 2e 61 73 70}
		$s5 = {4e 6f 20 73 70 61 63 65 20 66 6f 72 20 63 6f 70 79 20 6f 66 20 63 6f 6d 6d 61 6e 64 20 6c 69 6e 65}
		$s7 = {2d 20 20 57 69 6e 64 6f 77 73 20 4e 54 2c 32 30 30 30 20 50 61 74 63 68 20 4d 65 74 68 6f 64 20 20 2d 20}
		$s8 = {73 63 61 6e 66 20 3a 20 66 6c 6f 61 74 69 6e 67 20 70 6f 69 6e 74 20 66 6f 72 6d 61 74 73 20 6e 6f 74 20 6c 69 6e 6b 65 64}
		$s12 = {68 72 64 69 72 5f 62 2e 63 3a 20 4c 6f 61 64 4c 69 62 72 61 72 79 20 21 3d 20 6d 6d 64 6c 6c 20 62 6f 72 6c 6e 64 6d 6d 20 66 61 69 6c 65 64}
		$s13 = {21 22 77 68 61 74 3f 22}
		$s14 = {25 73 20 50 6f 72 74 20 25 64 20 43 6c 6f 73 65 64}
		$s16 = {70 72 69 6e 74 66 20 3a 20 66 6c 6f 61 74 69 6e 67 20 70 6f 69 6e 74 20 66 6f 72 6d 61 74 73 20 6e 6f 74 20 6c 69 6e 6b 65 64}
		$s17 = {78 78 74 79 70 65 2e 63 70 70}

	condition:
		all of them
}

rule _FsHttp_FsPop_FsSniffer : hardened
{
	meta:
		description = "Disclosed hacktool set (old stuff) - from files FsHttp.exe, FsPop.exe, FsSniffer.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "23.11.14"
		score = 60
		super_rule = 1
		hash0 = "9d4e7611a328eb430a8bb6dc7832440713926f5f"
		hash1 = "ae23522a3529d3313dd883727c341331a1fb1ab9"
		hash2 = "7ffc496cd4a1017485dfb571329523a52c9032d8"
		id = "5ca543af-2589-52b0-83f9-ad25ba76b633"

	strings:
		$s0 = {2d 45 52 52 20 49 6e 76 61 6c 69 64 20 43 6f 6d 6d 61 6e 64 2c 20 54 79 70 65 20 5b 48 65 6c 70 5d 20 46 6f 72 20 43 6f 6d 6d 61 6e 64 20 4c 69 73 74}
		$s1 = {2d 45 52 52 20 47 65 74 20 53 4d 53 20 55 73 65 72 73 20 49 44 20 46 61 69 6c 65 64}
		$s2 = {43 6f 6e 74 72 6f 6c 20 54 69 6d 65 20 4f 75 74 20 39 30 20 53 65 63 73 2c 20 43 6f 6e 6e 65 63 74 69 6f 6e 20 43 6c 6f 73 65 64}
		$s3 = {2d 45 52 52 20 50 6f 73 74 20 53 4d 53 20 46 61 69 6c 65 64}
		$s4 = {43 75 72 72 65 6e 74 2e 68 6c 74}
		$s6 = {48 69 73 74 72 6f 79 2e 68 6c 74}
		$s7 = {2d 45 52 52 20 53 65 6e 64 20 53 4d 53 20 46 61 69 6c 65 64}
		$s12 = {2d 45 52 52 20 43 68 61 6e 67 65 20 50 61 73 73 77 6f 72 64 20 3c 4e 65 77 20 50 61 73 73 77 6f 72 64 3e}
		$s17 = {2b 4f 4b 20 53 65 6e 64 20 53 4d 53 20 53 75 63 63 75 73 73 69 66 75 6c 6c 79}
		$s18 = {2b 4f 4b 20 53 65 74 20 4e 65 77 20 50 61 73 73 77 6f 72 64 3a 20 5b 25 73 5d}
		$s19 = {43 48 41 4e 47 45 20 50 41 53 53 57 4f 52 44}

	condition:
		all of them
}

rule Ammyy_Admin_AA_v3 : hardened
{
	meta:
		description = "Remote Admin Tool used by APT group Anunak (ru) - file AA_v3.4.exe and AA_v3.5.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/gkAg2E"
		date = "2014/12/22"
		score = 55
		hash1 = "b130611c92788337c4f6bb9e9454ff06eb409166"
		hash2 = "07539abb2623fe24b9a05e240f675fa2d15268cb"
		id = "bb140cb7-9f56-5acb-883e-080dfd3f60d5"

	strings:
		$x1 = {53 3a 5c 41 6d 6d 79 79 5c 73 6f 75 72 63 65 73 5c 74 61 72 67 65 74 5c 54 72 53 65 72 76 69 63 65 2e 63 70 70}
		$x2 = {53 3a 5c 41 6d 6d 79 79 5c 73 6f 75 72 63 65 73 5c 74 61 72 67 65 74 5c 54 72 44 65 73 6b 74 6f 70 43 6f 70 79 52 65 63 74 2e 63 70 70}
		$x3 = {47 6c 6f 62 61 6c 5c 41 6d 6d 79 79 2e 54 61 72 67 65 74 2e 49 6e 63 6f 6d 65 50 6f 72 74}
		$x4 = {53 3a 5c 41 6d 6d 79 79 5c 73 6f 75 72 63 65 73 5c 74 61 72 67 65 74 5c 54 72 46 6d 46 69 6c 65 53 79 73 2e 63 70 70}
		$x5 = {50 6c 65 61 73 65 20 65 6e 74 65 72 20 70 61 73 73 77 6f 72 64 20 66 6f 72 20 61 63 63 65 73 73 69 6e 67 20 72 65 6d 6f 74 65 20 63 6f 6d 70 75 74 65 72}
		$s1 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 31 28 29 23 33 20 25 64 20 65 72 72 6f 72 3d 25 64}
		$s2 = {43 48 74 74 70 43 6c 69 65 6e 74 3a 3a 53 65 6e 64 52 65 71 75 65 73 74 32 28 25 73 2c 20 25 73 2c 20 25 64 29 20 65 72 72 6f 72 3a 20 69 6e 76 61 6c 69 64 20 68 6f 73 74 20 6e 61 6d 65 2e}
		$s3 = {45 52 52 4f 52 3a 20 43 72 65 61 74 65 50 72 6f 63 65 73 73 41 73 55 73 65 72 28 29 20 65 72 72 6f 72 3d 25 64 2c 20 73 65 73 73 69 6f 6e 3d 25 64}
		$s4 = {45 52 52 4f 52 3a 20 46 69 6e 64 50 72 6f 63 65 73 73 42 79 4e 61 6d 65 28 27 65 78 70 6c 6f 72 65 72 2e 65 78 65 27 29}

	condition:
		2 of ( $x* ) or all of ( $s* )
}

rule LinuxHacktool_eyes_scanssh : hardened
{
	meta:
		description = "Linux hack tools - file scanssh"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "not set"
		date = "2015/01/19"
		hash = "467398a6994e2c1a66a3d39859cde41f090623ad"
		id = "9546d0d8-42af-5b4c-ac93-195d14bfbb5b"

	strings:
		$s0 = {43 6f 6e 6e 65 63 74 69 6f 6e 20 63 6c 6f 73 65 64 20 62 79 20 72 65 6d 6f 74 65 20 68 6f 73 74}
		$s1 = {57 72 69 74 69 6e 67 20 70 61 63 6b 65 74 20 3a 20 65 72 72 6f 72 20 6f 6e 20 73 6f 63 6b 65 74 20 28 6f 72 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 63 6c 6f 73 65 64 29 3a 20 25 73}
		$s2 = {52 65 6d 6f 74 65 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 63 6c 6f 73 65 64 20 62 79 20 73 69 67 6e 61 6c 20 53 49 47 25 73 20 25 73}
		$s4 = {52 65 61 64 69 6e 67 20 70 72 69 76 61 74 65 20 6b 65 79 20 25 73 20 66 61 69 6c 65 64 20 28 62 61 64 20 70 61 73 73 70 68 72 61 73 65 20 3f 29}
		$s5 = {53 65 72 76 65 72 20 63 6c 6f 73 65 64 20 63 6f 6e 6e 65 63 74 69 6f 6e}
		$s6 = {25 73 3a 20 6c 69 6e 65 20 25 64 3a 20 6c 69 73 74 20 64 65 6c 69 6d 69 74 65 72 20 6e 6f 74 20 66 6f 6c 6c 6f 77 65 64 20 62 79 20 6b 65 79 77 6f 72 64}
		$s8 = {63 68 65 63 6b 69 6e 67 20 66 6f 72 20 76 65 72 73 69 6f 6e 20 60 25 73 27 20 69 6e 20 66 69 6c 65 20 25 73 20 72 65 71 75 69 72 65 64 20 62 79 20 66 69 6c 65 20 25 73}
		$s9 = {52 65 6d 6f 74 65 20 68 6f 73 74 20 63 6c 6f 73 65 64 20 63 6f 6e 6e 65 63 74 69 6f 6e}
		$s10 = {25 73 3a 20 6c 69 6e 65 20 25 64 3a 20 62 61 64 20 63 6f 6d 6d 61 6e 64 20 60 25 73 27}
		$s13 = {76 65 72 69 66 79 69 6e 67 20 74 68 61 74 20 73 65 72 76 65 72 20 69 73 20 61 20 6b 6e 6f 77 6e 20 68 6f 73 74 20 3a 20 66 69 6c 65 20 25 73 20 6e 6f 74 20 66 6f 75 6e 64}
		$s14 = {25 73 3a 20 6c 69 6e 65 20 25 64 3a 20 65 78 70 65 63 74 65 64 20 73 65 72 76 69 63 65 2c 20 66 6f 75 6e 64 20 60 25 73 27}
		$s15 = {25 73 3a 20 6c 69 6e 65 20 25 64 3a 20 6c 69 73 74 20 64 65 6c 69 6d 69 74 65 72 20 6e 6f 74 20 66 6f 6c 6c 6f 77 65 64 20 62 79 20 64 6f 6d 61 69 6e}
		$s17 = {50 75 62 6c 69 63 20 6b 65 79 20 66 72 6f 6d 20 73 65 72 76 65 72 20 28 25 73 29 20 64 6f 65 73 6e 27 74 20 6d 61 74 63 68 20 75 73 65 72 20 70 72 65 66 65 72 65 6e 63 65 20 28 25 73 29}

	condition:
		all of them
}

rule LinuxHacktool_eyes_pscan2 : hardened
{
	meta:
		description = "Linux hack tools - file pscan2"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "not set"
		date = "2015/01/19"
		hash = "56b476cba702a4423a2d805a412cae8ef4330905"
		id = "02d96766-6696-5410-ad48-bd8cb642ac51"

	strings:
		$s0 = {23 20 70 73 63 61 6e 20 63 6f 6d 70 6c 65 74 65 64 20 69 6e 20 25 75 20 73 65 63 6f 6e 64 73 2e 20 28 66 6f 75 6e 64 20 25 64 20 69 70 73 29}
		$s1 = {55 73 61 67 65 3a 20 25 73 20 3c 62 2d 62 6c 6f 63 6b 3e 20 3c 70 6f 72 74 3e 20 5b 63 2d 62 6c 6f 63 6b 5d}
		$s3 = {25 73 2e 25 64 2e 2a 20 28 74 6f 74 61 6c 3a 20 25 64 29 20 28 25 2e 31 66 25 25 20 64 6f 6e 65 29}
		$s8 = {49 6e 76 61 6c 69 64 20 49 50 2e}
		$s9 = {23 20 73 63 61 6e 6e 69 6e 67 3a 20}
		$s10 = {55 6e 61 62 6c 65 20 74 6f 20 61 6c 6c 6f 63 61 74 65 20 73 6f 63 6b 65 74 2e}

	condition:
		2 of them
}

rule LinuxHacktool_eyes_a : hardened
{
	meta:
		description = "Linux hack tools - file a"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "not set"
		date = "2015/01/19"
		hash = "458ada1e37b90569b0b36afebba5ade337ea8695"
		id = "2b4f52d4-b438-5040-89c5-aab1df15200e"

	strings:
		$s0 = {63 61 74 20 74 72 75 65 75 73 65 72 73 2e 74 78 74 20 7c 20 6d 61 69 6c 20 2d 73 20 22 65 79 65 73 22 20 63 6c 75 62 62 79 40 73 6c 75 63 69 61 2e 63 6f 6d}
		$s1 = {6d 76 20 73 63 61 6e 2e 6c 6f 67 20 62 69 6f 73 2e 74 78 74}
		$s2 = {72 6d 20 2d 72 66 20 62 69 6f 73 2e 74 78 74}
		$s3 = {65 63 68 6f 20 2d 65 20 22 23 20 62 79 20 45 79 65 73 2e 22}
		$s4 = {2e 2f 2e 2f 70 73 63 61 6e 32 20 24 31 20 32 32}
		$s10 = {65 63 68 6f 20 22 23 63 61 75 74 61 6d 2e 2e 2e 22}

	condition:
		2 of them
}

rule LinuxHacktool_eyes_mass : hardened
{
	meta:
		description = "Linux hack tools - file mass"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "not set"
		date = "2015/01/19"
		hash = "2054cb427daaca9e267b252307dad03830475f15"
		id = "5da0c474-2dc8-5580-bf5c-d3f464225e4c"

	strings:
		$s0 = {63 61 74 20 74 72 75 65 75 73 65 72 73 2e 74 78 74 20 7c 20 6d 61 69 6c 20 2d 73 20 22 65 79 65 73 22 20 63 6c 75 62 62 79 40 73 6c 75 63 69 61 2e 63 6f 6d}
		$s1 = {65 63 68 6f 20 2d 65 20 22 24 7b 42 4c 55 7d 50 72 69 76 61 74 65 20 53 63 61 6e 6e 65 72 20 42 79 20 52 61 70 68 61 65 6c 6c 6f 20 2c 20 44 65 4d 4d 6f 4e 4e 20 2c 20 74 7a 65 70 65 6c 75 73 68 20 26 20 44 72 61 43 5c 6e 5c 72}
		$s3 = {6b 69 6c 6c 61 6c 6c 20 2d 39 20 70 73 63 61 6e 32}
		$s5 = {65 63 68 6f 20 22 5b 2a 5d 20 24 7b 44 43 59 4e 7d 47 61 74 61 20 65 73 74 69 20 68 34 78 30 72 20 3b 2d 29 24 7b 52 45 53 7d 20 20 5b 2a 5d 22}
		$s6 = {65 63 68 6f 20 2d 65 20 22 24 7b 44 43 59 4e 7d 40 23 40 23 40 23 40 23 40 23 40 23 40 23 40 23 40 23 40 23 40 23 40 23 40 23 40 23 40 23 40 23 40 23 40 23 40 23 40 23 40 23 40 23 40 23 40 23 40 23 40 23 40 23 24 7b 52 45 53 7d 22}

	condition:
		1 of them
}

rule LinuxHacktool_eyes_pscan2_2 : hardened
{
	meta:
		description = "Linux hack tools - file pscan2.c"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "not set"
		date = "2015/01/19"
		hash = "eb024dfb441471af7520215807c34d105efa5fd8"
		id = "3950b235-70bc-5afd-add5-38c50055b28b"

	strings:
		$s0 = {73 6e 70 72 69 6e 74 66 28 6f 75 74 66 69 6c 65 2c 20 73 69 7a 65 6f 66 28 6f 75 74 66 69 6c 65 29 20 2d 20 31 2c 20 22 73 63 61 6e 2e 6c 6f 67 22 2c 20 61 72 67 76 5b 31 5d 2c 20 61 72 67 76 5b 32 5d 29 3b}
		$s2 = {70 72 69 6e 74 66 28 22 55 73 61 67 65 3a 20 25 73 20 3c 62 2d 62 6c 6f 63 6b 3e 20 3c 70 6f 72 74 3e 20 5b 63 2d 62 6c 6f 63 6b 5d 5c 6e 22 2c 20 61 72 67 76 5b 30 5d 29 3b}
		$s3 = {70 72 69 6e 74 66 28 22 5c 6e 23 20 70 73 63 61 6e 20 63 6f 6d 70 6c 65 74 65 64 20 69 6e 20 25 75 20 73 65 63 6f 6e 64 73 2e 20 28 66 6f 75 6e 64 20 25 64 20 69 70 73 29 5c 6e 22 2c 20 28 74 69 6d 65 28 30 29 20 2d 20 73 63 61}
		$s19 = {63 6f 6e 6e 6c 69 73 74 5b 69 5d 2e 61 64 64 72 2e 73 69 6e 5f 66 61 6d 69 6c 79 20 3d 20 41 46 5f 49 4e 45 54 3b}
		$s20 = {73 6e 70 72 69 6e 74 66 28 6c 61 73 74 2c 20 73 69 7a 65 6f 66 28 6c 61 73 74 29 20 2d 20 31 2c 20 22 25 73 2e 25 64 2e 2a 20 28 74 6f 74 61 6c 3a 20 25 64 29 20 28 25 2e 31 66 25 25 20 64 6f 6e 65 29 22 2c}

	condition:
		2 of them
}

rule CN_Portscan : APT hardened
{
	meta:
		description = "CN Port Scanner"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2013-11-29"
		confidential = false
		score = 70
		id = "fb52a89a-2270-5170-9874-9278a0177454"

	strings:
		$s2 = {54 43 50 20 31 32 2e 31 32 2e 31 32 2e 31 32}

	condition:
		uint16( 0 ) == 0x5A4D and $s2
}

rule WMI_vbs : APT hardened
{
	meta:
		description = "WMI Tool - APT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2013-11-29"
		confidential = false
		score = 70
		id = "b367306a-38d8-5f4d-8f09-2bf025831f0a"

	strings:
		$s3 = {57 53 63 72 69 70 74 2e 45 63 68 6f 20 22 20 20 20 24 24 5c 20 20 20 20 20 20 24 24 5c 20 24 24 5c 20 20 20 20 20 20 24 24 5c 20 24 24 24 24 24 24 5c 20 24 24 24 24 24 24 24 24 5c 20 24 24 5c 20 20 20 24 24 5c 20 24 24 24 24 24 24 24 24 5c 20 20 24 24 24 24 24 24}

	condition:
		all of them
}

rule CN_Toolset__XScanLib_XScanLib_XScanLib : hardened
{
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - from files XScanLib.dll, XScanLib.dll, XScanLib.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		date = "2015/03/30"
		score = 70
		super_rule = 1
		hash0 = "af419603ac28257134e39683419966ab3d600ed2"
		hash1 = "c5cb4f75cf241f5a9aea324783193433a42a13b0"
		hash2 = "135f6a28e958c8f6a275d8677cfa7cb502c8a822"
		id = "c32415f4-044c-50ef-9c4c-b9327cbcef69"

	strings:
		$s1 = {50 6c 75 67 2d 69 6e 20 74 68 72 65 61 64 20 63 61 75 73 65 73 20 61 6e 20 65 78 63 65 70 74 69 6f 6e 2c 20 66 61 69 6c 65 64 20 74 6f 20 61 6c 65 72 74 20 75 73 65 72 2e}
		$s2 = {50 6c 75 67 47 65 74 55 64 70 50 6f 72 74}
		$s3 = {58 53 63 61 6e 4c 69 62 2e 64 6c 6c}
		$s4 = {50 6c 75 67 47 65 74 54 63 70 50 6f 72 74}
		$s11 = {50 6c 75 67 47 65 74 56 75 6c 6e 4e 75 6d}

	condition:
		all of them
}

rule CN_Toolset_NTscan_PipeCmd : hardened
{
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - file PipeCmd.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		date = "2015/03/30"
		score = 70
		hash = "a931d65de66e1468fe2362f7f2e0ee546f225c4e"
		id = "056ee42d-23f4-5b03-b240-392bc92b90b0"

	strings:
		$s2 = {50 6c 65 61 73 65 20 55 73 65 20 4e 54 43 6d 64 2e 65 78 65 20 52 75 6e 20 54 68 69 73 20 50 72 6f 67 72 61 6d 2e}
		$s3 = {50 00 69 00 70 00 65 00 43 00 6d 00 64 00 2e 00 65 00 78 00 65 00}
		$s4 = {5c 5c 2e 5c 70 69 70 65 5c 25 73 25 73 25 64}
		$s5 = {25 73 5c 70 69 70 65 5c 25 73 25 73 25 64}
		$s6 = {25 73 5c 41 44 4d 49 4e 24 5c 53 79 73 74 65 6d 33 32 5c 25 73 25 73}
		$s7 = {25 73 5c 41 44 4d 49 4e 24 5c 53 79 73 74 65 6d 33 32 5c 25 73}
		$s9 = {50 69 70 65 43 6d 64 53 72 76 2e 65 78 65}
		$s10 = {54 68 69 73 20 69 73 20 61 20 73 65 72 76 69 63 65 20 65 78 65 63 75 74 61 62 6c 65 21 20 43 6f 75 6c 64 6e 27 74 20 73 74 61 72 74 20 64 69 72 65 63 74 6c 79 2e}
		$s13 = {5c 5c 2e 5c 70 69 70 65 5c 50 69 70 65 43 6d 64 5f 63 6f 6d 6d 75 6e 69 63 61 74 6f 6e}
		$s14 = {50 00 49 00 50 00 45 00 43 00 4d 00 44 00 53 00 52 00 56 00}
		$s15 = {50 69 70 65 43 6d 64 20 53 65 72 76 69 63 65}

	condition:
		4 of them
}

rule CN_Toolset_LScanPortss_2 : hardened
{
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - file LScanPortss.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		date = "2015/03/30"
		score = 70
		hash = "4631ec57756466072d83d49fbc14105e230631a0"
		id = "0a796585-5fc8-5b55-acfc-3fe87308b681"

	strings:
		$s1 = {4c 00 53 00 63 00 61 00 6e 00 50 00 6f 00 72 00 74 00 2e 00 45 00 58 00 45 00}
		$s3 = {77 00 77 00 77 00 2e 00 68 00 6f 00 6e 00 6b 00 65 00 72 00 38 00 2e 00 63 00 6f 00 6d 00}
		$s4 = {44 65 66 61 75 6c 74 50 6f 72 74 2e 6c 73 74}
		$s5 = {53 63 61 6e 20 6f 76 65 72 2e 55 73 65 64 20 25 64 6d 73 21}
		$s6 = {77 00 77 00 77 00 2e 00 68 00 66 00 31 00 31 00 30 00 2e 00 63 00 6f 00 6d 00}
		$s15 = {4c 00 53 00 63 00 61 00 6e 00 50 00 6f 00 72 00 74 00 20 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00}
		$s18 = {4c 00 2d 00 53 00 63 00 61 00 6e 00 50 00 6f 00 72 00 74 00 32 00 2e 00 30 00 20 00 43 00 6f 00 6f 00 46 00 6c 00 79 00}

	condition:
		4 of them
}

rule CN_Toolset_sig_1433_135_sqlr : hardened
{
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - file sqlr.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		date = "2015/03/30"
		score = 70
		hash = "8542c7fb8291b02db54d2dc58cd608e612bfdc57"
		id = "74038975-ef06-53d6-bdcc-02706408b596"

	strings:
		$s0 = {43 6f 6e 6e 65 63 74 20 74 6f 20 25 73 20 4d 53 53 51 4c 20 73 65 72 76 65 72 20 73 75 63 63 65 73 73 2e 20 54 79 70 65 20 43 6f 6d 6d 61 6e 64 20 61 74 20 50 72 6f 6d 70 74 2e}
		$s11 = {3b 44 41 54 41 42 41 53 45 3d 6d 61 73 74 65 72}
		$s12 = {78 70 5f 63 6d 64 73 68 65 6c 6c 20 27}
		$s14 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 4f 50 45 4e 52 4f 57 53 45 54 28 27 53 51 4c 4f 4c 45 44 42 27 2c 27 54 72 75 73 74 65 64 5f 43 6f 6e 6e 65 63 74 69 6f 6e 3d 59 65 73 3b 44 61 74 61 20 53 6f 75 72 63 65 3d 6d 79 73 65 72 76 65 72}

	condition:
		all of them
}

rule VSSown_VBS : hardened
{
	meta:
		description = "Detects VSSown.vbs script - used to export shadow copy elements like NTDS to take away and crack elsewhere"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2015-10-01"
		score = 75
		id = "ffbb5faf-3522-50dc-a568-503074ac0636"

	strings:
		$s0 = {53 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 57 69 6e 33 32 5f 53 65 72 76 69 63 65 20 57 68 65 72 65 20 4e 61 6d 65 20 3d 27 56 53 53 27}
		$s1 = {53 65 6c 65 63 74 20 2a 20 46 72 6f 6d 20 57 69 6e 33 32 5f 53 68 61 64 6f 77 43 6f 70 79}
		$s2 = {63 6d 64 20 2f 43 20 6d 6b 6c 69 6e 6b 20 2f 44 20}
		$s3 = {43 6c 69 65 6e 74 41 63 63 65 73 73 69 62 6c 65}
		$s4 = {57 53 63 72 69 70 74 2e 53 68 65 6c 6c}
		$s5 = {57 69 6e 33 32 5f 50 72 6f 63 65 73 73}

	condition:
		all of them
}

rule Netview_Hacktool : hardened
{
	meta:
		description = "Network domain enumeration tool - often used by attackers - file Nv.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/mubix/netview"
		date = "2016-03-07"
		score = 60
		hash = "52cec98839c3b7d9608c865cfebc904b4feae0bada058c2e8cdbd561cfa1420a"
		id = "087e2fd7-726e-5c6b-ba99-e20dd3337d6a"

	strings:
		$s1 = {5b 00 2b 00 5d 00 20 00 25 00 77 00 73 00 20 00 2d 00 20 00 54 00 61 00 72 00 67 00 65 00 74 00 20 00 75 00 73 00 65 00 72 00 20 00 66 00 6f 00 75 00 6e 00 64 00 20 00 2d 00 20 00 25 00 73 00 5c 00 25 00 73 00}
		$s2 = {5b 2a 5d 20 2d 67 20 75 73 65 64 20 77 69 74 68 6f 75 74 20 67 72 6f 75 70 20 73 70 65 63 69 66 69 65 64 20 2d 20 75 73 69 6e 67 20 22 44 6f 6d 61 69 6e 20 41 64 6d 69 6e 73 22}
		$s3 = {5b 2a 5d 20 2d 69 20 75 73 65 64 20 77 69 74 68 6f 75 74 20 69 6e 74 65 72 76 61 6c 20 73 70 65 63 69 66 69 65 64 20 2d 20 69 67 6e 6f 72 69 6e 67}
		$s4 = {5b 00 2b 00 5d 00 20 00 25 00 77 00 73 00 20 00 2d 00 20 00 53 00 65 00 73 00 73 00 69 00 6f 00 6e 00 20 00 2d 00 20 00 25 00 73 00 20 00 66 00 72 00 6f 00 6d 00 20 00 25 00 73 00 20 00 2d 00 20 00 41 00 63 00 74 00 69 00 76 00 65 00 3a 00 20 00 25 00 64 00 20 00 2d 00 20 00 49 00 64 00 6c 00 65 00 3a 00 20 00 25 00 64 00}
		$s5 = {5b 00 2b 00 5d 00 20 00 25 00 77 00 73 00 20 00 2d 00 20 00 42 00 61 00 63 00 6b 00 75 00 70 00 20 00 44 00 6f 00 6d 00 61 00 69 00 6e 00 20 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 6c 00 65 00 72 00}
		$s6 = {5b 00 2d 00 5d 00 20 00 25 00 6c 00 73 00 20 00 2d 00 20 00 53 00 68 00 61 00 72 00 65 00 20 00 2d 00 20 00 45 00 72 00 72 00 6f 00 72 00 3a 00 20 00 25 00 6c 00 64 00}
		$s7 = {5b 00 2d 00 5d 00 20 00 25 00 6c 00 73 00 20 00 2d 00 20 00 53 00 65 00 73 00 73 00 69 00 6f 00 6e 00 20 00 2d 00 20 00 45 00 72 00 72 00 6f 00 72 00 3a 00 20 00 25 00 6c 00 64 00}
		$s8 = {5b 2b 5d 20 25 73 20 2d 20 4f 53 20 56 65 72 73 69 6f 6e 20 2d 20 25 64 2e 25 64}
		$s9 = {45 6e 75 6d 65 72 61 74 69 6e 67 20 4c 6f 67 67 65 64 2d 6f 6e 20 55 73 65 72 73}
		$s10 = {3a 20 53 70 65 63 69 66 69 65 73 20 61 20 64 6f 6d 61 69 6e 20 74 6f 20 70 75 6c 6c 20 61 20 6c 69 73 74 20 6f 66 20 68 6f 73 74 73 20 66 72 6f 6d}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 500KB and 2 of them ) or 3 of them
}

rule Netview_Hacktool_Output : hardened
{
	meta:
		description = "Network domain enumeration tool output - often used by attackers - file filename.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/mubix/netview"
		date = "2016-03-07"
		score = 60
		id = "259db870-6293-5a55-b56a-f981c060c18f"

	strings:
		$s1 = {5b 2a 5d 20 55 73 69 6e 67 20 69 6e 74 65 72 76 61 6c 3a}
		$s2 = {5b 2a 5d 20 55 73 69 6e 67 20 6a 69 74 74 65 72 3a}
		$s3 = {5b 2b 5d 20 4e 75 6d 62 65 72 20 6f 66 20 68 6f 73 74 73 3a}

	condition:
		2 of them
}

rule PSAttack_EXE : hardened
{
	meta:
		description = "PSAttack - Powershell attack tool - file PSAttack.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/gdssecurity/PSAttack/releases/"
		date = "2016-03-09"
		modified = "2023-01-06"
		score = 100
		hash = "ad05d75640c850ee7eeee26422ba4f157be10a4e2d6dc6eaa19497d64cf23715"
		id = "87f7956a-f607-5e14-a940-5080499cf682"

	strings:
		$x1 = {5c 52 65 6c 65 61 73 65 5c 50 53 41 74 74 61 63 6b 2e 70 64 62}
		$s1 = {73 00 65 00 74 00 2d 00 65 00 78 00 65 00 63 00 75 00 74 00 69 00 6f 00 6e 00 70 00 6f 00 6c 00 69 00 63 00 79 00 20 00 62 00 79 00 70 00 61 00 73 00 73 00 20 00 2d 00 53 00 63 00 6f 00 70 00 65 00 20 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 2d 00 46 00 6f 00 72 00 63 00 65 00}
		$s2 = {50 53 41 74 74 61 63 6b 2e 4d 6f 64 75 6c 65 73 2e}
		$s3 = {50 53 41 74 74 61 63 6b 2e 50 53 41 74 74 61 63 6b 50 72 6f 63 65 73 73 69 6e 67}
		$s4 = {50 00 53 00 41 00 74 00 74 00 61 00 63 00 6b 00 2e 00 4d 00 6f 00 64 00 75 00 6c 00 65 00 73 00 2e 00 6b 00 65 00 79 00 2e 00 74 00 78 00 74 00}

	condition:
		( uint16( 0 ) == 0x5a4d and ( $x1 or 2 of ( $s* ) ) ) or 3 of them
}

rule Powershell_Attack_Scripts : hardened
{
	meta:
		description = "Powershell Attack Scripts"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2016-03-09"
		score = 70
		id = "e8c4a672-229b-56c8-811b-071ae9ff341e"

	strings:
		$s1 = {50 6f 77 65 72 73 68 65 6c 6c 4d 61 66 69 61 5c 49 6e 76 6f 6b 65 2d 53 68 65 6c 6c 63 6f 64 65 2e 70 73 31}
		$s2 = {4e 69 73 68 61 6e 67 5c 44 6f 2d 45 78 66 69 6c 74 72 61 74 69 6f 6e 2e 70 73 31}
		$s3 = {50 6f 77 65 72 73 68 65 6c 6c 4d 61 66 69 61 5c 49 6e 76 6f 6b 65 2d 4d 69 6d 69 6b 61 74 7a 2e 70 73 31}
		$s4 = {49 6e 76 65 69 67 68 5c 49 6e 76 65 69 67 68 2e 70 73 31}

	condition:
		1 of them
}

rule PSAttack_ZIP : hardened
{
	meta:
		description = "PSAttack - Powershell attack tool - file PSAttack.zip"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/gdssecurity/PSAttack/releases/"
		date = "2016-03-09"
		score = 100
		hash = "3864f0d44f90404be0c571ceb6f95bbea6c527bbfb2ec4a2b4f7d92e982e15a2"
		id = "4e064eb4-0b87-590c-9ee4-6764b982c006"

	strings:
		$s0 = {50 53 41 74 74 61 63 6b 2e 65 78 65}

	condition:
		uint16( 0 ) == 0x4b50 and all of them
}

rule Linux_Portscan_Shark_1 : hardened
{
	meta:
		description = "Detects Linux Port Scanner Shark"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Virustotal Research - see https://github.com/Neo23x0/Loki/issues/35"
		date = "2016-04-01"
		super_rule = 1
		hash1 = "4da0e535c36c0c52eaa66a5df6e070c52e7ddba13816efc3da5691ea2ec06c18"
		hash2 = "e395ca5f932419a4e6c598cae46f17b56eb7541929cdfb67ef347d9ec814dea3"
		id = "0b264106-3536-56f4-9e8c-68f3756af07d"

	strings:
		$s0 = {72 6d 20 2d 72 66 20 73 63 61 6e 2e 6c 6f 67 20 73 65 73 73 69 6f 6e 2e 74 78 74}
		$s17 = {2a 2a 2a 20 62 75 66 66 65 72 20 6f 76 65 72 66 6c 6f 77 20 64 65 74 65 63 74 65 64 20 2a 2a 2a 3a 20 25 73 20 74 65 72 6d 69 6e 61 74 65 64}
		$s18 = {2a 2a 2a 20 73 74 61 63 6b 20 73 6d 61 73 68 69 6e 67 20 64 65 74 65 63 74 65 64 20 2a 2a 2a 3a 20 25 73 20 74 65 72 6d 69 6e 61 74 65 64}

	condition:
		( uint16( 0 ) == 0x7362 and all of them )
}

rule Linux_Portscan_Shark_2 : hardened
{
	meta:
		description = "Detects Linux Port Scanner Shark"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Virustotal Research - see https://github.com/Neo23x0/Loki/issues/35"
		date = "2016-04-01"
		super_rule = 1
		hash1 = "5f80bd2db608a47e26290f3385eeb5bfc939d63ba643f06c4156704614def986"
		hash2 = "90af44cbb1c8a637feda1889d301d82fff7a93b0c1a09534909458a64d8d8558"
		id = "eea378d5-0399-5035-8573-139878fa1abc"

	strings:
		$s1 = {75 73 61 67 65 3a 20 25 73 20 3c 66 69 73 69 65 72 20 69 70 75 72 69 3e 20 3c 66 69 73 69 65 72 20 75 73 65 72 69 3a 70 61 72 6f 6c 65 3e 20 3c 63 6f 6e 6e 65 63 74 20 74 69 6d 65 6f 75 74 3e 20 3c 66 61 69 6c 32 62 61 6e 20 77 61 69 74 3e 20 3c 74 68 72 65 61 64 73 3e 20 3c 6f 75 74 66 69 6c 65 3e 20 3c 70 6f 72 74 3e}
		$s2 = {44 69 66 66 65 72 65 6e 63 65 20 62 65 74 77 65 65 6e 20 73 65 72 76 65 72 20 6d 6f 64 75 6c 75 73 20 61 6e 64 20 68 6f 73 74 20 6d 6f 64 75 6c 75 73 20 69 73 20 6f 6e 6c 79 20 25 64 2e 20 49 74 27 73 20 69 6c 6c 65 67 61 6c 20 61 6e 64 20 6d 61 79 20 6e 6f 74 20 77 6f 72 6b}
		$s3 = {72 6d 20 2d 72 66 20 73 63 61 6e 2e 6c 6f 67}

	condition:
		all of them
}

rule dnscat2_Hacktool : hardened
{
	meta:
		description = "Detects dnscat2 - from files dnscat, dnscat2.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://downloads.skullsecurity.org/dnscat2/"
		date = "2016-05-15"
		super_rule = 1
		hash1 = "8bc8d6c735937c9c040cbbdcfc15f17720a7ecef202a19a7bf43e9e1c66fe66a"
		hash2 = "4a882f013419695c8c0ac41d8a0fde1cf48172a89e342c504138bc6f1d13c7c8"
		id = "23cca0fe-3e4e-5b91-8b53-933de8ff264a"

	strings:
		$s1 = {2d 2d 65 78 65 63 20 2d 65 20 3c 70 72 6f 63 65 73 73 3e 20 20 20 20 20 45 78 65 63 75 74 65 20 74 68 65 20 67 69 76 65 6e 20 70 72 6f 63 65 73 73 20 61 6e 64 20 6c 69 6e 6b 20 69 74 20 74 6f 20 74 68 65 20 73 74 72 65 61 6d 2e}
		$s2 = {53 61 77 6c 6f 67}
		$s3 = {43 4f 4d 4d 41 4e 44 5f 45 58 45 43 20 5b 72 65 71 75 65 73 74 5d 20 3a 3a 20 72 65 71 75 65 73 74 5f 69 64 3a 20 30 78 25 30 34 78 20 3a 3a 20 6e 61 6d 65 3a 20 25 73 20 3a 3a 20 63 6f 6d 6d 61 6e 64 3a 20 25 73}
		$s4 = {43 4f 4d 4d 41 4e 44 5f 53 48 45 4c 4c 20 5b 72 65 71 75 65 73 74 5d 20 3a 3a 20 72 65 71 75 65 73 74 5f 69 64 3a 20 30 78 25 30 34 78 20 3a 3a 20 6e 61 6d 65 3a 20 25 73}
		$s5 = {5b 54 75 6e 6e 65 6c 20 25 64 5d 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 74 6f 20 25 73 3a 25 64 20 63 6c 6f 73 65 64 20 62 79 20 74 68 65 20 73 65 72 76 65 72 21}

	condition:
		(( uint16( 0 ) == 0x457f or uint16( 0 ) == 0x5a4d ) and filesize < 400KB and ( 2 of ( $s* ) ) ) or ( all of them )
}

rule WCE_in_memory : hardened
{
	meta:
		description = "Detects Windows Credential Editor (WCE) in memory (and also on disk)"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		score = 80
		date = "2016-08-28"
		id = "90c90ca5-e3be-5035-b35c-c2e7faec43a5"

	strings:
		$s1 = {77 6b 4b 55 53 76 66 6c 65 68 48 72 3a 3a 6f 3a 74 3a 73 3a 63 3a 69 3a 64 3a 61 3a 67 3a}
		$s2 = {77 63 65 61 75 78 2e 64 6c 6c}

	condition:
		all of them
}

rule pstgdump : hardened
{
	meta:
		description = "Detects a tool used by APT groups - file pstgdump.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/igxLyF"
		date = "2016-09-08"
		hash1 = "65d48a2f868ff5757c10ed796e03621961954c523c71eac1c5e044862893a106"
		id = "86a105a3-b5b5-58b2-99bd-ec05f31adb6b"

	strings:
		$x1 = {5c 52 65 6c 65 61 73 65 5c 70 73 74 67 64 75 6d 70 2e 70 64 62}
		$x2 = {46 61 69 6c 65 64 20 74 6f 20 64 75 6d 70 20 61 6c 6c 20 70 72 6f 74 65 63 74 65 64 20 73 74 6f 72 61 67 65 20 69 74 65 6d 73 20 2d 20 73 65 65 20 70 72 65 76 69 6f 75 73 20 6d 65 73 73 61 67 65 73 20 66 6f 72 20 64 65 74 61 69 6c 73}
		$x3 = {70 74 73 67 64 75 6d 70 20 5b 2d 68 5d 5b 2d 71 5d 5b 2d 75 20 55 73 65 72 6e 61 6d 65 5d 5b 2d 70 20 50 61 73 73 77 6f 72 64 5d}
		$x4 = {41 74 74 65 6d 70 74 69 6e 67 20 74 6f 20 69 6d 70 65 72 73 6f 6e 61 74 65 20 64 6f 6d 61 69 6e 20 75 73 65 72 20 27 25 73 27 20 69 6e 20 64 6f 6d 61 69 6e 20 27 25 73 27}
		$x5 = {46 61 69 6c 65 64 20 74 6f 20 69 6d 70 65 72 73 6f 6e 61 74 65 20 75 73 65 72 20 28 49 6d 70 65 72 73 6f 6e 61 74 65 4c 6f 67 67 65 64 4f 6e 55 73 65 72 20 66 61 69 6c 65 64 29 3a 20 65 72 72 6f 72 20 25 64}
		$x6 = {55 6e 61 62 6c 65 20 74 6f 20 6f 62 74 61 69 6e 20 68 61 6e 64 6c 65 20 74 6f 20 50 53 74 6f 72 65 43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 20 69 6e 20 70 73 74 6f 72 65 63 2e 64 6c 6c}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 200KB and 1 of ( $x* ) ) or ( 3 of them )
}

rule lsremora : hardened
{
	meta:
		description = "Detects a tool used by APT groups"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/igxLyF"
		date = "2016-09-08"
		hash1 = "efa66f6391ec471ca52cd053159c8a8778f11f921da14e6daf76387f8c9afcd5"
		hash2 = "e0327c1218fd3723e20acc780e20135f41abca35c35e0f97f7eccac265f4f44e"
		id = "c15c583f-70cd-5a80-bdea-a14582097e50"

	strings:
		$x1 = {54 61 72 67 65 74 3a 20 46 61 69 6c 65 64 20 74 6f 20 6c 6f 61 64 20 70 72 69 6d 61 72 79 20 53 41 4d 20 66 75 6e 63 74 69 6f 6e 73 2e}
		$x2 = {6c 73 72 65 6d 6f 72 61 36 34 2e 64 6c 6c}
		$x3 = {50 00 77 00 44 00 75 00 6d 00 70 00 45 00 72 00 72 00 6f 00 72 00 3a 00 39 00 39 00 39 00 39 00 39 00 39 00}
		$x4 = {50 00 77 00 44 00 75 00 6d 00 70 00 45 00 72 00 72 00 6f 00 72 00}
		$x5 = {6c 73 72 65 6d 6f 72 61 2e 64 6c 6c}
		$s1 = {3a 5c 5c 2e 5c 70 69 70 65 5c 25 73}
		$s2 = {78 00 25 00 73 00 5f 00 68 00 69 00 73 00 74 00 6f 00 72 00 79 00 5f 00 25 00 64 00 3a 00 25 00 64 00}
		$s3 = {55 73 69 6e 67 20 70 69 70 65 20 25 73}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 200KB and 1 of ( $x* ) ) or ( 3 of them )
}

rule servpw : hardened
{
	meta:
		description = "Detects a tool used by APT groups - file servpw.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/igxLyF"
		date = "2016-09-08"
		hash1 = "97b39ac28794a7610ed83ad65e28c605397ea7be878109c35228c126d43e2f46"
		hash2 = "0f340b471ef34c69f5413540acd3095c829ffc4df38764e703345eb5e5020301"
		id = "48b9dae1-16b3-563c-ac4e-b71f3a86b38a"

	strings:
		$s1 = {55 6e 61 62 6c 65 20 74 6f 20 6f 70 65 6e 20 74 61 72 67 65 74 20 70 72 6f 63 65 73 73 3a 20 25 64 2c 20 70 69 64 20 25 64}
		$s2 = {4c 00 53 00 41 00 53 00 53 00 2e 00 45 00 58 00 45 00}
		$s3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 20 66 61 69 6c 65 64 3a 20 25 64}
		$s4 = {6c 73 72 65 6d 6f 72 61 36 34 2e 64 6c 6c}
		$s5 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 20 66 61 69 6c 65 64 3a 20 25 64}
		$s6 = {54 68 72 65 61 64 20 63 6f 64 65 3a 20 25 64 2c 20 70 61 74 68 3a 20 25 73}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 200KB and 3 of them ) or ( all of them )
}

rule fgexec : hardened
{
	meta:
		description = "Detects a tool used by APT groups - file fgexec.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/igxLyF"
		date = "2016-09-08"
		hash1 = "8697897bee415f213ce7bc24f22c14002d660b8aaffab807490ddbf4f3f20249"
		id = "8ffe47b9-81a8-5eb4-b46f-db9d23682de4"

	strings:
		$x1 = {5c 52 65 6c 65 61 73 65 5c 66 67 65 78 65 63 2e 70 64 62}
		$x2 = {66 67 65 78 65 63 20 52 65 6d 6f 74 65 20 50 72 6f 63 65 73 73 20 45 78 65 63 75 74 69 6f 6e 20 54 6f 6f 6c}
		$x3 = {66 67 65 78 65 63 20 43 61 6c 6c 4e 61 6d 65 64 50 69 70 65 20 66 61 69 6c 65 64}
		$x4 = {66 69 7a 7a 67 69 67 20 61 6e 64 20 74 68 65 20 6d 69 67 68 74 79 20 66 6f 6f 66 75 73 2e 6e 65 74 20 74 65 61 6d}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 100KB and 1 of ( $x* ) ) or ( 3 of them )
}

rule cachedump : hardened
{
	meta:
		description = "Detects a tool used by APT groups - from files cachedump.exe, cachedump64.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/igxLyF"
		date = "2016-09-08"
		super_rule = 1
		hash1 = "cf58ca5bf8c4f87bb67e6a4e1fb9e8bada50157dacbd08a92a4a779e40d569c4"
		hash2 = "e38edac8c838a043d0d9d28c71a96fe8f7b7f61c5edf69f1ce0c13e141be281f"
		id = "ebcaeb73-d2df-5a4c-9f50-b4a01293b88b"

	strings:
		$s1 = {46 61 69 6c 65 64 20 74 6f 20 6f 70 65 6e 20 6b 65 79 20 53 45 43 55 52 49 54 59 5c 43 61 63 68 65 20 69 6e 20 52 65 67 4f 70 65 6e 4b 65 79 45 78 2e 20 49 73 20 73 65 72 76 69 63 65 20 72 75 6e 6e 69 6e 67 20 61 73 20 53 59 53 54 45 4d 20 3f 20 44 6f 20 79 6f 75 20 65 76 65 72 20 6c 6f 67 20 6f 6e 20 64 6f 6d 61 69 6e 20 3f 20}
		$s2 = {55 6e 61 62 6c 65 20 74 6f 20 6f 70 65 6e 20 4c 53 41 53 53 2e 45 58 45 20 70 72 6f 63 65 73 73}
		$s3 = {53 65 72 76 69 63 65 20 6e 6f 74 20 66 6f 75 6e 64 2e 20 49 6e 73 74 61 6c 6c 69 6e 67 20 43 61 63 68 65 44 75 6d 70 20 53 65 72 76 69 63 65 20 28 25 73 29}
		$s4 = {43 61 63 68 65 44 75 6d 70 20 73 65 72 76 69 63 65 20 73 75 63 63 65 73 73 66 75 6c 6c 79 20 69 6e 73 74 61 6c 6c 65 64 2e}
		$s5 = {4b 69 6c 6c 20 43 61 63 68 65 44 75 6d 70 20 73 65 72 76 69 63 65 20 28 73 68 6f 75 6c 64 6e 27 74 20 62 65 20 75 73 65 64 29}
		$s6 = {63 61 63 68 65 44 75 6d 70 20 5b 2d 76 20 7c 20 2d 76 76 20 7c 20 2d 4b 5d}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 500KB and 1 of them ) or ( 3 of them )
}

rule PwDump_B : hardened
{
	meta:
		description = "Detects a tool used by APT groups - file PwDump.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/igxLyF"
		date = "2016-09-08"
		hash1 = "3c796092f42a948018c3954f837b4047899105845019fce75a6e82bc99317982"
		id = "aad974f1-76bf-5aae-8376-a4fd3f27b345"

	strings:
		$x1 = {55 73 61 67 65 3a 20 25 73 20 5b 2d 78 5d 5b 2d 6e 5d 5b 2d 68 5d 5b 2d 6f 20 6f 75 74 70 75 74 5f 66 69 6c 65 5d 5b 2d 75 20 75 73 65 72 5d 5b 2d 70 20 70 61 73 73 77 6f 72 64 5d 5b 2d 73 20 73 68 61 72 65 5d 20 6d 61 63 68 69 6e 65 4e 61 6d 65}
		$x2 = {70 77 64 75 6d 70 36 20 56 65 72 73 69 6f 6e 20 25 73 20 62 79 20 66 69 7a 7a 67 69 67 20 61 6e 64 20 74 68 65 20 6d 69 67 68 74 79 20 67 72 6f 75 70 20 61 74 20 66 6f 6f 66 75 73 2e 6e 65 74}
		$x3 = {77 68 65 72 65 20 2d 78 20 74 61 72 67 65 74 73 20 61 20 36 34 2d 62 69 74 20 68 6f 73 74}
		$x4 = {43 6f 75 6c 64 6e 27 74 20 64 65 6c 65 74 65 20 74 61 72 67 65 74 20 65 78 65 63 75 74 61 62 6c 65 20 66 72 6f 6d 20 72 65 6d 6f 74 65 20 6d 61 63 68 69 6e 65 3a 20 25 64}
		$s1 = {6c 73 72 65 6d 6f 72 61 36 34 2e 64 6c 6c}
		$s2 = {6c 73 72 65 6d 6f 72 61 2e 64 6c 6c}
		$s3 = {73 65 72 76 70 77 2e 65 78 65}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 400KB and 1 of ( $x* ) ) or ( 3 of them )
}

rule MSBuild_Mimikatz_Execution_via_XML : hardened
{
	meta:
		description = "Detects an XML that executes Mimikatz on an endpoint via MSBuild"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://gist.github.com/subTee/c98f7d005683e616560bda3286b6a0d8#file-katz-xml"
		date = "2016-10-07"
		id = "98aa68b9-6de4-5353-8d87-9e974529c044"

	strings:
		$x1 = {3c 50 72 6f 6a 65 63 74 20 54 6f 6f 6c 73 56 65 72 73 69 6f 6e 3d}
		$x2 = {3c 2f 53 68 61 72 70 4c 61 75 6e 63 68 65 72 3e}
		$s1 = {22 54 56 71 51 41 41 4d 41 41 41 41}
		$s2 = {53 79 73 74 65 6d 2e 43 6f 6e 76 65 72 74 2e 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28}
		$s3 = {2e 49 6e 76 6f 6b 65 28}
		$s4 = {41 73 73 65 6d 62 6c 79 2e 4c 6f 61 64 28}
		$s5 = {2e 43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 28}

	condition:
		all of them
}

rule Fscan_Portscanner : hardened
{
	meta:
		description = "Fscan port scanner scan output / strings"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/JamesHabben/status/817112447970480128"
		date = "2017-01-06"
		id = "400383dc-8bc0-5e77-a3f3-d6ba9f4c3c0f"

	strings:
		$s1 = {54 69 6d 65 20 74 61 6b 65 6e 3a}
		$s2 = {53 63 61 6e 20 66 69 6e 69 73 68 65 64 20 61 74}
		$s3 = {53 63 61 6e 20 73 74 61 72 74 65 64 20 61 74}

	condition:
		filesize < 20KB and 3 of them
}

rule WPR_loader_EXE : hardened
{
	meta:
		description = "Windows Password Recovery - file loader.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-03-15"
		hash1 = "e7d158d27d9c14a4f15a52ee5bf8aa411b35ad510b1b93f5e163ae7819c621e2"
		id = "97fa3efb-9e7a-52ef-9e26-3fdd573d4d30"

	strings:
		$s1 = {46 00 61 00 69 00 6c 00 65 00 64 00 20 00 74 00 6f 00 20 00 67 00 65 00 74 00 20 00 73 00 79 00 73 00 74 00 65 00 6d 00 20 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 49 00 44 00}
		$s2 = {67 00 4c 00 53 00 41 00 53 00 53 00 2e 00 45 00 58 00 45 00}
		$s3 = {57 00 72 00 69 00 74 00 65 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 20 00 66 00 61 00 69 00 6c 00 65 00 64 00}
		$s4 = {77 00 6f 00 77 00 36 00 34 00 20 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 4e 00 4f 00 54 00 20 00 63 00 72 00 65 00 61 00 74 00 65 00 64 00}
		$s5 = {5c 00 61 00 73 00 74 00 2e 00 65 00 78 00 65 00}
		$s6 = {45 00 78 00 69 00 74 00 20 00 63 00 6f 00 64 00 65 00 3d 00 25 00 73 00 2c 00 20 00 73 00 74 00 61 00 74 00 75 00 73 00 3d 00 25 00 64 00}
		$s7 = {56 00 69 00 72 00 74 00 75 00 61 00 6c 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 20 00 66 00 61 00 69 00 6c 00 65 00 64 00}
		$s8 = {6e 00 53 00 65 00 44 00 65 00 62 00 75 00 67 00 50 00 72 00 69 00 76 00 69 00 6c 00 65 00 67 00 65 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 100KB and 3 of them )
}

rule WPR_loader_DLL : hardened
{
	meta:
		description = "Windows Password Recovery - file loader64.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-03-15"
		hash1 = "7b074cb99d45fc258e0324759ee970467e0f325e5d72c0b046c4142edc6776f6"
		hash2 = "a1f27f7fd0e03601a11b66d17cfacb202eacf34f94de3c4e9d9d39ea8d1a2612"
		id = "d3102ab6-0473-544b-b9dd-ec7a18ae1c4b"

	strings:
		$x1 = {6c 6f 61 64 65 72 36 34 2e 64 6c 6c}
		$x2 = {6c 6f 61 64 65 72 2e 64 6c 6c}
		$s1 = {54 55 6c 44 55 6b 39 54 54 30 5a 55 58 30 46 56 56 45 68 46 54 6c 52 4a 51 30 46 55 53 55 39 4f 58 31 42 42 51 30 74 42 52 30 56 66 56 6a 46 66 4d 41 3d 3d}
		$s2 = {55 6d 56 74 62 33 52 6c 52 47 56 7a 61 33 52 76 63 45 68 6c 62 48 42 42 63 33 4e 70 63 33 52 68 62 6e 52 42 59 32 4e 76 64 57 35 30}
		$s3 = {55 32 46 74 53 56 4a 6c 64 48 4a 70 5a 58 5a 6c 55 48 4a 70 62 57 46 79 65 55 4e 79 5a 57 52 6c 62 6e 52 70 59 57 78 7a}
		$s4 = {56 46 4d 36 53 57 35 30 5a 58 4a 75 5a 58 52 44 62 32 35 75 5a 57 4e 30 62 33 4a 51 63 33 64 6b}
		$s5 = {54 43 52 56 52 55 46 6a 64 47 39 79 51 57 78 30 51 33 4a 6c 5a 46 42 79 61 58 5a 68 64 47 56 4c 5a 58 6b 3d}
		$s6 = {59 58 4e 77 62 6d 56 30 58 31 64 51 58 31 42 42 55 31 4e 58 54 31 4a 45}
		$s7 = {54 43 52 42 54 6b 31 66 51 31 4a 46 52 45 56 4f 56 45 6c 42 54 46 4d 3d}
		$s8 = {52 47 56 6d 59 58 56 73 64 46 42 68 63 33 4e 33 62 33 4a 6b}
		$op0 = { 48 8b cd e8 e0 e8 ff ff 48 89 07 48 85 c0 74 72 }
		$op1 = { e8 ba 23 00 00 33 c9 ff 15 3e 82 }
		$op2 = { 48 83 c4 28 e9 bc 55 ff ff 48 8d 0d 4d a7 00 00 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 400KB and ( ( 1 of ( $x* ) and 1 of ( $s* ) ) or ( 1 of ( $s* ) and all of ( $op* ) ) )
}

rule WPR_Passscape_Loader : hardened
{
	meta:
		description = "Windows Password Recovery - file ast.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-03-15"
		hash1 = "f6f2d4b9f19f9311ec419f05224a1c17cf2449f2027cb7738294479eea56e9cb"
		id = "d8e224ce-edd2-5e2d-9b6e-a8995f5d2c1c"

	strings:
		$s1 = {53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 5c 00 50 00 61 00 73 00 73 00 63 00 61 00 70 00 65 00 4c 00 6f 00 61 00 64 00 65 00 72 00 36 00 34 00}
		$s2 = {61 73 74 36 34 2e 64 6c 6c}
		$s3 = {5c 00 6c 00 6f 00 61 00 64 00 65 00 72 00 36 00 34 00 2e 00 65 00 78 00 65 00}
		$s4 = {50 00 61 00 73 00 73 00 63 00 61 00 70 00 65 00 20 00 36 00 34 00 2d 00 62 00 69 00 74 00 20 00 4c 00 6f 00 61 00 64 00 65 00 72 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00}
		$s5 = {50 00 61 00 73 00 73 00 63 00 61 00 70 00 65 00 4c 00 6f 00 61 00 64 00 65 00 72 00 36 00 34 00}
		$s6 = {61 00 73 00 74 00 36 00 34 00 20 00 7b 00 6d 00 73 00 67 00 31 00 47 00 6b 00 6a 00 4e 00 37 00 53 00 68 00 38 00 73 00 67 00 32 00 41 00 6c 00 37 00 6b 00 65 00 72 00 36 00 33 00 66 00 7d 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 200KB and 2 of them )
}

rule WPR_Asterisk_Hook_Library : hardened
{
	meta:
		description = "Windows Password Recovery - file ast64.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-03-15"
		hash1 = "225071140e170a46da0e57ce51f0838f4be00c8f14e9922c6123bee4dffde743"
		hash2 = "95ec84dc709af990073495082d30309c42d175c40bd65cad267e6f103852a02d"
		id = "03c20c9d-bb8f-53f6-9cb5-9b059fb24949"

	strings:
		$s1 = {61 73 74 36 34 2e 64 6c 6c}
		$s2 = {61 00 73 00 74 00 2e 00 64 00 6c 00 6c 00}
		$s3 = {63 3a 5c 25 73 2e 6c 76 63}
		$s4 = {63 3a 5c 25 64 2e 6c 76 63}
		$s5 = {41 00 73 00 74 00 65 00 72 00 69 00 73 00 6b 00 20 00 48 00 6f 00 6f 00 6b 00 20 00 4c 00 69 00 62 00 72 00 61 00 72 00 79 00}
		$s6 = {3f 41 73 74 5f 53 74 61 72 74 52 64 36 34 40 40 59 41 58 58 5a}
		$s7 = {47 6c 6f 62 61 6c 5c 7b 31 33 37 34 38 32 31 41 2d 32 38 31 42 2d 39 41 46 34 2d 25 30 34 58 2d 31 32 33 34 35 36 37 38 39 30 31 32 33 34 7d}
		$s8 = {32 00 30 00 30 00 34 00 2d 00 32 00 30 00 31 00 33 00 20 00 50 00 61 00 73 00 73 00 63 00 61 00 70 00 65 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00}
		$s9 = {47 6c 6f 62 61 6c 5c 50 61 73 73 63 61 70 65 23 36 37 31 32 25 30 34 58}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 300KB and 3 of them )
}

rule WPR_WindowsPasswordRecovery_EXE : hardened
{
	meta:
		description = "Windows Password Recovery - file wpr.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-03-15"
		hash1 = "c1c64cba5c8e14a1ab8e9dd28828d036581584e66ed111455d6b4737fb807783"
		id = "7fa2062c-75dd-55aa-8775-631a9c1a497e"

	strings:
		$x1 = {55 75 50 69 70 65}
		$x2 = {64 62 61 64 6c 6c 67 6c}
		$x3 = {55 6b 56 48 53 56 4e 55 55 6c 6b 67 54 55 39 4f}
		$x4 = {52 6b 6c 4d 52 53 42 4e 54 30 35 4a 56 45 39 53 49 43 30 67 55 31 6c}
		$s1 = {57 00 50 00 52 00 2e 00 65 00 78 00 65 00}
		$s2 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 20 00 52 00 65 00 63 00 6f 00 76 00 65 00 72 00 79 00}
		$op0 = { 5f df 27 17 89 }
		$op1 = { 5f 00 00 f2 e5 cb 97 }
		$op2 = { e8 ed 00 f0 cc e4 00 a0 17 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 20000KB and ( 1 of ( $x* ) or all of ( $s* ) or all of ( $op* ) )
}

rule WPR_WindowsPasswordRecovery_EXE_64 : hardened
{
	meta:
		description = "Windows Password Recovery - file ast64.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-03-15"
		hash1 = "4e1ea81443b34248c092b35708b9a19e43a1ecbdefe4b5180d347a6c8638d055"
		id = "0f6c7695-e616-5757-b9cd-8cff5f972c3e"

	strings:
		$s1 = {25 00 42 00 20 00 25 00 64 00 20 00 25 00 59 00 20 00 20 00 2d 00 20 00 20 00 25 00 48 00 3a 00 25 00 4d 00 3a 00 25 00 53 00}
		$op0 = { 48 8d 8c 24 50 22 00 00 e8 bf eb ff ff 4c 8b c7 }
		$op1 = { ff 15 16 25 01 00 f7 d8 1b }
		$op2 = { e8 c2 26 00 00 83 20 00 83 c8 ff 48 8b 5c 24 30 }

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 300KB and all of them )
}

rule BeyondExec_RemoteAccess_Tool : hardened
{
	meta:
		description = "Detects BeyondExec Remote Access Tool - file rexesvr.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/BvYurS"
		date = "2017-03-17"
		hash1 = "3d3e3f0708479d951ab72fa04ac63acc7e5a75a5723eb690b34301580747032c"
		id = "fd68cb45-a46f-53d7-bf52-8f7bd3636d0d"

	strings:
		$x1 = {5c 42 65 79 6f 6e 64 45 78 65 63 56 32 5c 53 65 72 76 65 72 5c 52 65 6c 65 61 73 65 5c 50 69 70 65 73 2e 70 64 62}
		$x2 = {5c 5c 2e 5c 70 69 70 65 5c 62 65 79 6f 6e 64 65 78 65 63 25 64 2d 73 74 64 69 6e}
		$x3 = {46 61 69 6c 65 64 20 74 6f 20 63 72 65 61 74 65 20 64 69 73 70 61 74 63 68 20 70 69 70 65 2e 20 44 6f 20 79 6f 75 20 68 61 76 65 20 61 6e 6f 74 68 65 72 20 69 6e 73 74 61 6e 63 65 20 72 75 6e 6e 69 6e 67 3f}
		$op1 = { 83 e9 04 72 0c 83 e0 03 03 c8 ff 24 85 80 6f 40 }
		$op2 = { 6a 40 33 c0 59 bf e0 d8 40 00 f3 ab 8d 0c 52 c1 }

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 200KB and ( 1 of ( $x* ) or all of ( $op* ) ) ) or ( 3 of them )
}

rule Mimikatz_Gen_Strings : hardened
{
	meta:
		description = "Detects Mimikatz by using some special strings"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-06-19"
		super_rule = 1
		hash1 = "058cc8b3e4e4055f3be460332a62eb4cbef41e3a7832aceb8119fd99fea771c4"
		hash2 = "eefd4c038afa0e80cf6521c69644e286df08c0883f94245902383f50feac0f85"
		hash3 = "f35b589c1cc1c98c4c4a5123fd217bdf0d987c00d2561992cbfb94bd75920159"
		id = "3f4ab5d7-5a9f-55f0-9dda-e2975df582a0"

	strings:
		$s1 = {5b 00 2a 00 5d 00 20 00 27 00 25 00 73 00 27 00 20 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 61 00 6c 00 72 00 65 00 61 00 64 00 79 00 20 00 73 00 74 00 61 00 72 00 74 00 65 00 64 00}
		$s2 = {2a 00 2a 00 20 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 20 00 43 00 61 00 6c 00 6c 00 62 00 61 00 63 00 6b 00 21 00 20 00 2a 00 2a 00}
		$s3 = {54 00 72 00 79 00 20 00 74 00 6f 00 20 00 65 00 78 00 70 00 6f 00 72 00 74 00 20 00 61 00 20 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 20 00 43 00 41 00 20 00 74 00 6f 00 20 00 61 00 20 00 63 00 72 00 79 00 70 00 74 00 6f 00 20 00 28 00 76 00 69 00 72 00 74 00 75 00 61 00 6c 00 29 00 68 00 61 00 72 00 64 00 77 00 61 00 72 00 65 00}
		$s4 = {65 00 6e 00 74 00 65 00 72 00 70 00 72 00 69 00 73 00 65 00 61 00 64 00 6d 00 69 00 6e 00}
		$s5 = {41 00 73 00 6b 00 20 00 64 00 65 00 62 00 75 00 67 00 20 00 70 00 72 00 69 00 76 00 69 00 6c 00 65 00 67 00 65 00}
		$s6 = {49 00 6e 00 6a 00 65 00 63 00 74 00 65 00 64 00 20 00 3d 00 29 00}
		$s7 = {2a 00 2a 00 20 00 53 00 41 00 4d 00 20 00 41 00 43 00 43 00 4f 00 55 00 4e 00 54 00 20 00 2a 00 2a 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 12000KB and 1 of them )
}

rule Disclosed_0day_POCs_lpe : hardened
{
	meta:
		description = "Detects POC code from disclosed 0day hacktool set"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed 0day Repos"
		date = "2017-07-07"
		hash1 = "e10ee278f4c86d6ee1bd93a7ed71d4d59c0279381b00eb6153aedfb3a679c0b5"
		hash2 = "a5916cefa0f50622a30c800e7f21df481d7a3e1e12083fef734296a22714d088"
		hash3 = "5b701a5b5bbef7027711071cef2755e57984bfdff569fe99efec14a552d8ee43"
		id = "d3693d1d-6085-5e62-8f0b-dde5b14758b7"

	strings:
		$x1 = {6d 73 69 65 78 65 63 20 2f 66 20 63 3a 5c 75 73 65 72 73 5c 25 75 73 65 72 6e 61 6d 65 25 5c 64 6f 77 6e 6c 6f 61 64 73 5c}
		$x2 = {63 3a 5c 75 73 65 72 73 5c 25 75 73 65 72 6e 61 6d 65 25 5c 64 6f 77 6e 6c 6f 61 64 73 5c 62 61 74 2e 62 61 74}
		$x3 = {5c 70 61 79 6c 6f 61 64 2e 6d 73 69 20 2f 71 75 69 65 74}
		$x4 = {5c 00 70 00 61 00 79 00 6c 00 6f 00 61 00 64 00 32 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 54 00 72 00 75 00 73 00 74 00 65 00 64 00 52 00 54 00 50 00 72 00 6f 00 78 00 79 00 2e 00 73 00 79 00 73 00}
		$x5 = {5c 00 70 00 61 00 79 00 6c 00 6f 00 61 00 64 00 32 00}
		$x6 = {5c 00 70 00 61 00 79 00 6c 00 6f 00 61 00 64 00}
		$x7 = {57 69 6e 64 6f 77 73 54 72 75 73 74 65 64 52 54 50 72 6f 78 79 2e 73 79 73 20 2f 67 72 61 6e 74 3a 72 20 61 64 6d 69 6e 69 73 74 72 61 74 6f 72 73 3a 52 58}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 70KB and 1 of them )
}

rule Disclosed_0day_POCs_exploit : hardened
{
	meta:
		description = "Detects POC code from disclosed 0day hacktool set"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed 0day Repos"
		date = "2017-07-07"
		hash1 = "632d35a0bac27c9b2f3f485d43ebba818089cf72b3b8c4d2e87ce735b2e67d7e"
		id = "72b8aafd-d79a-5812-90fd-5d5aca109254"

	strings:
		$x1 = {5c 52 65 6c 65 61 73 65 5c 65 78 70 6c 6f 69 74 2e 70 64 62}
		$x2 = {5c 00 66 00 61 00 76 00 6f 00 72 00 69 00 74 00 65 00 73 00 5c 00 73 00 74 00 6f 00 6c 00 65 00 6e 00 64 00 61 00 74 00 61 00 2e 00 74 00 78 00 74 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 200KB and 1 of them )
}

rule Disclosed_0day_POCs_InjectDll : hardened
{
	meta:
		description = "Detects POC code from disclosed 0day hacktool set"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed 0day Repos"
		date = "2017-07-07"
		modified = "2022-12-21"
		hash1 = "173d3f78c9269f44d069afbd04a692f5ae42d5fdc9f44f074599ec91e8a29aa2"
		id = "90a4dca0-4f12-5946-9d5d-0b93bb5a3c5d"

	strings:
		$x1 = {5c 52 65 6c 65 61 73 65 5c 49 6e 6a 65 63 74 44 6c 6c 2e 70 64 62}
		$x2 = {53 70 65 63 69 66 79 20 2d 6c 20 74 6f 20 6c 69 73 74 20 61 6c 6c 20 49 45 20 70 72 6f 63 65 73 73 65 73 20 72 75 6e 6e 69 6e 67 20 69 6e 20 74 68 65 20 63 75 72 72 65 6e 74 20 73 65 73 73 69 6f 6e}
		$x3 = {55 73 61 67 65 3a 20 49 6e 6a 65 63 74 44 6c 6c 20 2d 6c 7c 70 69 64 20 50 61 74 68 54 6f 44 6c 6c}
		$x4 = {49 6e 6a 65 63 74 69 6e 67 20 44 4c 4c 3a 20 25 6c 73 20 69 6e 74 6f 20 50 49 44 3a 20 25 64}
		$x5 = {45 72 72 6f 72 20 61 64 6a 75 73 74 69 6e 67 20 70 72 69 76 69 6c 65 67 65 20 25 64}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 300KB and 1 of them )
}

rule Disclosed_0day_POCs_payload_MSI : hardened
{
	meta:
		description = "Detects POC code from disclosed 0day hacktool set"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed 0day Repos"
		date = "2017-07-07"
		modified = "2022-12-21"
		hash1 = "a7c498a95850e186b7749a96004a98598f45faac2de9b93354ac93e627508a87"
		id = "fe32af56-d5a1-5246-a7df-395b9cd02faf"

	strings:
		$s1 = {57 00 53 00 68 00 65 00 6c 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00}
		$s2 = {54 00 61 00 72 00 67 00 65 00 74 00 20 00 65 00 6d 00 70 00 74 00 79 00 2c 00 20 00 73 00 6f 00 20 00 61 00 63 00 63 00 6f 00 75 00 6e 00 74 00 20 00 6e 00 61 00 6d 00 65 00 20 00 74 00 72 00 61 00 6e 00 73 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 20 00 62 00 65 00 67 00 69 00 6e 00 73 00 20 00 6f 00 6e 00 20 00 74 00 68 00 65 00 20 00 6c 00 6f 00 63 00 61 00 6c 00 20 00 73 00 79 00 73 00 74 00 65 00 6d 00 2e 00}
		$s3 = {5c 63 75 73 74 61 63 74 5c 78 38 36 5c 41 49 43 75 73 74 41 63 74 2e 70 64 62}

	condition:
		( uint16( 0 ) == 0xcfd0 and filesize < 1000KB and all of them )
}

rule Disclosed_0day_POCs_injector : hardened
{
	meta:
		description = "Detects POC code from disclosed 0day hacktool set"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed 0day Repos"
		date = "2017-07-07"
		hash1 = "ba0e2119b2a6bad612e86662b643a404426a07444d476472a71452b7e9f94041"
		id = "6de89a84-fe16-5064-8cbb-a3b9003f4c0c"

	strings:
		$x1 = {5c 52 65 6c 65 61 73 65 5c 69 6e 6a 65 63 74 6f 72 2e 70 64 62}
		$x2 = {43 61 6e 6e 6f 74 20 77 72 69 74 65 20 74 68 65 20 73 68 65 6c 6c 63 6f 64 65 20 69 6e 20 74 68 65 20 70 72 6f 63 65 73 73 20 6d 65 6d 6f 72 79 2c 20 65 72 72 6f 72 3a 20}
		$x3 = {2f 73 20 73 68 65 6c 6c 63 6f 64 65 5f 66 69 6c 65 20 50 49 44 3a 20 73 68 65 6c 6c 63 6f 64 65 20 69 6e 6a 65 63 74 69 6f 6e 2e}
		$x4 = {2f 64 20 64 6c 6c 5f 66 69 6c 65 20 50 49 44 3a 20 64 6c 6c 20 69 6e 6a 65 63 74 69 6f 6e 20 76 69 61 20 4c 6f 61 64 4c 69 62 72 61 72 79 28 29 2e}
		$x5 = {2f 73 20 73 68 65 6c 6c 63 6f 64 65 5f 66 69 6c 65 20 50 49 44}
		$x6 = {53 68 65 6c 6c 63 6f 64 65 20 63 6f 70 69 65 64 20 69 6e 20 6d 65 6d 6f 72 79 3a 20 4f 4b}
		$x7 = {55 73 61 67 65 20 6f 66 20 74 68 65 20 69 6e 6a 65 63 74 6f 72 2e 20}
		$x8 = {4b 4f 3a 20 63 61 6e 6e 6f 74 20 6f 62 74 61 69 6e 20 74 68 65 20 53 65 44 65 62 75 67 20 70 72 69 76 69 6c 65 67 65 2e}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 90KB and 1 of them ) or 3 of them
}

rule Disclosed_0day_POCs_lpe_2 : hardened
{
	meta:
		description = "Detects POC code from disclosed 0day hacktool set"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed 0day Repos"
		date = "2017-07-07"
		hash1 = "b4f3787a19b71c47bc4357a5a77ffb456e2f71fd858079d93e694a6a79f66533"
		id = "9326bbae-81ee-588e-8581-628b47d348f8"

	strings:
		$s1 = {5c 63 6d 64 2e 65 78 65 22 20 2f 6b 20 77 75 73 61 20 63 3a 5c 75 73 65 72 73 5c}
		$s2 = {44 3a 5c 67 69 74 70 6f 63 5c 55 41 43 5c 73 72 63 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 6c 70 65 2e 70 64 62}
		$s3 = {46 00 6f 00 6c 00 64 00 65 00 72 00 20 00 43 00 72 00 65 00 61 00 74 00 65 00 64 00 3a 00 20 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 700KB and 2 of them )
}

rule Disclosed_0day_POCs_shellcodegenerator : hardened
{
	meta:
		description = "Detects POC code from disclosed 0day hacktool set"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed 0day Repos"
		date = "2017-07-07"
		hash1 = "55c4073bf8d38df7d392aebf9aed2304109d92229971ffac6e1c448986a87916"
		id = "49250cbe-7bbd-5462-9324-1a8f350386f3"

	strings:
		$x1 = {5c 52 65 6c 65 61 73 65 5c 73 68 65 6c 6c 63 6f 64 65 67 65 6e 65 72 61 74 6f 72 2e 70 64 62}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 40KB and all of them )
}

rule SecurityXploded_Producer_String : hardened
{
	meta:
		description = "Detects hacktools by SecurityXploded"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://securityxploded.com/browser-password-dump.php"
		date = "2017-07-13"
		score = 60
		hash1 = "d57847db5458acabc87daee6f30173348ac5956eb25e6b845636e25f5a56ac59"
		id = "739c4ba1-5126-51cc-a2dd-cdac2737e29a"

	strings:
		$x1 = {68 74 74 70 3a 2f 2f 73 65 63 75 72 69 74 79 78 70 6c 6f 64 65 64 2e 63 6f 6d}

	condition:
		( uint16( 0 ) == 0x5a4d and all of them )
}

rule Kekeo_Hacktool : hardened
{
	meta:
		description = "Detects Kekeo Hacktool"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/gentilkiwi/kekeo/releases"
		date = "2017-07-21"
		hash1 = "ce92c0bcdf63347d84824a02b7a448cf49dd9f44db2d02722d01c72556a2b767"
		hash2 = "49d7fec5feff20b3b57b26faccd50bc05c71f1dddf5800eb4abaca14b83bba8c"
		id = "a4158da8-fc4d-5dc6-b44c-f5325b3bb8ca"

	strings:
		$x1 = {5b 00 74 00 69 00 63 00 6b 00 65 00 74 00 20 00 25 00 75 00 5d 00 20 00 73 00 65 00 73 00 73 00 69 00 6f 00 6e 00 20 00 4b 00 65 00 79 00 20 00 69 00 73 00 20 00 4e 00 55 00 4c 00 4c 00 2c 00 20 00 6d 00 61 00 79 00 62 00 65 00 20 00 61 00 20 00 54 00 47 00 54 00 20 00 77 00 69 00 74 00 68 00 6f 00 75 00 74 00 20 00 65 00 6e 00 6f 00 75 00 67 00 68 00 20 00 72 00 69 00 67 00 68 00 74 00 73 00 20 00 77 00 68 00 65 00 6e 00 20 00 57 00 43 00 45 00 20 00 64 00 75 00 6d 00 70 00 65 00 64 00 20 00 69 00 74 00 2e 00}
		$x2 = {45 00 52 00 52 00 4f 00 52 00 20 00 6b 00 75 00 68 00 6c 00 5f 00 6d 00 5f 00 73 00 6d 00 62 00 5f 00 74 00 69 00 6d 00 65 00 20 00 3b 00 20 00 49 00 6e 00 76 00 61 00 6c 00 69 00 64 00 21 00 20 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 3a 00 20 00 25 00 30 00 32 00 78 00 20 00 2d 00 20 00 53 00 74 00 61 00 74 00 75 00 73 00 3a 00 20 00 25 00 30 00 38 00 78 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 2000KB and ( 1 of ( $x* ) ) )
}

rule AllTheThings : hardened
{
	meta:
		description = "Detects AllTheThings"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/subTee/AllTheThings"
		date = "2017-07-27"
		modified = "2022-12-21"
		hash1 = "5a0e9a9ce00d843ea95bd5333b6ab50cc5b1dbea648cc819cfe48482513ce842"
		id = "c3169ca7-3482-5d55-a1d9-6d1c01349922"

	strings:
		$x1 = {5c 6f 62 6a 5c 44 65 62 75 67 5c 41 6c 6c 54 68 65 54 68 69 6e 67 73 2e 70 64 62}
		$x2 = {41 00 6c 00 6c 00 54 00 68 00 65 00 54 00 68 00 69 00 6e 00 67 00 73 00 2e 00 65 00 78 00 65 00}
		$x3 = {5c 41 6c 6c 54 68 65 54 68 69 6e 67 73 2e 64 6c 6c}
		$x4 = {48 00 65 00 6c 00 6c 00 6f 00 20 00 46 00 72 00 6f 00 6d 00 20 00 4d 00 61 00 69 00 6e 00 2e 00 2e 00 2e 00 49 00 20 00 44 00 6f 00 6e 00 27 00 74 00 20 00 44 00 6f 00 20 00 41 00 6e 00 79 00 74 00 68 00 69 00 6e 00 67 00}
		$x5 = {49 00 20 00 61 00 6d 00 20 00 61 00 20 00 62 00 61 00 73 00 69 00 63 00 20 00 43 00 4f 00 4d 00 20 00 4f 00 62 00 6a 00 65 00 63 00 74 00}
		$x6 = {49 00 20 00 73 00 68 00 6f 00 75 00 6c 00 64 00 6e 00 27 00 74 00 20 00 72 00 65 00 61 00 6c 00 6c 00 79 00 20 00 65 00 78 00 65 00 63 00 75 00 74 00 65 00 20 00 65 00 69 00 74 00 68 00 65 00 72 00 2e 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 50KB and 1 of them )
}

rule Impacket_Keyword : hardened
{
	meta:
		description = "Detects Impacket Keyword in Executable"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-08-04"
		score = 60
		hash1 = "9388c78ea6a78dbea307470c94848ae2481481f593d878da7763e649eaab4068"
		hash2 = "2f6d95e0e15174cfe8e30aaa2c53c74fdd13f9231406b7103da1e099c08be409"
		id = "a92962e6-1b05-583b-8b06-f226bdea88e2"

	strings:
		$s1 = {69 6d 70 61 63 6b 65 74 2e 73 6d 62 28}
		$s2 = {69 6d 70 61 63 6b 65 74 2e 6e 74 6c 6d 28}
		$s3 = {69 6d 70 61 63 6b 65 74 2e 6e 6d 62 28}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 14000KB and 1 of them )
}

rule PasswordsPro : hardened
{
	meta:
		description = "Auto-generated rule - file PasswordsPro.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "PasswordPro"
		date = "2017-08-27"
		hash1 = "5b3d6654e6d9dc49ee1136c0c8e8122cb0d284562447abfdc05dfe38c79f95bf"
		id = "c749f883-364e-5f65-9eb8-3dcd74495f7c"

	strings:
		$s1 = {4e 6f 20 75 73 65 72 73 20 6d 61 72 6b 65 64 20 66 6f 72 20 61 74 74 61 63 6b 20 6f 72 20 61 6c 6c 20 6d 61 72 6b 65 64 20 75 73 65 72 73 20 61 6c 72 65 61 64 79 20 68 61 76 65 20 70 61 73 73 77 6f 72 64 73 20 66 6f 75 6e 64 21}
		$s2 = {25 73 5c 50 61 73 73 77 6f 72 64 73 50 72 6f 2e 69 6e 69 2e 44 69 63 74 69 6f 6e 61 72 69 65 73 28 25 64 29}
		$s3 = {50 61 73 73 77 6f 72 64 73 20 70 72 6f 63 65 73 73 65 64 20 73 69 6e 63 65 20 61 74 74 61 63 6b 20 73 74 61 72 74 3a}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 2000KB and 1 of them )
}

import "pe"

rule PasswordPro_NTLM_DLL : hardened
{
	meta:
		description = "Auto-generated rule - file NTLM.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "PasswordPro"
		date = "2017-08-27"
		hash1 = "47d4755d31bb96147e6230d8ea1ecc3065da8e557e8176435ccbcaea16fe50de"
		id = "cc86b868-000f-56b1-91cd-4aa8caace1df"

	strings:
		$s1 = {4e 54 4c 4d 2e 64 6c 6c}
		$s2 = {41 6c 67 6f 72 69 74 68 6d 3a 20 4e 54 4c 4d}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 20KB and pe.exports ( "GetHash" ) and pe.exports ( "GetInfo" ) and ( all of them ) )
}

rule KeeThief_PS : hardened
{
	meta:
		description = "Detects component of KeeTheft - KeePass dump tool - file KeeThief.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/HarmJ0y/KeeThief"
		date = "2017-08-29"
		hash1 = "a3b976279ded8e64b548c1d487212b46b03aaec02cb6e199ea620bd04b8de42f"
		id = "9a54e8d1-3cae-51e8-8da0-024ac25dc6d0"

	strings:
		$x1 = {24 57 4d 49 50 72 6f 63 65 73 73 20 3d 20 47 65 74 2d 57 6d 69 4f 62 6a 65 63 74 20 77 69 6e 33 32 5f 70 72 6f 63 65 73 73 20 2d 46 69 6c 74 65 72 20 22 50 72 6f 63 65 73 73 49 44 20 3d 20 24 28 24 4b 65 65 50 61 73 73 50 72 6f 63 65 73 73 2e 49 44 29 22}
		$x2 = {69 66 28 24 4b 65 65 50 61 73 73 50 72 6f 63 65 73 73 2e 46 69 6c 65 56 65 72 73 69 6f 6e 20 2d 6d 61 74 63 68 20 27 5e 32 5c 2e 27 29 20 7b}

	condition:
		( uint16( 0 ) == 0x7223 and filesize < 1000KB and ( 1 of ( $x* ) ) )
}

rule KeeTheft_EXE : hardened
{
	meta:
		description = "Detects component of KeeTheft - KeePass dump tool - file KeeTheft.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/HarmJ0y/KeeThief"
		date = "2017-08-29"
		hash1 = "f06789c3e9fe93c165889799608e59dda6b10331b931601c2b5ae06ede41dc22"
		id = "65531239-c5fa-5285-8f44-2d858e211c9b"

	strings:
		$x1 = {45 00 72 00 72 00 6f 00 72 00 3a 00 20 00 43 00 6f 00 75 00 6c 00 64 00 20 00 6e 00 6f 00 74 00 20 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 61 00 20 00 74 00 68 00 72 00 65 00 61 00 64 00 20 00 66 00 6f 00 72 00 20 00 74 00 68 00 65 00 20 00 73 00 68 00 65 00 6c 00 6c 00 63 00 6f 00 64 00 65 00}
		$x2 = {43 00 6f 00 75 00 6c 00 64 00 20 00 6e 00 6f 00 74 00 20 00 66 00 69 00 6e 00 64 00 20 00 61 00 64 00 64 00 72 00 65 00 73 00 73 00 20 00 6d 00 61 00 72 00 6b 00 65 00 72 00 20 00 69 00 6e 00 20 00 73 00 68 00 65 00 6c 00 6c 00 63 00 6f 00 64 00 65 00}
		$x3 = {47 65 6e 65 72 61 74 65 44 65 63 72 79 70 74 69 6f 6e 53 68 65 6c 6c 43 6f 64 65}
		$x4 = {4b 00 65 00 65 00 50 00 61 00 73 00 73 00 4c 00 69 00 62 00 2e 00 4b 00 65 00 79 00 73 00 2e 00 4b 00 63 00 70 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00}
		$x5 = {2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 20 00 46 00 6f 00 75 00 6e 00 64 00 20 00 61 00 20 00 43 00 6f 00 6d 00 70 00 6f 00 73 00 69 00 74 00 65 00 4b 00 65 00 79 00 21 00 20 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00}
		$x6 = {2a 00 2a 00 2a 00 20 00 49 00 6e 00 74 00 65 00 72 00 65 00 73 00 74 00 69 00 6e 00 67 00 2e 00 2e 00 2e 00 20 00 74 00 68 00 65 00 72 00 65 00 20 00 61 00 72 00 65 00 20 00 6d 00 75 00 6c 00 74 00 69 00 70 00 6c 00 65 00 20 00 2e 00 4e 00 45 00 54 00 20 00 72 00 75 00 6e 00 74 00 69 00 6d 00 65 00 73 00 20 00 6c 00 6f 00 61 00 64 00 65 00 64 00 20 00 69 00 6e 00 20 00 4b 00 65 00 65 00 50 00 61 00 73 00 73 00}
		$x7 = {47 65 74 4b 63 70 50 61 73 73 77 6f 72 64 49 6e 66 6f}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 200KB and 2 of them )
}

rule KeeTheft_Out_Shellcode : hardened
{
	meta:
		description = "Detects component of KeeTheft - KeePass dump tool - file Out-Shellcode.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/HarmJ0y/KeeThief"
		date = "2017-08-29"
		hash1 = "2afb1c8c82363a0ae43cad9d448dd20bb7d2762aa5ed3672cd8e14dee568e16b"
		id = "1263ad5d-5d50-50e6-ad78-9d5e4e16634b"

	strings:
		$x1 = {57 72 69 74 65 2d 48 6f 73 74 20 22 53 68 65 6c 6c 63 6f 64 65 20 6c 65 6e 67 74 68 3a 20 30 78 24 28 28 24 53 68 65 6c 6c 63 6f 64 65 4c 65 6e 67 74 68 20 2b 20 31 29 2e 54 6f 53 74 72 69 6e 67 28 27 58 34 27 29 29 22}
		$x2 = {24 54 65 78 74 53 65 63 74 69 6f 6e 49 6e 66 6f 20 3d 20 40 28 24 4d 61 70 43 6f 6e 74 65 6e 74 73 20 7c 20 57 68 65 72 65 2d 4f 62 6a 65 63 74 20 7b 20 24 5f 20 2d 6d 61 74 63 68 20 27 5c 2e 74 65 78 74 5c 57 2b 43 4f 44 45 27 20 7d 29 5b 30 5d}

	condition:
		( filesize < 2KB and 1 of them )
}

rule Sharpire : hardened
{
	meta:
		description = "Auto-generated rule - file Sharpire.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/0xbadjuju/Sharpire"
		date = "2017-09-23"
		modified = "2022-12-21"
		hash1 = "327a1dc2876cd9d7f6a5b3777373087296fc809d466e42861adcf09986c6e587"
		id = "747f2798-4f93-5073-b358-969060a1c937"

	strings:
		$x1 = {5c 6f 62 6a 5c 44 65 62 75 67 5c 53 68 61 72 70 69 72 65 2e 70 64 62}
		$x2 = {5b 00 2a 00 5d 00 20 00 55 00 70 00 6c 00 6f 00 61 00 64 00 20 00 6f 00 66 00 20 00 24 00 66 00 69 00 6c 00 65 00 4e 00 61 00 6d 00 65 00 20 00 73 00 75 00 63 00 63 00 65 00 73 00 73 00 66 00 75 00 6c 00}
		$s1 = {6e 00 6f 00 20 00 73 00 68 00 65 00 6c 00 6c 00 20 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00 73 00 75 00 70 00 70 00 6c 00 69 00 65 00 64 00}
		$s2 = {2f 00 6c 00 6f 00 67 00 69 00 6e 00 2f 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 2e 00 70 00 68 00 70 00}
		$s3 = {69 6e 76 6f 6b 65 53 68 65 6c 6c 43 6f 6d 6d 61 6e 64}
		$s4 = {2e 00 2e 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00 65 00 78 00 65 00 63 00 75 00 74 00 69 00 6f 00 6e 00 20 00 63 00 6f 00 6d 00 70 00 6c 00 65 00 74 00 65 00 64 00 2e 00}
		$s5 = {4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 2f 00 35 00 2e 00 30 00 20 00 28 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 20 00 36 00 2e 00 31 00 3b 00 20 00 57 00 4f 00 57 00 36 00 34 00 3b 00 20 00 54 00 72 00 69 00 64 00 65 00 6e 00 74 00 2f 00 37 00 2e 00 30 00 3b 00 20 00 72 00 76 00 3a 00 31 00 31 00 2e 00 30 00 29 00 20 00 6c 00 69 00 6b 00 65 00 20 00 47 00 65 00 63 00 6b 00 6f 00}
		$s6 = {2f 00 61 00 64 00 6d 00 69 00 6e 00 2f 00 67 00 65 00 74 00 2e 00 70 00 68 00 70 00}
		$s7 = {5b 00 21 00 5d 00 20 00 45 00 72 00 72 00 6f 00 72 00 20 00 69 00 6e 00 20 00 73 00 74 00 6f 00 70 00 70 00 69 00 6e 00 67 00 20 00 6a 00 6f 00 62 00 3a 00 20 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 100KB and ( 1 of ( $x* ) and 3 of them ) )
}

rule Invoke_Metasploit : hardened
{
	meta:
		description = "Detects Invoke-Metasploit Payload"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/jaredhaight/Invoke-MetasploitPayload/blob/master/Invoke-MetasploitPayload.ps1"
		date = "2017-09-23"
		hash1 = "b36d3ca7073741c8a48c578edaa6d3b6a8c3c4413e961a83ad08ad128b843e0b"
		id = "40452884-df3f-5b49-ad10-05006cb115f2"

	strings:
		$s1 = {((5b 2a 5d 20 4c 6f 6f 6b 73 20 6c 69 6b 65 20 77 65 27 72 65 20 36 34 62 69 74 2c 20 75 73 69 6e 67 20 72 65 67 75 6c 61 72 20 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65) | (5b 00 2a 00 5d 00 20 00 4c 00 6f 00 6f 00 6b 00 73 00 20 00 6c 00 69 00 6b 00 65 00 20 00 77 00 65 00 27 00 72 00 65 00 20 00 36 00 34 00 62 00 69 00 74 00 2c 00 20 00 75 00 73 00 69 00 6e 00 67 00 20 00 72 00 65 00 67 00 75 00 6c 00 61 00 72 00 20 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00))}
		$s2 = {5b 2a 5d 20 4b 69 63 6b 69 6e 67 20 6f 66 66 20 64 6f 77 6e 6c 6f 61 64 20 63 72 61 64 6c 65 20 69 6e 20 61 20 6e 65 77 20 70 72 6f 63 65 73 73}
		$s3 = {50 72 6f 78 79 2e 43 72 65 64 65 6e 74 69 61 6c 73 3d 5b 4e 65 74 2e 43 72 65 64 65 6e 74 69 61 6c 43 61 63 68 65 5d 3a 3a 44 65 66 61 75 6c 74 43 72 65 64 65 6e 74 69 61 6c 73 3b 49 6e 76 6f 6b 65 2d 45 78 70 72 65 73 73 69 6f 6e 20 24 63 6c 69 65 6e 74 2e 64 6f 77 6e 6c 6f 61 64 73 74 72 69 6e 67 28 27 27 27 2b 24 75 72 6c 2b 27 27 27 29 3b 27}

	condition:
		( filesize < 20KB and 1 of them )
}

rule PowerShell_Mal_HackTool_Gen : hardened
{
	meta:
		description = "Detects PowerShell hack tool samples - generic PE loader"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-11-02"
		hash1 = "d442304ca839d75b34e30e49a8b9437b5ab60b74d85ba9005642632ce7038b32"
		id = "d1fc4594-d816-5d02-bff6-3f220477b555"

	strings:
		$x1 = {24 00 50 00 45 00 42 00 79 00 74 00 65 00 73 00 33 00 32 00 20 00 3d 00 20 00 27 00 54 00 56 00 71 00 51 00 41 00 41 00 4d 00 41 00 41 00 41 00 41 00 45 00 41 00 41 00 41 00 41 00}
		$x2 = {57 00 72 00 69 00 74 00 65 00 2d 00 42 00 79 00 74 00 65 00 73 00 54 00 6f 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 20 00 2d 00 42 00 79 00 74 00 65 00 73 00 20 00 24 00 53 00 68 00 65 00 6c 00 6c 00 63 00 6f 00 64 00 65 00 31 00 20 00 2d 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 41 00 64 00 64 00 72 00 65 00 73 00 73 00 20 00 24 00 47 00 65 00 74 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 4c 00 69 00 6e 00 65 00 57 00 41 00 64 00 64 00 72 00 54 00 65 00 6d 00 70 00}
		$x3 = {40 00 28 00 24 00 50 00 45 00 42 00 79 00 74 00 65 00 73 00 36 00 34 00 2c 00 20 00 24 00 50 00 45 00 42 00 79 00 74 00 65 00 73 00 33 00 32 00 2c 00 20 00 22 00 56 00 6f 00 69 00 64 00 22 00 2c 00 20 00 30 00 2c 00 20 00 22 00 22 00 2c 00 20 00 24 00 45 00 78 00 65 00 41 00 72 00 67 00 73 00 29 00}
		$x4 = {28 00 53 00 68 00 65 00 6c 00 6c 00 63 00 6f 00 64 00 65 00 3a 00 20 00 4c 00 6f 00 61 00 64 00 4c 00 69 00 62 00 72 00 61 00 72 00 79 00 41 00 2e 00 61 00 73 00 6d 00 29 00}

	condition:
		filesize < 8000KB and 1 of them
}

rule Sig_RemoteAdmin_1 : hardened
{
	meta:
		description = "Detects strings from well-known APT malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-12-03"
		score = 45
		id = "da55084c-ec1f-5800-a614-189dce7b5820"

	strings:
		$ = {52 00 61 00 64 00 6d 00 69 00 6e 00 2c 00 20 00 52 00 65 00 6d 00 6f 00 74 00 65 00 20 00 41 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00}
		$ = {52 00 61 00 64 00 6d 00 69 00 6e 00 20 00 33 00 2e 00 30 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 3000KB and 1 of them
}

rule RemCom_RemoteCommandExecution : hardened
{
	meta:
		description = "Detects strings from RemCom tool"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/tezXZt"
		date = "2017-12-28"
		score = 50
		id = "90b4ce3c-a690-5b6e-95e8-7e5dc8270152"

	strings:
		$ = {5c 5c 2e 5c 70 69 70 65 5c 25 73 25 73 25 64}
		$ = {25 73 5c 70 69 70 65 5c 25 73 25 73 25 64 25 73}
		$ = {5c 41 44 4d 49 4e 24 5c 53 79 73 74 65 6d 33 32 5c 25 73 25 73}

	condition:
		1 of them
}

rule Crackmapexec_EXE : hardened
{
	meta:
		description = "Detects CrackMapExec hack tool"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2018-04-06"
		score = 85
		hash1 = "371f104b7876b9080c519510879235f36edb6668097de475949b84ab72ee9a9a"
		id = "9fcfba98-7ba1-5810-99b7-62ad2b1aa4c0"

	strings:
		$s1 = {63 6f 72 65 2e 73 63 72 69 70 74 73 2e 73 65 63 72 65 74 73 64 75 6d 70 28}
		$s2 = {63 6f 72 65 2e 73 63 72 69 70 74 73 2e 73 61 6d 72 64 75 6d 70 28}
		$s3 = {63 6f 72 65 2e 75 61 63 64 75 6d 70 28}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 10000KB and 2 of them
}

import "pe"

rule SUSP_Imphash_PassRevealer_PY_EXE : hardened
{
	meta:
		description = "Detects an imphash used by password revealer and hack tools (some false positives with hardware driver installers)"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2018-04-06"
		modified = "2021-11-09"
		score = 40
		hash1 = "371f104b7876b9080c519510879235f36edb6668097de475949b84ab72ee9a9a"
		id = "9462dfc4-2feb-591d-ac0c-ba02f093c216"

	strings:
		$fp1 = {((41 73 73 6d 61 6e 6e 20 45 6c 65 63 74 72 6f 6e 69 63 20 47 6d 62 48) | (41 00 73 00 73 00 6d 00 61 00 6e 00 6e 00 20 00 45 00 6c 00 65 00 63 00 74 00 72 00 6f 00 6e 00 69 00 63 00 20 00 47 00 6d 00 62 00 48 00))}
		$fp2 = {((4f 63 75 6c 75 73 20 56 52) | (4f 00 63 00 75 00 6c 00 75 00 73 00 20 00 56 00 52 00))}
		$fp3 = {65 66 6d 38 6c 6f 61 64}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 10000KB and pe.imphash ( ) == "ed61beebc8d019dd9bec823e2d694afd" and not 1 of ( $fp* )
}

rule MAL_Unknown_PWDumper_Apr18_3 : hardened
{
	meta:
		description = "Detects sample from unknown sample set - IL origin"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2018-04-06"
		hash1 = "d435e7b6f040a186efeadb87dd6d9a14e038921dc8b8658026a90ae94b4c8b05"
		hash2 = "8c35c71838f34f7f7a40bf06e1d2e14d58d9106e6d4e6f6e9af732511a126276"
		id = "2431d562-dcd8-5d21-8406-7d2567b6eca9"

	strings:
		$s1 = {6c 6f 61 64 65 72 78 38 36 2e 64 6c 6c}
		$s2 = {74 00 63 00 70 00 73 00 76 00 63 00 73 00 2e 00 65 00 78 00 65 00}
		$s3 = {25 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 2c 00 20 00 43 00 6f 00 6d 00 6d 00 6f 00 6e 00 20 00 46 00 4f 00 4c 00 44 00 45 00 52 00 25 00}
		$s4 = {25 00 41 00 6c 00 6c 00 55 00 73 00 65 00 72 00 73 00 2c 00 20 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 44 00 61 00 74 00 61 00 20 00 46 00 4f 00 4c 00 44 00 45 00 52 00 25 00}
		$s5 = {6c 6f 61 64 65 72 78 38 36}
		$s6 = {54 4e 74 44 6c 6c 48 6f 6f 6b 24}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 3000KB and all of them
}

import "pe"

rule ProcessInjector_Gen : HIGHVOL hardened
{
	meta:
		description = "Detects a process injection utility that can be used ofr good and bad purposes"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/cuckoosandbox/monitor/blob/master/bin/inject.c"
		date = "2018-04-23"
		score = 60
		hash1 = "456c1c25313ce2e2eedf24fdcd4d37048bcfff193f6848053cbb3b5e82cd527d"
		id = "9b0b6ac7-8432-5f93-b389-c2356ec75113"

	strings:
		$x1 = {45 72 72 6f 72 20 69 6e 6a 65 63 74 69 6e 67 20 72 65 6d 6f 74 65 20 74 68 72 65 61 64 20 69 6e 20 70 72 6f 63 65 73 73 3a}
		$s5 = {5b 2d 5d 20 45 72 72 6f 72 20 67 65 74 74 69 6e 67 20 61 63 63 65 73 73 20 74 6f 20 70 72 6f 63 65 73 73 3a 20 25 6c 64 21}
		$s6 = {2d 2d 70 72 6f 63 65 73 73 2d 6e 61 6d 65 20 3c 6e 61 6d 65 3e 20 20 50 72 6f 63 65 73 73 20 6e 61 6d 65 20 74 6f 20 69 6e 6a 65 63 74}
		$s12 = {4e 6f 20 69 6e 6a 65 63 74 69 6f 6e 20 74 61 72 67 65 74 20 68 61 73 20 62 65 65 6e 20 70 72 6f 76 69 64 65 64 21}
		$s17 = {5b 2d 5d 20 41 6e 20 61 70 70 20 70 61 74 68 20 69 73 20 72 65 71 75 69 72 65 64 20 77 68 65 6e 20 6e 6f 74 20 69 6e 6a 65 63 74 69 6e 67 21}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 50KB and ( pe.imphash ( ) == "d27e0fa013d7ae41be12aaf221e41f9b" or 1 of them ) or 3 of them
}

rule Lazagne_PW_Dumper : hardened
{
	meta:
		description = "Detects Lazagne PW Dumper"
		author = "Markus Neis / Florian Roth"
		reference = "https://github.com/AlessandroZ/LaZagne/releases/"
		date = "2018-03-22"
		score = 70
		id = "1904029e-9336-5278-ae2e-4bc853316600"

	strings:
		$s1 = {43 72 79 70 74 6f 2e 48 61 73 68}
		$s2 = {6c 61 5a 61 67 6e 65}
		$s3 = {69 6d 70 61 63 6b 65 74 2e 77 69 6e 72 65 67 69 73 74 72 79}

	condition:
		3 of them
}

rule HKTL_shellpop_TCLsh : hardened
{
	meta:
		description = "Detects suspicious TCLsh popshell"
		author = "Tobias Michalski"
		reference = "https://github.com/0x00-0x00/ShellPop"
		date = "2018-05-18"
		hash1 = "9f49d76d70d14bbe639a3c16763d3b4bee92c622ecb1c351cb4ea4371561e133"
		id = "24f6b626-383e-54c9-abd4-bd67c37af937"

	strings:
		$s1 = {7b 20 70 75 74 73 20 2d 6e 6f 6e 65 77 6c 69 6e 65 20 24 73 20 22 73 68 65 6c 6c 3e 22 3b 66 6c 75 73 68 20 24 73 3b 67 65 74 73 20 24 73 20 63 3b 73 65 74 20 65 20 22 65 78 65 63 20 24 63 22 3b 69 66}

	condition:
		filesize < 1KB and 1 of them
}

rule HKTL_shellpop_ruby : hardened
{
	meta:
		description = "Detects suspicious ruby shellpop"
		author = "Tobias Michalski"
		reference = "https://github.com/0x00-0x00/ShellPop"
		date = "2018-05-18"
		hash1 = "6b425b37f3520fd8c778928cc160134a293db0ce6d691e56a27894354b04f783"
		id = "cb3a93d5-02a1-5a49-b37e-3f9312b993ea"

	strings:
		$x1 = {29 3b 77 68 69 6c 65 28 63 6d 64 3d 63 2e 67 65 74 73 29 3b 49 4f 2e 70 6f 70 65 6e 28 63 6d 64 2c 27 72 27 29 7b}

	condition:
		filesize < 1KB and all of them
}

rule HKTL_shellpop_awk : hardened
{
	meta:
		description = "Detects suspicious AWK Shellpop"
		author = "Tobias Michalski"
		reference = "https://github.com/0x00-0x00/ShellPop"
		date = "2018-05-18"
		hash1 = "7513a0a0ba786b0e22a9a7413491b4011f60af11253c596fa6857fb92a6736fc"
		id = "92d1e6dd-d758-5df2-b5e5-eb275964551d"

	strings:
		$s1 = {61 77 6b 20 27 42 45 47 49 4e 20 7b 73 20 3d 20 22 2f 69 6e 65 74 2f 74 63 70 2f 30 2f}
		$s2 = {3b 20 77 68 69 6c 65 28 34 32 29 20}

	condition:
		filesize < 1KB and 1 of them
}

rule HKTL_shellpop_Netcat_UDP : hardened
{
	meta:
		description = "Detects suspicious netcat popshell"
		author = "Tobias Michalski"
		reference = "https://github.com/0x00-0x00/ShellPop"
		date = "2018-05-18"
		hash1 = "d823ad91b315c25893ce8627af285bcf4e161f9bbf7c070ee2565545084e88be"
		id = "67aa53b6-00bc-5d2e-b6f3-37e9121cdd01"

	strings:
		$s1 = {6d 6b 66 69 66 6f 20 66 69 66 6f 20 3b 20 6e 63 2e 74 72 61 64 69 74 69 6f 6e 61 6c 20 2d 75}
		$s2 = {3c 20 66 69 66 6f 20 7c 20 7b 20 62 61 73 68 20 2d 69 3b 20 7d 20 3e 20 66 69 66 6f}

	condition:
		filesize < 1KB and 1 of them
}

rule HKTL_shellpop_socat : hardened
{
	meta:
		description = "Detects suspicious socat popshell"
		author = "Tobias Michalski"
		reference = "https://github.com/0x00-0x00/ShellPop"
		date = "2018-05-18"
		hash1 = "267f69858a5490efb236628260b275ad4bbfeebf4a83fab8776e333ca706a6a0"
		id = "23c331ba-217c-5b17-b45e-d553eea76a56"

	strings:
		$s1 = {73 6f 63 61 74 20 74 63 70 2d 63 6f 6e 6e 65 63 74}
		$s2 = {2c 70 74 79 2c 73 74 64 65 72 72 2c 73 65 74 73 69 64 2c 73 69 67 69 6e 74 2c 73 61 6e 65}

	condition:
		filesize < 1KB and 2 of them
}

rule HKTL_shellpop_Perl : hardened
{
	meta:
		description = "Detects Shellpop Perl script"
		author = "Tobias Michalski"
		reference = "https://github.com/0x00-0x00/ShellPop"
		date = "2018-05-18"
		hash1 = "32c3e287969398a070adaad9b819ee9228174c9cb318d230331d33cda51314eb"
		id = "d597d213-a70b-5412-adde-791b4d498848"

	strings:
		$ = {70 65 72 6c 20 2d 65 20 27 75 73 65 20 49 4f 3a 3a 53 6f 63 6b 65 74 3a 3a 49 4e 45 54 3b 24 7c 3d 31 3b 6d 79 20 28 24 73 2c 24 72 29 3b}
		$ = {3b 53 54 44 49 4e 2d 3e 66 64 6f 70 65 6e 28 5c 24 63 2c 72 29 3b 24 7e 2d 3e 66 64 6f 70 65 6e 28 5c 24 63 2c 77 29 3b 73}

	condition:
		filesize < 2KB and 1 of them
}

rule HKTL_shellpop_Python : hardened
{
	meta:
		description = "Detects malicious python shell"
		author = "Tobias Michalski"
		reference = "https://github.com/0x00-0x00/ShellPop"
		date = "2018-05-18"
		hash1 = "aee1c9e45a1edb5e462522e266256f68313e2ff5956a55f0a84f33bc6baa980b"
		id = "62fe0ae9-422e-5021-8a67-e88ff4bd2cf3"

	strings:
		$ = {6f 73 2e 70 75 74 65 6e 76 28 27 48 49 53 54 46 49 4c 45 27 2c 20 27 2f 64 65 76 2f 6e 75 6c 6c 27 29 3b}

	condition:
		filesize < 2KB and 1 of them
}

rule HKTL_shellpop_PHP_TCP : hardened
{
	meta:
		description = "Detects malicious PHP shell"
		author = "Tobias Michalski"
		reference = "https://github.com/0x00-0x00/ShellPop"
		date = "2018-05-18"
		hash1 = "0412e1ab9c672abecb3979a401f67d35a4a830c65f34bdee3f87e87d060f0290"
		id = "3bafc225-62e5-5183-84aa-9c3406b6c444"

	strings:
		$x1 = {70 68 70 20 2d 72 20 22 5c 24 73 6f 63 6b 3d 66 73 6f 63 6b 6f 70 65 6e}
		$x2 = {3b 65 78 65 63 28 27 2f 62 69 6e 2f 73 68 20 2d 69 20 3c 26 33 20 3e 26 33 20 32 3e 26 33 27 29 3b 22}

	condition:
		filesize < 3KB and all of them
}

rule HKTL_shellpop_Powershell_TCP : hardened
{
	meta:
		description = "Detects malicious powershell"
		author = "Tobias Michalski"
		reference = "https://github.com/0x00-0x00/ShellPop"
		date = "2018-05-18"
		hash1 = "8328806700696ffe8cc37a0b81a67a6e9c86bb416364805b8aceaee5db17333f"
		id = "4f3a92db-f686-559a-9588-fb79f423c51f"

	strings:
		$ = {53 6f 6d 65 74 68 69 6e 67 20 77 65 6e 74 20 77 72 6f 6e 67 20 77 69 74 68 20 65 78 65 63 75 74 69 6f 6e 20 6f 66 20 63 6f 6d 6d 61 6e 64 20 6f 6e 20 74 68 65 20 74 61 72 67 65 74}
		$ = {3b 5b 62 79 74 65 5b 5d 5d 24 62 79 74 65 73 20 3d 20 30 2e 2e 36 35 35 33 35 7c 25 7b 30 7d 3b 24 73 65 6e 64 62 79 74 65 73 20 3d}

	condition:
		filesize < 3KB and 1 of them
}

rule SUSP_Powershell_ShellCommand_May18_1 : hardened
{
	meta:
		description = "Detects a supcicious powershell commandline"
		author = "Tobias Michalski"
		reference = "https://github.com/0x00-0x00/ShellPop"
		date = "2018-05-18"
		hash1 = "8328806700696ffe8cc37a0b81a67a6e9c86bb416364805b8aceaee5db17333f"
		id = "efa81fd0-b764-5a1a-98a5-fc3135be220b"

	strings:
		$x1 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 6e 6f 70 20 2d 65 70 20 62 79 70 61 73 73 20 2d 43 6f 6d 6d 61 6e 64}

	condition:
		filesize < 3KB and 1 of them
}

rule HKTL_shellpop_Telnet_TCP : hardened
{
	meta:
		description = "Detects malicious telnet shell"
		author = "Tobias Michalski"
		reference = "https://github.com/0x00-0x00/ShellPop"
		date = "2018-05-18"
		hash1 = "cf5232bae0364606361adafab32f19cf56764a9d3aef94890dda9f7fcd684a0e"
		id = "dbd5cc65-c6f1-54f3-813f-7a7f9bcca184"

	strings:
		$x1 = {69 66 20 5b 20 2d 65 20 2f 74 6d 70 2f 66 20 5d 3b 20 74 68 65 6e 20 72 6d 20 2f 74 6d 70 2f 66 3b}
		$x2 = {30 3c 2f 74 6d 70 2f 66 7c 2f 62 69 6e 2f 62 61 73 68 20 31 3e 2f 74 6d 70 2f 66}

	condition:
		filesize < 3KB and 1 of them
}

rule SUSP_shellpop_Bash : hardened
{
	meta:
		description = "Detects susupicious bash command"
		author = "Tobias Michalski"
		reference = "https://github.com/0x00-0x00/ShellPop"
		date = "2018-05-18"
		hash1 = "36fad575a8bc459d0c2e3ad626e97d5cf4f5f8bedc56b3cc27dd2f7d88ed889b"
		id = "ea9c2491-8b25-5ba4-9968-22a45d6e6491"

	strings:
		$ = {2f 62 69 6e 2f 62 61 73 68 20 2d 69 20 3e 26 20 2f 64 65 76 2f 74 63 70 2f}

	condition:
		1 of them
}

rule HKTL_shellpop_netcat : hardened
{
	meta:
		description = "Detects suspcious netcat shellpop"
		author = "Tobias Michalski"
		reference = "https://github.com/0x00-0x00/ShellPop"
		date = "2018-05-18"
		hash1 = "98e3324f4c096bb1e5533114249a9e5c43c7913afa3070488b16d5b209e015ee"
		id = "cd55e912-b57b-5fce-98eb-5a0cd27a6e4d"

	strings:
		$s1 = {69 66 20 5b 20 2d 65 20 2f 74 6d 70 2f 66 20 5d 3b 20 74 68 65 6e 20 72 6d 20 2f 74 6d 70 2f 66 3b}
		$s2 = {66 69 3b 6d 6b 66 69 66 6f 20 2f 74 6d 70 2f 66 3b 63 61 74 20 2f 74 6d 70 2f 66 7c 2f 62 69 6e 2f 73 68 20 2d 69 20 32 3e 26 31 7c 6e 63}
		$s4 = {6d 6b 6e 6f 64 20 2f 74 6d 70 2f 66 20 70 20 26 26 20 6e 63}
		$s5 = {3c 2f 74 6d 70 2f 66 7c 2f 62 69 6e 2f 62 61 73 68 20 31 3e 2f 74 6d 70 2f 66}

	condition:
		filesize < 2KB and 1 of them
}

rule HKTL_beRootexe : hardened
{
	meta:
		description = "Detects beRoot.exe which checks common Windows missconfigurations"
		author = "yarGen Rule Generator"
		reference = "https://github.com/AlessandroZ/BeRoot/tree/master/Windows"
		date = "2018-07-25"
		hash1 = "865b3b8ec9d03d3475286c3030958d90fc72b21b0dca38e5bf8e236602136dd7"
		id = "b91c2e0b-2e47-5339-bf48-eaa8329ea63b"

	strings:
		$s1 = {63 68 65 63 6b 73 2e 77 65 62 63 6c 69 65 6e 74 2e 73 65 63 72 65 74 73 64 75 6d 70 28}
		$s2 = {62 65 72 6f 6f 74 2e 6d 6f 64 75 6c 65 73}
		$s3 = {62 65 52 6f 6f 74 2e 65 78 65 2e 6d 61 6e 69 66 65 73 74}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 18000KB and 1 of them )
}

rule HKTL_beRootexe_output : hardened
{
	meta:
		description = "Detects the output of beRoot.exe"
		author = "Tobias Michalski"
		reference = "https://github.com/AlessandroZ/BeRoot/tree/master/Windows"
		date = "2018-07-25"
		id = "dfd11915-443f-5ce9-b94a-bdcb0e62104e"

	strings:
		$s1 = {70 00 65 00 72 00 6d 00 69 00 73 00 73 00 69 00 6f 00 6e 00 73 00 3a 00 20 00 7b 00 27 00 63 00 68 00 61 00 6e 00 67 00 65 00 5f 00 63 00 6f 00 6e 00 66 00 69 00 67 00 27 00}
		$s2 = {46 00 75 00 6c 00 6c 00 20 00 70 00 61 00 74 00 68 00 3a 00 20 00 43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 6d 00 73 00 69 00 65 00 78 00 65 00 63 00 2e 00 65 00 78 00 65 00 20 00 2f 00 56 00}
		$s3 = {46 00 75 00 6c 00 6c 00 20 00 70 00 61 00 74 00 68 00 3a 00 20 00 43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 20 00 2d 00 6b 00 20 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 46 00 6c 00 6f 00 77 00}
		$s4 = {21 00 20 00 42 00 41 00 4e 00 47 00 20 00 42 00 41 00 4e 00 47 00 20 00 21 00}

	condition:
		filesize < 400KB and 3 of them
}

rule HKTL_EmbeddedPDF : hardened
{
	meta:
		description = "Detects Embedded PDFs which can start malicious content"
		author = "Tobias Michalski"
		reference = "https://twitter.com/infosecn1nja/status/1021399595899731968?s=12"
		date = "2018-07-25"
		id = "d4e2d878-fb75-54c5-9879-fe94102911d1"

	strings:
		$x1 = {2f 54 79 70 65 20 2f 41 63 74 69 6f 6e 0a 20 2f 53 20 2f 4a 61 76 61 53 63 72 69 70 74 0a 20 2f 4a 53 20 28 74 68 69 73 2e 65 78 70 6f 72 74 44 61 74 61 4f 62 6a 65 63 74 28 7b}
		$s1 = {28 54 68 69 73 20 50 44 46 20 64 6f 63 75 6d 65 6e 74 20 65 6d 62 65 64 73 20 66 69 6c 65}
		$s2 = {2f 4e 61 6d 65 73 20 3c 3c 20 2f 45 6d 62 65 64 64 65 64 46 69 6c 65 73 20 3c 3c 20 2f 4e 61 6d 65 73}
		$s3 = {2f 54 79 70 65 20 2f 45 6d 62 65 64 64 65 64 46 69 6c 65}

	condition:
		uint16( 0 ) == 0x5025 and 2 of ( $s* ) and $x1
}

rule HTKL_BlackBone_DriverInjector : hardened
{
	meta:
		description = "Detects BlackBone Driver injector"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/DarthTon/Blackbone"
		date = "2018-09-11"
		score = 60
		hash1 = "8062a4284c719412270614458150cb4abbdf77b2fc35f770ce9c45d10ccb1f4d"
		hash2 = "2d2fc27200c22442ac03e2f454b6e1f90f2bbc17017f05b09f7824fac6beb14b"
		hash3 = "e45da157483232d9c9c72f44b13fca2a0d268393044db00104cc1afe184ca8d1"
		id = "0d992a6c-c57a-5895-af0d-9c167d922601"

	strings:
		$s1 = {3d 49 4e 49 54 74 48 3d 50 41 47 45 74 41}
		$s2 = {42 42 49 6e 6a 65 63 74 44 6c 6c}
		$s3 = {4c 64 72 4c 6f 61 64 44 6c 6c}
		$s4 = {5c 00 3f 00 3f 00 5c 00 70 00 69 00 70 00 65 00 5c 00 25 00 6c 00 73 00}
		$s5 = {46 61 69 6c 65 64 20 74 6f 20 72 65 74 72 69 65 76 65 20 4b 65 72 6e 65 6c 20 62 61 73 65 20 61 64 64 72 65 73 73 2e 20 41 62 6f 72 74 69 6e 67}
		$x2 = {42 6c 61 63 6b 42 6f 6e 65 3a 20 25 73 3a 20 41 50 43 20 69 6e 6a 65 63 74 69 6f 6e 20 66 61 69 6c 65 64 20 77 69 74 68 20 73 74 61 74 75 73 20 30 78 25 58}
		$x3 = {42 6c 61 63 6b 42 6f 6e 65 3a 20 50 44 45 5f 42 41 53 45 2f 50 54 45 5f 42 41 53 45 20 6e 6f 74 20 66 6f 75 6e 64 20}
		$x4 = {25 73 3a 20 49 6e 76 61 6c 69 64 20 69 6e 6a 65 63 74 69 6f 6e 20 74 79 70 65 20 73 70 65 63 69 66 69 65 64 20 2d 20 25 64}
		$x6 = {54 00 72 00 79 00 69 00 6e 00 67 00 20 00 74 00 6f 00 20 00 6d 00 61 00 70 00 20 00 43 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 69 00 6e 00 74 00 6f 00 20 00 63 00 75 00 72 00 72 00 65 00 6e 00 74 00 20 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00}
		$x7 = {5c 42 6c 61 63 6b 42 6f 6e 65 44 72 76 5c 62 69 6e 5c}
		$x8 = {44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 42 00 6c 00 61 00 63 00 6b 00 42 00 6f 00 6e 00 65 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 8000KB and ( 3 of them or 1 of ( $x* ) )
}

rule HKTL_SqlMap : hardened
{
	meta:
		description = "Detects sqlmap hacktool"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/sqlmapproject/sqlmap"
		date = "2018-10-09"
		hash1 = "9444478b03caf7af853a64696dd70083bfe67f76aa08a16a151c00aadb540fa8"
		id = "da2029dd-c4ce-557f-a409-c468fa3deef3"

	strings:
		$x1 = {69 66 20 63 6d 64 4c 69 6e 65 4f 70 74 69 6f 6e 73 2e 67 65 74 28 22 73 71 6c 6d 61 70 53 68 65 6c 6c 22 29 3a}
		$x2 = {69 66 20 63 6f 6e 66 2e 67 65 74 28 22 64 75 6d 70 65 72 22 29 3a}

	condition:
		filesize < 50KB and 1 of them
}

rule HKTL_SqlMap_backdoor : hardened
{
	meta:
		description = "Detects SqlMap backdoors"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/sqlmapproject/sqlmap"
		date = "2018-10-09"
		id = "bf09caac-cf15-5936-b5b4-df4f28788961"

	condition:
		( uint32( 0 ) == 0x8e859c07 or uint32( 0 ) == 0x2d859c07 or uint32( 0 ) == 0x92959c07 or uint32( 0 ) == 0x929d9c07 or uint32( 0 ) == 0x29959c07 or uint32( 0 ) == 0x2b8d9c07 or uint32( 0 ) == 0x2b859c07 or uint32( 0 ) == 0x28b59c07 ) and filesize < 2KB
}

rule HKTL_Lazagne_PasswordDumper_Dec18_1 : hardened
{
	meta:
		description = "Detects password dumper Lazagne often used by middle eastern threat groups"
		author = "Florian Roth (Nextron Systems)"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		reference = "https://www.symantec.com/blogs/threat-intelligence/seedworm-espionage-group"
		date = "2018-12-11"
		score = 85
		hash1 = "1205f5845035e3ee30f5a1ced5500d8345246ef4900bcb4ba67ef72c0f79966c"
		hash2 = "884e991d2066163e02472ea82d89b64e252537b28c58ad57d9d648b969de6a63"
		hash3 = "bf8f30031769aa880cdbe22bc0be32691d9f7913af75a5b68f8426d4f0c7be50"
		id = "bae48a4d-33b6-55b9-abf5-daf87e5da9e9"

	strings:
		$s1 = {73 6f 66 74 77 61 72 65 73 2e 6f 70 65 72 61 28}
		$s2 = {73 6f 66 74 77 61 72 65 73 2e 6d 6f 7a 69 6c 6c 61 28}
		$s3 = {63 6f 6e 66 69 67 2e 64 69 63 6f 28}
		$s4 = {73 6f 66 74 77 61 72 65 73 2e 63 68 72 6f 6d 65 28}
		$s5 = {73 6f 66 74 77 61 72 65 73 2e 6f 75 74 6c 6f 6f 6b 28}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 17000KB and 1 of them
}

rule HKTL_Lazagne_Gen_18 : hardened
{
	meta:
		description = "Detects Lazagne password extractor hacktool"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/AlessandroZ/LaZagne"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		date = "2018-12-11"
		score = 80
		hash1 = "51121dd5fbdfe8db7d3a5311e3e9c904d644ff7221b60284c03347938577eecf"
		id = "034ea6d8-f5cf-5664-9ff9-24d19403093d"

	strings:
		$x1 = {6c 61 7a 61 67 6e 65 2e 63 6f 6e 66 69 67 2e 70 6f 77 65 72 73 68 65 6c 6c 5f 65 78 65 63 75 74 65 28}
		$x2 = {63 72 65 64 64 75 6d 70 37 2e 77 69 6e 33 32 2e}
		$x3 = {6c 61 7a 61 67 6e 65 2e 73 6f 66 74 77 61 72 65 73 2e 77 69 6e 64 6f 77 73 2e 68 61 73 68 64 75 6d 70}
		$x4 = {2e 73 6f 66 74 77 61 72 65 73 2e 6d 65 6d 6f 72 79 2e 6c 69 62 6b 65 65 70 61 73 73 2e 63 6f 6d 6d 6f 6e 28}

	condition:
		2 of them
}

rule HKTL_NoPowerShell : hardened
{
	meta:
		description = "Detects NoPowerShell hack tool"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/bitsadmin/nopowershell"
		date = "2018-12-28"
		modified = "2022-12-21"
		hash1 = "2dad091dd00625762a7590ce16c3492cbaeb756ad0e31352a42751deb7cf9e70"
		id = "17d508d5-833f-5232-a071-dbed8758493b"

	strings:
		$x1 = {5c 4e 6f 50 6f 77 65 72 53 68 65 6c 6c 2e 70 64 62}
		$x2 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 57 00 6d 00 69 00 4d 00 65 00 74 00 68 00 6f 00 64 00 20 00 2d 00 43 00 6c 00 61 00 73 00 73 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 2d 00 4e 00 61 00 6d 00 65 00 20 00 43 00 72 00 65 00 61 00 74 00 65 00 20 00 22 00 63 00 6d 00 64 00}
		$x3 = {6c 00 73 00 20 00 43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 20 00 2d 00 49 00 6e 00 63 00 6c 00 75 00 64 00 65 00 20 00 2a 00 2e 00 65 00 78 00 65 00 20 00 7c 00 20 00 73 00 65 00 6c 00 65 00 63 00 74 00 20 00 2d 00 46 00 69 00 72 00 73 00 74 00 20 00 31 00 30 00 20 00 4e 00 61 00 6d 00 65 00 2c 00 4c 00 65 00 6e 00 67 00 74 00 68 00}
		$x4 = {6c 00 73 00 20 00 2d 00 52 00 65 00 63 00 75 00 72 00 73 00 65 00 20 00 2d 00 46 00 6f 00 72 00 63 00 65 00 20 00 43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 20 00 2d 00 49 00 6e 00 63 00 6c 00 75 00 64 00 65 00 20 00 2a 00 2e 00 6b 00 64 00 62 00 78 00}
		$x5 = {4e 00 6f 00 50 00 6f 00 77 00 65 00 72 00 53 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00}

	condition:
		1 of them
}

rule HKTL_htran_go : hardened
{
	meta:
		author = "Jeff Beley"
		hash1 = "4acbefb9f7907c52438ebb3070888ddc8cddfe9e3849c9d0196173a422b9035f"
		description = "Detects go based htran variant"
		date = "2019-01-09"
		id = "bd9409e3-3d4c-57d6-af60-b6d6bd93d46b"

	strings:
		$s1 = {68 74 74 70 73 3a 2f 2f 67 69 74 68 75 62 2e 63 6f 6d 2f 63 77 31 39 39 37 2f 4e 41 54 42 79 70 61 73 73}
		$s2 = {2d 73 6c 61 76 65 20 69 70 31 3a 70 6f 72 74 31 20 69 70 32 3a 70 6f 72 74 32}
		$s3 = {2d 74 72 61 6e 20 70 6f 72 74 31 20 69 70 3a 70 6f 72 74 32}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 7000KB and 1 of them
}

rule SUSP_Katz_PDB : hardened
{
	meta:
		description = "Detects suspicious PDB in file"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2019-02-04"
		hash1 = "6888ce8116c721e7b2fc3d7d594666784cf38a942808f35e309a48e536d8e305"
		id = "79f4f07c-b234-5203-a2ab-aba4a9cb9f8d"

	strings:
		$s1 = /\\Release\\[a-z]{0,8}katz.pdb/
		$s2 = /\\Debug\\[a-z]{0,8}katz.pdb/

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 6000KB and all of them
}

rule HKTL_LNX_Pnscan : hardened
{
	meta:
		description = "Detects Pnscan port scanner"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/ptrrkssn/pnscan"
		date = "2019-05-27"
		score = 55
		id = "46c6c0d9-08bb-5de3-ad14-c1a7ab0542c6"

	strings:
		$x1 = {2d 52 3c 68 65 78 20 6c 69 73 74 3e 20 20 20 48 65 78 20 63 6f 64 65 64 20 72 65 73 70 6f 6e 73 65 20 73 74 72 69 6e 67 20 74 6f 20 6c 6f 6f 6b 20 66 6f 72 2e}
		$x2 = {((54 68 69 73 20 70 72 6f 67 72 61 6d 20 69 6d 70 6c 65 6d 65 6e 74 73 20 61 20 6d 75 6c 74 69 74 68 72 65 61 64 65 64 20 54 43 50 20 70 6f 72 74 20 73 63 61 6e 6e 65 72 2e) | (54 00 68 00 69 00 73 00 20 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 69 00 6d 00 70 00 6c 00 65 00 6d 00 65 00 6e 00 74 00 73 00 20 00 61 00 20 00 6d 00 75 00 6c 00 74 00 69 00 74 00 68 00 72 00 65 00 61 00 64 00 65 00 64 00 20 00 54 00 43 00 50 00 20 00 70 00 6f 00 72 00 74 00 20 00 73 00 63 00 61 00 6e 00 6e 00 65 00 72 00 2e 00))}

	condition:
		filesize < 6000KB and 1 of them
}

rule PAExec : hardened
{
	meta:
		description = "Detects remote access tool PAEXec (like PsExec) - file PAExec.exe"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://researchcenter.paloaltonetworks.com/2017/03/unit42-shamoon-2-delivering-disttrack/"
		date = "2017-03-27"
		score = 40
		hash1 = "01a461ad68d11b5b5096f45eb54df9ba62c5af413fa9eb544eacb598373a26bc"
		id = "ee564534-b921-5639-a7ed-5da79d6bf86a"

	strings:
		$x1 = {45 78 3a 20 2d 72 6c 6f 20 43 3a 5c 54 65 6d 70 5c 50 41 45 78 65 63 2e 6c 6f 67}
		$x2 = {43 00 61 00 6e 00 27 00 74 00 20 00 65 00 6e 00 75 00 6d 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 65 00 73 00 20 00 2d 00 20 00 46 00 61 00 69 00 6c 00 65 00 64 00 20 00 74 00 6f 00 20 00 67 00 65 00 74 00 20 00 74 00 6f 00 6b 00 65 00 6e 00 20 00 66 00 6f 00 72 00 20 00 4c 00 6f 00 63 00 61 00 6c 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00 2e 00}
		$x3 = {50 00 41 00 45 00 78 00 65 00 63 00 20 00 25 00 73 00 20 00 2d 00 20 00 45 00 78 00 65 00 63 00 75 00 74 00 65 00 20 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 73 00 20 00 52 00 65 00 6d 00 6f 00 74 00 65 00 6c 00 79 00}
		$x4 = {5c 00 5c 00 25 00 73 00 5c 00 70 00 69 00 70 00 65 00 5c 00 50 00 41 00 45 00 78 00 65 00 63 00 49 00 6e 00 25 00 73 00 25 00 75 00}
		$x5 = {5c 00 5c 00 2e 00 5c 00 70 00 69 00 70 00 65 00 5c 00 50 00 41 00 45 00 78 00 65 00 63 00 49 00 6e 00 25 00 73 00 25 00 75 00}
		$x6 = {25 00 25 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 25 00 25 00 5c 00 25 00 73 00 2e 00 65 00 78 00 65 00}
		$x7 = {69 6e 20 72 65 70 6c 61 63 65 6d 65 6e 74 20 66 6f 72 20 50 73 45 78 65 63 2c 20 73 6f 20 74 68 65 20 63 6f 6d 6d 61 6e 64 2d 6c 69 6e 65 20 75 73 61 67 65 20 69 73 20 69 64 65 6e 74 69 63 61 6c 2c 20 77 69 74 68 20}
		$x8 = {5c 00 5c 00 25 00 73 00 5c 00 41 00 44 00 4d 00 49 00 4e 00 24 00 5c 00 50 00 41 00 45 00 78 00 65 00 63 00 5f 00 4d 00 6f 00 76 00 65 00 25 00 75 00 2e 00 64 00 61 00 74 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 600KB and 1 of ( $x* ) ) or ( 3 of them )
}

rule HKTL_DomainPasswordSpray : hardened
{
	meta:
		description = "Detects the Powershell password spray tool DomainPasswordSpray"
		author = "Arnim Rupp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		reference = "https://github.com/dafthack/DomainPasswordSpray"
		date = "2023-01-13"
		score = 60
		hash1 = "44d4c0ae5673d2a076f3b5acdc83063aca49d58e6dd7cf73d0b927f83d359247"
		id = "890e4514-2846-54f8-8f32-cc9d2a4ef81b"

	strings:
		$s = {((49 6e 76 6f 6b 65 2d 44 6f 6d 61 69 6e 50 61 73 73 77 6f 72 64 53 70 72 61 79) | (49 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 44 00 6f 00 6d 00 61 00 69 00 6e 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 53 00 70 00 72 00 61 00 79 00))}

	condition:
		filesize < 100KB and all of them
}

rule HKTL_RustHound : hardened
{
	meta:
		description = "Detect hacktool RustHound (Sharphound clone)"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-03-30"
		reference = "https://github.com/OPENCYBER-FR/RustHound"
		hash = "409f61a34d9771643246f401a9670f6f7dcced9df50cbd89a2e1a5c9ba8d03ab"
		hash = "b1a58a9c94b1df97a243e6c3fc2d04ffd92bc802edc7d8e738573b394be331a9"
		hash = "170f4a48911f3ebef674aade05184ea0a6b1f6b089bcffd658e95b9905423365"
		hash = "e52f6496b863b08296bf602e92a090768e86abf498183aa5b6531a3a2d9c0bdb"
		hash = "847e57a35df29d40858c248e5b278b09cfa89dd4201cb24262c6158395e2e585"
		hash = "4edfed92b54d32a58b2cfc926f98a56637e89850410706abcc469a8bc846bc85"
		hash = "feba0c16830ea0a13819a9ab8a221cc64d5a9b3cc73f3c66c405a171a2069cc1"
		hash = "21d37c2393a6f748fe34c9d2f52693cb081b63c3a02ca0bebe4a584076f5886c"
		hash = "874a1a186eb5808d456ce86295cd5f09d6c819375acb100573c2103608af0d84"
		hash = "bf576bd229393010b2bb4ba17e49604109e294ca38cf19647fc7d9c325f7bcd1"
		id = "d2fd79a5-9a1a-51de-920c-61653c8b0064"

	strings:
		$rh1 = {((72 75 73 74 68 6f 75 6e 64) | (72 00 75 00 73 00 74 00 68 00 6f 00 75 00 6e 00 64 00))}
		$rh2 = {((4d 61 6b 69 6e 67 20 6a 73 6f 6e 2f 7a 69 70 20 66 69 6c 65 73 20 66 69 6e 69 73 68 65 64 21) | (4d 00 61 00 6b 00 69 00 6e 00 67 00 20 00 6a 00 73 00 6f 00 6e 00 2f 00 7a 00 69 00 70 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 66 00 69 00 6e 00 69 00 73 00 68 00 65 00 64 00 21 00))}

	condition:
		( uint16( 0 ) == 0x5A4D or uint16( 0 ) == 0x457f ) and 1 of ( $rh* )
}

