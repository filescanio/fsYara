rule apt_hiddencobra_binaries : hardened
{
	meta:
		description = "HIDDEN COBRA – North Korea’s DDoS Botnet Infrastructure"
		author = "US-CERT"
		url = "https://www.us-cert.gov/ncas/alerts/TA17-164A"

	strings:
		$STR1 = {((57 61 74 69 6e 67) | (57 00 61 00 74 00 69 00 6e 00 67 00))}
		$STR2 = {((52 65 61 6d 69 6e) | (52 00 65 00 61 00 6d 00 69 00 6e 00))}
		$STR3 = {((6c 61 70 74 6f 73) | (6c 00 61 00 70 00 74 00 6f 00 73 00))}

	condition:
		( uint16( 0 ) == 0x5A4D or uint16( 0 ) == 0xCFD0 or uint16( 0 ) == 0xC3D4 or uint32( 0 ) == 0x46445025 or uint32( 1 ) == 0x6674725C ) and 2 of them
}

rule Malware_Updater : hardened
{
	meta:
		Author = "US-CERT Code Analysis Team"
		Date = "2017/08/02"
		Incident = "10132963"
		MD5_1 = "8F4FC2E10B6EC15A01E0AF24529040DD"
		MD5_2 = "584AC94142F0B7C0DF3D0ADDE6E661ED"
		Info = "Malware may be used to update multiple systems with secondary payloads"
		super_rule = 1
		report = "https://www.us-cert.gov/sites/default/files/publications/MAR-10132963.pdf"
		report = "https://www.us-cert.gov/HIDDEN-COBRA-North-Korean-Malicious-Cyber-Activity"

	strings:
		$s0 = { 8A4C040480F15D80C171884C04044083F8107CEC }
		$s1 = { 8A4D0080F19580E97C884D00454B75F0 }

	condition:
		any of them
}

rule NK_SSL_PROXY : hardened
{
	meta:
		Author = "US-CERT Code Analysis Team"
		Date = "2018/01/09"
		MD5_1 = "C6F78AD187C365D117CACBEE140F6230"
		MD5_2 = "C01DC42F65ACAF1C917C0CC29BA63ADC"
		Info = "Detects NK SSL PROXY"
		report = "https://www.us-cert.gov/sites/default/files/publications/MAR-10135536-G.PDF"
		report = "https://www.us-cert.gov/HIDDEN-COBRA-North-Korean-Malicious-Cyber-Activity"

	strings:
		$s0 = {8B4C24088A140880F24780C228881408403BC67CEF5E}
		$s1 = {568B74240C33C085F67E158B4C24088A140880EA2880F247881408403BC67CEF5E}
		$s2 = {4775401F713435747975366867766869375E2524736466}
		$s3 = {67686667686A75797566676467667472}
		$s4 = {6D2A5E265E676866676534776572}
		$s5 = {3171617A5853444332337765}
		$s6 = {67 68 66 67 68 6a 75 79 75 66 67 64 67 66 74 72}
		$s7 = {71 34 35 74 79 75 36 68 67 76 68 69 37 5e 25 24 73 64 66}
		$s8 = {6d 2a 5e 26 5e 67 68 66 67 65 34 77 65 72}

	condition:
		($s0 and $s1 and $s2 and $s3 and $s4 and $s5 ) or ( $s6 and $s7 and $s8 )
}

rule r4_wiper_1 : hardened
{
	meta:
		source = "NCCIC Partner"
		date = "2017-12-12"
		report = "https://www.us-cert.gov/sites/default/files/publications/MAR-10135536.11.WHITE.pdf"
		report = "https://www.us-cert.gov/HIDDEN-COBRA-North-Korean-Malicious-Cyber-Activity"

	strings:
		$mbr_code = { 33 C0 8E D0 BC 00 7C FB 50 07 50 1F FC BE 5D 7C 33 C9 41 81 F9 00 ?? 74 24 B4 43 B0 00 CD 13 FE C2 80 FA 84 7C F3 B2 80 BF 65 7C 81 05 00 04 83 55 02 00 83 55 04 00 83 55 06 00 EB D5 BE 4D 7C B4 43 B0 00 CD 13 33 C9 BE 5D 7C EB C5 }
		$controlServiceFoundlnBoth = { 83 EC 1C 57 68 3F 00 0F 00 6A 00 6A 00 FF 15 ?? ?? ?? ?? 8B F8 85 FF 74 44 8B 44 24 24 53 56 6A 24 50 57 FF 15 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 8B F0 85 F6 74 1C 8D 4C 24 0C 51 6A 01 56 FF 15 ?? ?? ?? ?? 68 E8 03 00 00 FF 15 ?? ?? ?? ?? 56 FF D3 57 FF D3 5E 5B 33 C0 5F 83 C4 1C C3 33 C0 5F 83 C4 1C C3 }

	condition:
		uint16( 0 ) == 0x5a4d and uint16( uint32( 0x3c ) ) == 0x4550 and any of them
}

rule r4_wiper_2 : hardened
{
	meta:
		source = "NCCIC Partner"
		date = "2017-12-12"
		report = "https://www.us-cert.gov/sites/default/files/publications/MAR-10135536.11.WHITE.pdf"
		report = "https://www.us-cert.gov/HIDDEN-COBRA-North-Korean-Malicious-Cyber-Activity"

	strings:
		$PhysicalDriveSTR = {5c 00 5c 00 2e 00 5c 00 50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 44 00 72 00 69 00 76 00 65 00}
		$ExtendedWrite = { B4 43 B0 00 CD 13 }

	condition:
		uint16( 0 ) == 0x5a4d and uint16( uint32( 0x3c ) ) == 0x4550 and all of them
}

