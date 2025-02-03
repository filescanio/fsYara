rule APT_MAL_VEILEDSIGNAL_Backdoor_Apr23 : hardened
{
	meta:
		description = "Detects malicious VEILEDSIGNAL backdoor"
		author = "X__Junior"
		reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
		date = "2023-04-20"
		score = 85
		hash1 = "aa318070ad1bf90ed459ac34dc5254acc178baff3202d2ea7f49aaf5a055dd43"
		id = "74c403ea-3178-58e8-88b3-a51c1d475868"

	strings:
		$op1 = {B8 AB AA AA AA F7 E1 8B C1 C1 EA 02 8D 14 52 03 D2 2B C2 8A 84 05 ?? ?? ?? ?? 30 84 0D ?? ?? ?? ??}
		$op2 = { 50 66 0F 13 85 ?? ?? ?? ?? 66 0F 13 85 ?? ?? ?? ?? 66 0F 13 85 ?? ?? ?? ?? 66 0F 13 85 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 3C 00 00 00 C7 85 ?? ?? ?? ?? 40 00 00 00 C7 85 ?? ?? ?? ?? 05 00 00 00 FF 15}
		$op3 = { 6A 00 8D 85 ?? ?? ?? ?? 50 6A 04 8D 85 ?? ?? ?? ?? 50 57 FF 15 }

	condition:
		uint16( 0 ) == 0x5a4d and all of them
}

rule SUSP_APT_MAL_VEILEDSIGNAL_Backdoor_Apr23 : hardened
{
	meta:
		description = "Detects marker found in VEILEDSIGNAL backdoor"
		author = "X__Junior"
		reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
		date = "2023-04-20"
		modified = "2023-04-21"
		score = 75
		hash1 = "aa318070ad1bf90ed459ac34dc5254acc178baff3202d2ea7f49aaf5a055dd43"
		id = "8f0d92b6-d9b0-55e3-b2ca-601d095f5279"

	strings:
		$opb1 = { 81 BD ?? ?? ?? ?? 5E DA F3 76}
		$opb2 = { C7 85 ?? ?? ?? ?? 74 F2 39 DA 66 C7 85 ?? ?? ?? ?? E5 CF}
		$opb3 = { C7 85 ?? ?? ?? ?? 74 F2 39 DA B9 00 04 00 00 66 C7 85 ?? ?? ?? ?? E5 CF }

	condition:
		2 of them
}

rule APT_NK_MAL_M_Hunting_VEILEDSIGNAL_1 : hardened
{
	meta:
		description = "Detects VEILEDSIGNAL malware"
		author = "Mandiant"
		score = 75
		disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"
		hash1 = "404b09def6054a281b41d309d809a428"
		hash2 = "c6441c961dcad0fe127514a918eaabd4"
		reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
		date = "2023-04-20"
		id = "3e7c92fe-a7bd-5180-9935-4f98f2b64e2b"

	strings:
		$rh1 = { 68 5D 7A D2 2C 3C 14 81 2C 3C 14 81 2C 3C 14 81 77 54 10 80 26 3C 14 81 77 54 17 80 29 3C 14 81 77 54 11 80 AB 3C 14 81 D4 4C 11 80 33 3C 14 81 D4 4C 10 80 22 3C 14 81 D4 4C 17 80 25 3C 14 81 77 54 15 80 27 3C 14 81 2C 3C 15 81 4B 3C 14 81 94 4D 1D 80 28 3C 14 81 94 4D 14 80 2D 3C 14 81 94 4D 16 80 2D 3C 14 81 }
		$rh2 = { 00 E5 A0 2B 44 84 CE 78 44 84 CE 78 44 84 CE 78 1F EC CA 79 49 84 CE 78 1F EC CD 79 41 84 CE 78 1F EC CB 79 C8 84 CE 78 BC F4 CA 79 4A 84 CE 78 BC F4 CD 79 4D 84 CE 78 BC F4 CB 79 65 84 CE 78 1F EC CF 79 43 84 CE 78 44 84 CF 78 22 84 CE 78 FC F5 C7 79 42 84 CE 78 FC F5 CE 79 45 84 CE 78 FC F5 CC 79 45 84 CE 78}
		$rh3 = { DA D2 21 22 9E B3 4F 71 9E B3 4F 71 9E B3 4F 71 C5 DB 4C 70 94 B3 4F 71 C5 DB 4A 70 15 B3 4F 71 C5 DB 4B 70 8C B3 4F 71 66 C3 4B 70 8C B3 4F 71 66 C3 4C 70 8F B3 4F 71 C5 DB 49 70 9F B3 4F 71 66 C3 4A 70 B0 B3 4F 71 C5 DB 4E 70 97 B3 4F 71 9E B3 4E 71 F9 B3 4F 71 26 C2 46 70 9F B3 4F 71 26 C2 B0 71 9F B3 4F 71 9E B3 D8 71 9F B3 4F 71 26 C2 4D 70 9F B3 4F 71 }
		$rh4 = { CB 8A 35 66 8F EB 5B 35 8F EB 5B 35 8F EB 5B 35 D4 83 5F 34 85 EB 5B 35 D4 83 58 34 8A EB 5B 35 D4 83 5E 34 09 EB 5B 35 77 9B 5E 34 92 EB 5B 35 77 9B 5F 34 81 EB 5B 35 77 9B 58 34 86 EB 5B 35 D4 83 5A 34 8C EB 5B 35 8F EB 5A 35 D3 EB 5B 35 37 9A 52 34 8C EB 5B 35 37 9A 58 34 8E EB 5B 35 37 9A 5B 34 8E EB 5B 35 37 9A 59 34 8E EB 5B 35 }

	condition:
		uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 and 1 of ( $rh* )
}

rule APT_NK_MAL_M_Hunting_VEILEDSIGNAL_2 : hardened
{
	meta:
		description = "Detects VEILEDSIGNAL malware"
		author = "Mandiant"
		score = 75
		disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"
		hash1 = "404b09def6054a281b41d309d809a428"
		reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
		date = "2023-04-20"
		id = "1b96c2f0-1c57-593e-9630-a72d43eb857e"

	strings:
		$sb1 = { C1 E0 05 4D 8? [2] 33 D0 45 69 C0 7D 50 BF 12 8B C2 41 FF C2 C1 E8 07 33 D0 8B C2 C1 E0 16 41 81 C0 87 D6 12 00 }
		$si1 = {43 72 79 70 74 42 69 6e 61 72 79 54 6f 53 74 72 69 6e 67 41}
		$si2 = {42 43 72 79 70 74 47 65 6e 65 72 61 74 65 53 79 6d 6d 65 74 72 69 63 4b 65 79}
		$si3 = {43 72 65 61 74 65 54 68 72 65 61 64}
		$ss1 = {43 00 68 00 61 00 69 00 6e 00 69 00 6e 00 67 00 4d 00 6f 00 64 00 65 00 47 00 43 00 4d 00}
		$ss2 = {5f 5f 74 75 74 6d 61}

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) and all of them
}

rule APT_NK_MAL_M_Hunting_VEILEDSIGNAL_3 : hardened
{
	meta:
		description = "Detects VEILEDSIGNAL malware"
		author = "Mandiant"
		score = 75
		disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"
		md5 = "c6441c961dcad0fe127514a918eaabd4"
		reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
		date = "2023-04-20"
		id = "82790c65-1d93-509b-95df-841543943c30"

	strings:
		$ss1 = { 61 70 70 6C 69 63 61 74 69 6F 6E 2F 6A 73 6F 6E 2C 20 74 65 78 74 2F 6A 61 76 61 73 63 72 69 70 74 2C 20 2A 2F 2A 3B 20 71 3D 30 2E 30 31 00 00 61 63 63 65 70 74 00 00 65 6E 2D 55 53 2C 65 6E 3B 71 3D 30 2E 39 00 00 61 63 63 65 70 74 2D 6C 61 6E 67 75 61 67 65 00 63 6F 6F 6B 69 65 00 00 }
		$si1 = {48 74 74 70 53 65 6e 64 52 65 71 75 65 73 74 57}
		$si2 = {43 72 65 61 74 65 4e 61 6d 65 64 50 69 70 65 57}
		$si3 = {43 72 65 61 74 65 54 68 72 65 61 64}
		$se1 = {44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74}

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) and all of them
}

rule APT_NK_MAL_M_Hunting_VEILEDSIGNAL_4 : hardened
{
	meta:
		description = "Detects VEILEDSIGNAL malware"
		author = "Mandiant"
		score = 75
		disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"
		hash1 = "404b09def6054a281b41d309d809a428"
		hash2 = "c6441c961dcad0fe127514a918eaabd4"
		reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
		date = "2023-04-20"
		id = "379e6471-3c4f-5c72-b8fd-17f481e89ac6"

	strings:
		$sb1 = { FF 15 FC 76 01 00 8B F0 85 C0 74 ?? 8D 50 01 [6-16] FF 15 [4] 48 8B D8 48 85 C0 74 ?? 89 ?? 24 28 44 8B CD 4C 8B C? 48 89 44 24 20 }
		$sb2 = { 33 D2 33 C9 FF 15 [4] 4C 8B CB 4C 89 74 24 28 4C 8D 05 [2] FF FF 44 89 74 24 20 33 D2 33 C9 FF 15 }
		$si1 = {43 72 65 61 74 65 54 68 72 65 61 64}
		$si2 = {4d 75 6c 74 69 42 79 74 65 54 6f 57 69 64 65 43 68 61 72}
		$si3 = {4c 6f 63 61 6c 41 6c 6c 6f 63}
		$se1 = {44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74}

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) and all of them
}

rule APT_NK_MAL_M_Hunting_VEILEDSIGNAL_5 : hardened
{
	meta:
		description = "Detects VEILEDSIGNAL malware"
		author = "Mandiant"
		score = 75
		disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"
		hash1 = "6727284586ecf528240be21bb6e97f88"
		reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
		date = "2023-04-20"
		id = "7d0718fc-4f1c-5293-8dc4-81a5783fbfb2"

	strings:
		$sb1 = { 48 8D 15 [4] 48 8D 4C 24 4C E8 [4] 85 C0 74 ?? 48 8D 15 [4] 48 8D 4C 24 4C E8 [4] 85 C0 74 ?? 48 8D 15 [4] 48 8D 4C 24 4C E8 [4] 85 C0 74 ?? 48 8D [3] 48 8B CB FF 15 [4] EB }
		$ss1 = {63 00 68 00 72 00 6f 00 6d 00 65 00 2e 00 65 00 78 00 65 00}
		$ss2 = {66 00 69 00 72 00 65 00 66 00 6f 00 78 00 2e 00 65 00 78 00 65 00}
		$ss3 = {6d 00 73 00 65 00 64 00 67 00 65 00 2e 00 65 00 78 00 65 00}
		$ss4 = {5c 5c 2e 5c 70 69 70 65 5c 2a}
		$ss5 = {46 69 6e 64 46 69 72 73 74 46 69 6c 65 41}
		$ss6 = {50 72 6f 63 65 73 73 33 32 46 69 72 73 74 57}
		$ss7 = {52 74 6c 41 64 6a 75 73 74 50 72 69 76 69 6c 65 67 65}
		$ss8 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73}
		$ss9 = {4e 74 57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74}

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) and all of them
}

rule APT_NK_MAL_M_Hunting_VEILEDSIGNAL_6 : hardened
{
	meta:
		description = "Detects VEILEDSIGNAL malware"
		author = "Mandiant"
		score = 75
		disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"
		hash1 = "00a43d64f9b5187a1e1f922b99b09b77"
		reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
		date = "2023-04-20"
		id = "2cbedbc0-d465-5674-bf9c-9362003eb8d2"

	strings:
		$ss1 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 64 00 61 00 74 00 61 00 5c 00}
		$ss2 = {64 00 65 00 76 00 6f 00 62 00 6a 00 2e 00 64 00 6c 00 6c 00}
		$ss3 = {6d 00 73 00 76 00 63 00 72 00 31 00 30 00 30 00 2e 00 64 00 6c 00 6c 00}
		$ss4 = {54 00 70 00 6d 00 56 00 73 00 63 00 4d 00 67 00 72 00 53 00 76 00 72 00 2e 00 65 00 78 00 65 00}
		$ss5 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 54 00 50 00 4d 00}
		$ss6 = {43 72 65 61 74 65 46 69 6c 65 57}

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x010B ) and all of them
}

rule SUSP_NK_MAL_M_Hunting_POOLRAT : hardened limited
{
	meta:
		description = "Detects VEILEDSIGNAL malware"
		author = "Mandiant"
		old_rule_name = "APT_NK_MAL_M_Hunting_POOLRAT"
		score = 70
		disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"
		description = "Detects strings found in POOLRAT malware"
		hash1 = "451c23709ecd5a8461ad060f6346930c"
		reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
		date = "2023-04-20"
		id = "70f5f3a0-0fd0-54dc-97cc-4f3c35f02fcd"

	strings:
		$s1 = {((6e 61 6d 65 3d 22 75 69 64 22 25 73 25 73 25 75 25 73) | (6e 00 61 00 6d 00 65 00 3d 00 22 00 75 00 69 00 64 00 22 00 25 00 73 00 25 00 73 00 25 00 75 00 25 00 73 00))}
		$s2 = {((6e 61 6d 65 3d 22 73 65 73 73 69 6f 6e 22 25 73 25 73 25 75 25 73) | (6e 00 61 00 6d 00 65 00 3d 00 22 00 73 00 65 00 73 00 73 00 69 00 6f 00 6e 00 22 00 25 00 73 00 25 00 73 00 25 00 75 00 25 00 73 00))}
		$s3 = {((6e 61 6d 65 3d 22 61 63 74 69 6f 6e 22 25 73 25 73 25 73 25 73) | (6e 00 61 00 6d 00 65 00 3d 00 22 00 61 00 63 00 74 00 69 00 6f 00 6e 00 22 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00))}
		$s4 = {((6e 61 6d 65 3d 22 74 6f 6b 65 6e 22 25 73 25 73 25 75 25 73) | (6e 00 61 00 6d 00 65 00 3d 00 22 00 74 00 6f 00 6b 00 65 00 6e 00 22 00 25 00 73 00 25 00 73 00 25 00 75 00 25 00 73 00))}
		$str1 = {((2d 2d 4e 39 64 4c 66 71 78 48 4e 55 55 77 38 71 61 55 50 71 67 67 56 54 70 58 2d) | (2d 00 2d 00 4e 00 39 00 64 00 4c 00 66 00 71 00 78 00 48 00 4e 00 55 00 55 00 77 00 38 00 71 00 61 00 55 00 50 00 71 00 67 00 67 00 56 00 54 00 70 00 58 00 2d 00))}

	condition:
		any of ( $s* ) or $str1
}

rule APT_NK_TradingTech_ForensicArtifacts_Apr23_1 : hardened
{
	meta:
		description = "Detects forensic artifacts, file names and keywords related the Trading Technologies compromise UNC4736"
		author = "Florian Roth"
		reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
		date = "2023-04-20"
		modified = "2023-04-21"
		score = 60
		id = "f79a5321-4f22-52d9-aa83-4aa750ecc036"

	strings:
		$x1 = {((77 77 77 2e 74 72 61 64 69 6e 67 74 65 63 68 6e 6f 6c 6f 67 69 65 73 2e 63 6f 6d 2f 74 72 61 64 69 6e 67 2f 6f 72 64 65 72 2d 6d 61 6e 61 67 65 6d 65 6e 74) | (77 00 77 00 77 00 2e 00 74 00 72 00 61 00 64 00 69 00 6e 00 67 00 74 00 65 00 63 00 68 00 6e 00 6f 00 6c 00 6f 00 67 00 69 00 65 00 73 00 2e 00 63 00 6f 00 6d 00 2f 00 74 00 72 00 61 00 64 00 69 00 6e 00 67 00 2f 00 6f 00 72 00 64 00 65 00 72 00 2d 00 6d 00 61 00 6e 00 61 00 67 00 65 00 6d 00 65 00 6e 00 74 00))}
		$xf1 = {((58 5f 54 52 41 44 45 52 5f 72 37 2e 31 37 2e 39 30 70 36 30 38 2e 65 78 65) | (58 00 5f 00 54 00 52 00 41 00 44 00 45 00 52 00 5f 00 72 00 37 00 2e 00 31 00 37 00 2e 00 39 00 30 00 70 00 36 00 30 00 38 00 2e 00 65 00 78 00 65 00))}
		$xf2 = {((5c 58 5f 54 52 41 44 45 52 2d 6a 61 2e 6d 73 74) | (5c 00 58 00 5f 00 54 00 52 00 41 00 44 00 45 00 52 00 2d 00 6a 00 61 00 2e 00 6d 00 73 00 74 00))}
		$xf3 = {((43 3a 5c 50 72 6f 67 72 61 6d 64 61 74 61 5c 54 50 4d 5c 54 70 6d 56 73 63 4d 67 72 53 76 72 2e 65 78 65) | (43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 64 00 61 00 74 00 61 00 5c 00 54 00 50 00 4d 00 5c 00 54 00 70 00 6d 00 56 00 73 00 63 00 4d 00 67 00 72 00 53 00 76 00 72 00 2e 00 65 00 78 00 65 00))}
		$xf4 = {((43 3a 5c 50 72 6f 67 72 61 6d 64 61 74 61 5c 54 50 4d 5c 77 69 6e 73 63 61 72 64 2e 64 6c 6c) | (43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 64 00 61 00 74 00 61 00 5c 00 54 00 50 00 4d 00 5c 00 77 00 69 00 6e 00 73 00 63 00 61 00 72 00 64 00 2e 00 64 00 6c 00 6c 00))}
		$fp1 = {3c 68 74 6d 6c}

	condition:
		not uint16( 0 ) == 0x5025 and 1 of ( $x* ) and not 1 of ( $fp* )
}

import "pe"

rule SUSP_TH_APT_UNC4736_TradingTech_Cert_Apr23_1 : hardened
{
	meta:
		description = "Threat hunting rule that detects samples signed with the compromised Trading Technologies certificate after May 2022"
		author = "Florian Roth"
		reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
		date = "2023-04-20"
		score = 65
		id = "9a05fba9-9466-5b69-9207-27ad01d6eb8b"

	strings:
		$s1 = { 00 85 38 A6 C5 01 8F 50 FC }
		$s2 = {47 6f 20 44 61 64 64 79 20 53 65 63 75 72 65 20 43 65 72 74 69 66 69 63 61 74 65 20 41 75 74 68 6f 72 69 74 79 20 2d 20 47 32}
		$s3 = {54 72 61 64 69 6e 67 20 54 65 63 68 6e 6f 6c 6f 67 69 65 73 20 49 6e 74 65 72 6e 61 74 69 6f 6e 61 6c 2c 20 49 6e 63}

	condition:
		pe.timestamp> 1651363200 and all of them
}

