rule OilRig_Strings_Oct17 : hardened
{
	meta:
		description = "Detects strings from OilRig malware and malicious scripts"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://researchcenter.paloaltonetworks.com/2017/10/unit42-oilrig-group-steps-attacks-new-delivery-documents-new-injector-trojan/"
		date = "2017-10-18"
		modified = "2022-12-21"
		id = "edf7c7ca-0c58-5507-8d99-83078ff8947a"

	strings:
		$x1 = {((25 6c 6f 63 61 6c 61 70 70 64 61 74 61 25 5c 73 72 76 48 65 61 6c 74 68 2e 65 78 65) | (25 00 6c 00 6f 00 63 00 61 00 6c 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 25 00 5c 00 73 00 72 00 76 00 48 00 65 00 61 00 6c 00 74 00 68 00 2e 00 65 00 78 00 65 00))}
		$x2 = {((25 6c 6f 63 61 6c 61 70 70 64 61 74 61 25 5c 73 72 76 42 53 2e 74 78 74) | (25 00 6c 00 6f 00 63 00 61 00 6c 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 25 00 5c 00 73 00 72 00 76 00 42 00 53 00 2e 00 74 00 78 00 74 00))}
		$x3 = {41 67 65 6e 74 20 49 6e 6a 65 63 74 6f 72 5c 50 6f 6c 69 63 79 43 6f 6e 76 65 72 74 65 72 5c 49 6e 6e 65 72 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 49 6e 6e 65 72 2e 70 64 62}
		$x4 = {41 67 65 6e 74 20 49 6e 6a 65 63 74 6f 72 5c 50 6f 6c 69 63 79 43 6f 6e 76 65 72 74 65 72 5c 4a 6f 69 6e 65 72 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 4a 6f 69 6e 65 72 2e 70 64 62}
		$s3 = {2e 4c 6f 61 64 44 6c 6c 28 22 52 75 6e 22 2c 20 61 72 67 2c 20 22 43 3a 5c 5c 57 69 6e 64 6f 77 73 5c 5c}

	condition:
		filesize < 800KB and 1 of them
}

rule OilRig_ISMAgent_Campaign_Samples1 : hardened
{
	meta:
		description = "Detects OilRig malware from Unit 42 report in October 2017"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/JQVfFP"
		date = "2017-10-18"
		hash1 = "119c64a8b35bd626b3ea5f630d533b2e0e7852a4c59694125ff08f9965b5f9cc"
		hash2 = "0ccb2117c34e3045a4d2c0d193f1963c8c0e8566617ed0a561546c932d1a5c0c"
		id = "237fe7af-a2ab-51ae-bc96-3af46b08622a"

	strings:
		$s1 = {23 23 23 24 24 24 54 56 71 51 41 41 4d 41 41 41 41 45 41 41 41 41}
		$s2 = {43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 4a 00 2d 00 57 00 69 00 6e 00 2d 00 37 00 2d 00 33 00 32 00 2d 00 56 00 6d 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 65 00 72 00 72 00 6f 00 72 00 2e 00 6a 00 70 00 67 00}
		$s3 = {24 44 41 54 41 20 3d 20 5b 53 79 73 74 65 6d 2e 43 6f 6e 76 65 72 74 5d 3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 5b 49 4f 2e 46 69 6c 65 5d 3a 3a 52 65 61 64 41 6c 6c 54 65 78 74 28 27 25 42 61 73 65 25 27 29 29 3b 5b 69 6f 2e 66 69 6c 65 5d 3a 3a 57 72 69 74 65 41 6c 6c 42 79 74 65 73 28}
		$s4 = {((20 2f 63 20 65 63 68 6f 20 70 6f 77 65 72 73 68 65 6c 6c 20 3e 20) | (20 00 2f 00 63 00 20 00 65 00 63 00 68 00 6f 00 20 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 20 00 3e 00 20 00))}
		$s5 = {5c 00 4c 00 69 00 62 00 72 00 61 00 72 00 69 00 65 00 73 00 5c 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 72 00 65 00 73 00 65 00 74 00 2e 00 65 00 78 00 65 00}
		$s6 = {((25 44 65 73 74 46 6f 6c 64 65 72 25) | (25 00 44 00 65 00 73 00 74 00 46 00 6f 00 6c 00 64 00 65 00 72 00 25 00))}

	condition:
		uint16( 0 ) == 0xcfd0 and filesize < 3000KB and 2 of them
}

rule OilRig_ISMAgent_Campaign_Samples2 : hardened
{
	meta:
		description = "Detects OilRig malware from Unit 42 report in October 2017"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/JQVfFP"
		date = "2017-10-18"
		hash1 = "fcad263d0fe2b418db05f47d4036f0b42aaf201c9b91281dfdcb3201b298e4f4"
		hash2 = "33c187cfd9e3b68c3089c27ac64a519ccc951ccb3c74d75179c520f54f11f647"
		id = "08771b23-1d0e-5da7-b42c-005ed257e2d1"

	strings:
		$x1 = {50 00 6f 00 6c 00 69 00 63 00 79 00 43 00 6f 00 6e 00 76 00 65 00 72 00 74 00 65 00 72 00 2e 00 65 00 78 00 65 00}
		$x2 = {53 00 72 00 76 00 48 00 65 00 61 00 6c 00 74 00 68 00 2e 00 65 00 78 00 65 00}
		$x3 = {73 00 72 00 76 00 42 00 53 00 2e 00 74 00 78 00 74 00}
		$s1 = {7b 00 61 00 33 00 35 00 33 00 38 00 62 00 61 00 33 00 2d 00 35 00 63 00 66 00 37 00 2d 00 34 00 33 00 66 00 30 00 2d 00 62 00 63 00 30 00 65 00 2d 00 39 00 62 00 35 00 33 00 61 00 39 00 38 00 65 00 31 00 36 00 34 00 33 00 7d 00 2c 00 20 00 50 00 75 00 62 00 6c 00 69 00 63 00 4b 00 65 00 79 00 54 00 6f 00 6b 00 65 00 6e 00 3d 00 33 00 65 00 35 00 36 00 33 00 35 00 30 00 36 00 39 00 33 00 66 00 37 00 33 00 35 00 35 00 65 00}
		$s2 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 76 00 32 00 2e 00 30 00 2e 00 35 00 30 00 37 00 32 00 37 00 5c 00 52 00 65 00 67 00 41 00 73 00 6d 00 2e 00 65 00 78 00 65 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 700KB and ( 2 of ( $x* ) or 3 of them )
}

import "pe"

rule OilRig_ISMAgent_Campaign_Samples3 : hardened
{
	meta:
		description = "Detects OilRig malware from Unit 42 report in October 2017"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/JQVfFP"
		date = "2017-10-18"
		hash1 = "a9f1375da973b229eb649dc3c07484ae7513032b79665efe78c0e55a6e716821"
		id = "e26510bd-d183-566a-a185-ebed7a81401c"

	strings:
		$x1 = {63 6d 64 20 2f 63 20 73 63 68 74 61 73 6b 73 20 2f 71 75 65 72 79 20 2f 74 6e 20 54 69 6d 65 55 70 64 61 74 65 20 3e 20 4e 55 4c 20 32 3e 26 31}
		$x2 = {73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 73 63 20 6d 69 6e 75 74 65 20 2f 6d 6f 20 30 30 30 32 20 2f 74 6e 20 54 69 6d 65 55 70 64 61 74 65 20 2f 74 72}
		$x3 = {2d 63 20 20 53 61 6d 70 6c 65 44 6f 6d 61 69 6e 2e 63 6f 6d 20 2d 6d 20 73 63 68 65 64 75 6c 65 6d 69 6e 75 74 65 73}
		$x4 = {2e 6e 74 70 75 70 64 61 74 65 73 65 72 76 65 72 2e 63 6f 6d}
		$x5 = {2e 6d 73 6f 66 66 69 63 65 33 36 35 75 70 64 61 74 65 2e 63 6f 6d}
		$s1 = {6f 75 74 2e 65 78 65}
		$s2 = {5c 57 69 6e 33 32 50 72 6f 6a 65 63 74 31 5c 52 65 6c 65 61 73 65 5c 57 69 6e 33 32 50 72 6f 6a 65 63 74 31 2e 70 64 62}
		$s3 = {43 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 63 6d 64 2e 65 78 65 20 2f 63 20 28}
		$s4 = {43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65 3d 22 66 69 6c 65 22 3b 20 66 69 6c 65 6e 61 6d 65 3d 22 61 2e 61 22}
		$s5 = {41 67 65 6e 74 20 63 6f 6e 66 69 67 75 72 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79}
		$s6 = {5c 72 75 6e 6c 6f 67 2a}
		$s7 = {63 61 6e 20 6e 6f 74 20 73 70 65 63 69 66 79 20 75 73 65 72 6e 61 6d 65 21 21}
		$s8 = {41 67 65 6e 74 20 63 61 6e 20 6e 6f 74 20 62 65 20 63 6f 6e 66 69 67 75 72 65 64}
		$s9 = {25 30 38 6c 58 25 30 34 68 58 25 30 34 68 58 25 30 32 68 68 58 25 30 32 68 68 58 25 30 32 68 68 58 25 30 32 68 68 58 25 30 32 68 68 58 25 30 32 68 68 58 25 30 32 68 68 58 25 30 32 68 68 58}
		$s10 = {21 21 21 20 63 61 6e 20 6e 6f 74 20 63 72 65 61 74 65 20 6f 75 74 70 75 74 20 66 69 6c 65 20 21 21 21}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 400KB and ( pe.imphash ( ) == "538805ecd776b9a42e71aebf94fde1b1" or pe.imphash ( ) == "861ac226fbe8c99a2c43ff451e95da97" or ( 1 of ( $x* ) or 3 of them ) )
}

