rule TeleBots_IntercepterNG : hardened
{
	meta:
		description = "Detects TeleBots malware - IntercepterNG"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/4if3HG"
		date = "2016-12-14"
		hash1 = "5f9fef7974d37922ac91365588fbe7b544e13abbbde7c262fe30bade7026e118"
		id = "f4d48eb6-8235-534d-a32f-7f2711b96e9d"

	strings:
		$s1 = {55 73 61 67 65 3a 20 25 73 20 69 66 61 63 65 5f 6e 75 6d 5c 64 75 6d 70 20 5b 6d 6f 64 65 5d 20 5b 77 5d 20 5b 2d 67 77 5d 20 5b 2d 74 31 20 69 70 5d}
		$s2 = {54 61 72 67 65 74 25 64 20 66 6f 75 6e 64 3a 20 25 73 20 2d 20 5b 25 2e 32 58 2d 25 2e 32 58 2d 25 2e 32 58 2d 25 2e 32 58 2d 25 2e 32 58 2d 25 2e 32 58 5d}
		$s3 = {33 3a 20 70 61 73 73 77 6f 72 64 73 20 2b 20 66 69 6c 65 73 2c 20 6e 6f 20 61 72 70 20 70 6f 69 73 6f 6e}
		$s4 = {49 52 43 20 4a 6f 69 6e 69 6e 67 20 4b 65 79 65 64 20 43 68 61 6e 6e 65 6c 20 69 6e 74 65 72 63 65 70 74 65 64}
		$s5 = {2d 74 58 20 2d 20 73 65 74 20 74 61 72 67 65 74 20 69 70}
		$s6 = {77 20 2d 20 73 61 76 65 20 73 65 73 73 69 6f 6e 20 74 6f 20 2e 70 63 61 70 20 64 75 6d 70}
		$s7 = {65 78 61 6d 70 6c 65 3a 20 25 73 20 31 20 31 20 2d 67 77 20 31 39 32 2e 31 36 38 2e 31 2e 31 20 2d 74 31 20 31 39 32 2e 31 36 38 2e 31 2e 33 20 2d 74 32 20 31 39 32 2e 31 36 38 2e 31 2e 35}
		$s8 = {4f 52 41 43 4c 45 38 20 44 45 53 20 41 75 74 68 6f 72 69 7a 61 74 69 6f 6e 20 69 6e 74 65 72 63 65 70 74 65 64}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 500KB and 1 of them ) or ( 4 of them )
}

rule TeleBots_KillDisk_1 : hardened
{
	meta:
		description = "Detects TeleBots malware - KillDisk"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/4if3HG"
		date = "2016-12-14"
		hash1 = "8246f709efa922a485e1ca32d8b0d10dc752618e8b3fce4d3dd58d10e4a6a16d"
		id = "111fc6bc-b790-51b9-81b7-a4716bb0aee9"

	strings:
		$s1 = {50 00 6c 00 75 00 67 00 2d 00 41 00 6e 00 64 00 2d 00 50 00 6c 00 61 00 79 00 20 00 53 00 75 00 70 00 70 00 6f 00 72 00 74 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00}
		$s2 = {20 00 2f 00 63 00 20 00 22 00 65 00 63 00 68 00 6f 00 20 00 59 00 7c 00}
		$s3 = {2d 73 65 74 3d 30 36 2e 31 32 2e 32 30 31 36 23 30 39 3a 33 30 20 2d 65 73 74 3d 31 34 31 30}
		$s4 = {25 64 2e 25 64 2e 25 64 23 25 64 3a 25 64}
		$s5 = {20 00 2f 00 54 00 20 00 2f 00 43 00 20 00 2f 00 47 00 20 00}
		$s6 = {5b 00 2d 00 5d 00 20 00 3e 00 20 00 25 00 6c 00 73 00}
		$s7 = {5b 00 2b 00 5d 00 20 00 3e 00 20 00 25 00 6c 00 73 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 500KB and 4 of them ) or ( 6 of them )
}

rule TeleBots_KillDisk_2 : hardened
{
	meta:
		description = "Detects TeleBots malware - KillDisk"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/4if3HG"
		date = "2016-12-14"
		hash1 = "26173c9ec8fd1c4f9f18f89683b23267f6f9d116196ed15655e9cb453af2890e"
		id = "7797187f-c94b-5323-ae43-2dc001f0b481"

	strings:
		$s1 = {50 00 6c 00 75 00 67 00 2d 00 41 00 6e 00 64 00 2d 00 50 00 6c 00 61 00 79 00 20 00 53 00 75 00 70 00 70 00 6f 00 72 00 74 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00}
		$s2 = {20 00 2f 00 63 00 20 00 22 00 65 00 63 00 68 00 6f 00 20 00 59 00 7c 00}
		$s3 = {25 64 2e 25 64 2e 25 64 23 25 64 3a 25 64}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 500KB and all of them )
}

rule TeleBots_CredRaptor_Password_Stealer : hardened
{
	meta:
		description = "Detects TeleBots malware - CredRaptor Password Stealer"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/4if3HG"
		date = "2016-12-14"
		modified = "2023-01-06"
		hash1 = "50b990f6555055a265fde98324759dbc74619d6a7c49b9fd786775299bf77d26"
		id = "f594a946-13b4-5179-9029-a0730634d55f"

	strings:
		$s1 = {43 3a 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 44 65 73 6b 74 6f 70 5c 47 65 74 50 41 49 5c 4f 75 74 5c 49 45 2e 70 64 62}
		$s2 = {53 45 4c 45 43 54 20 65 6e 63 72 79 70 74 65 64 55 73 65 72 6e 61 6d 65 2c 20 65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 2c 20 68 6f 73 74 6e 61 6d 65 2c 68 74 74 70 52 65 61 6c 6d 20 46 52 4f 4d 20 6d 6f 7a 5f 6c 6f 67 69 6e 73}
		$s3 = {53 45 4c 45 43 54 20 4f 52 49 47 49 4e 5f 55 52 4c 2c 55 53 45 52 4e 41 4d 45 5f 56 41 4c 55 45 2c 50 41 53 53 57 4f 52 44 5f 56 41 4c 55 45 20 46 52 4f 4d 20 4c 4f 47 49 4e 53}
		$s4 = {2e 5c 50 41 49 5c 49 45 66 6f 72 58 50 70 61 73 73 77 6f 72 64 73 2e 74 78 74}
		$s5 = {5c 4c 6f 63 61 6c 5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61}
		$s6 = {4f 00 70 00 65 00 72 00 61 00 20 00 6f 00 6c 00 64 00 20 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 20 00 63 00 72 00 65 00 64 00 65 00 6e 00 74 00 69 00 61 00 6c 00 73 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 2000KB and 2 of them ) or ( 4 of them )
}

rule TeleBots_VBS_Backdoor_1 : hardened
{
	meta:
		description = "Detects TeleBots malware - VBS Backdoor"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/4if3HG"
		date = "2016-12-14"
		hash1 = "eb31a918ccc1643d069cf08b7958e2760e8551ba3b88ea9e5d496e07437273b2"
		id = "2b711f66-8ec5-5b9a-a762-7e6668c821c9"

	strings:
		$s1 = {63 6d 64 20 3d 20 22 63 6d 64 2e 65 78 65 20 2f 63 20 22 20 2b 20 61 72 67 20 2b 20 22 20 3e 22 20 2b 20 6f 75 74 66 69 6c 65 20 2b 22 20 32 3e 26 31 22}
		$s2 = {47 65 74 54 65 6d 70 20 3d 20 22 63 3a 5c 57 49 4e 44 4f 57 53 5c 61 64 64 69 6e 73 22}
		$s3 = {65 6c 73 65 69 66 20 28 61 72 67 30 20 3d 20 22 2d 64 75 6d 70 22 29 20 54 68 65 6e}
		$s4 = {64 65 63 6f 64 65 20 3d 20 22 63 65 72 74 75 74 69 6c 20 2d 64 65 63 6f 64 65 20 22 20 2b 20 73 6f 75 72 63 65 20 2b 20 22 20 22 20 2b 20 64 65 73 74 20 20}

	condition:
		( uint16( 0 ) == 0x6553 and filesize < 8KB and 1 of them ) or ( all of them )
}

rule TeleBots_VBS_Backdoor_2 : hardened
{
	meta:
		description = "Detects TeleBots malware - VBS Backdoor"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/4if3HG"
		date = "2016-12-14"
		hash1 = "1b2a5922b58c8060844b43e14dfa5b0c8b119f281f54a46f0f1c34accde71ddb"
		id = "151849af-f1d0-529c-94f2-287312f6515e"

	strings:
		$s1 = {63 6d 64 20 3d 20 22 63 6d 64 2e 65 78 65 20 2f 63 20 22 20 2b 20 61 72 67 20 2b 20 22 20 22 20 2b 20 61 72 67 32}
		$s2 = {44 69 6d 20 57 4d 49 3a 20 20 53 65 74 20 57 4d 49 20 3d 20 47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 5c 5c 2e 5c 72 6f 6f 74 5c 63 69 6d 76 32 22 29}
		$s3 = {63 6d 64 20 3d 20 22 63 65 72 74 75 74 69 6c 20 2d 65 6e 63 6f 64 65 20 2d 66 20 22 20 2b 20 73 6f 75 72 63 65 20 2b 20 22 20 22 20 2b 20 64 65 73 74}

	condition:
		( uint16( 0 ) == 0x6944 and filesize < 30KB and 1 of them ) or ( 2 of them )
}

rule TeleBots_Win64_Spy_KeyLogger_G : hardened
{
	meta:
		description = "Detects TeleBots malware - Win64 Spy KeyLogger G"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/4if3HG"
		date = "2016-12-14"
		hash1 = "e3f134ae88f05463c4707a80f956a689fba7066bb5357f6d45cba312ad0db68e"
		id = "fd16a198-1b28-532b-a1ba-70680469ec51"

	strings:
		$s1 = {43 3a 5c 57 52 4b 5c 47 48 6f 6f 6b 5c 67 48 6f 6f 6b 5c 78 36 34 5c 44 65 62 75 67 5c 67 48 6f 6f 6b 78 36 34 2e 70 64 62}
		$s2 = {49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 20 00 68 00 6f 00 6f 00 6b 00 73 00 20 00 65 00 72 00 72 00 6f 00 72 00 21 00}
		$s4 = {25 00 6c 00 73 00 25 00 64 00 2e 00 7e 00 74 00 6d 00 70 00}
		$s5 = {5b 00 2a 00 5d 00 57 00 69 00 6e 00 64 00 6f 00 77 00 20 00 50 00 49 00 44 00 20 00 3e 00 20 00 25 00 64 00 3a 00 20 00}
		$s6 = {49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 20 00 68 00 6f 00 6f 00 6b 00 73 00 20 00 6f 00 6b 00 21 00}
		$s7 = {5b 00 21 00 5d 00 43 00 6c 00 69 00 70 00 62 00 6f 00 61 00 72 00 64 00 20 00 70 00 61 00 73 00 74 00 65 00}
		$s9 = {5b 00 2a 00 5d 00 20 00 49 00 4d 00 41 00 47 00 45 00 20 00 3a 00 20 00 25 00 6c 00 73 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 600KB and 1 of them ) or ( 3 of them )
}

