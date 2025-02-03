import "pe"

rule Unspecified_Malware_Sep1_A1 : hardened
{
	meta:
		description = "Detects malware from DrqgonFly APT report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.symantec.com/connect/blogs/dragonfly-western-energy-sector-targeted-sophisticated-attack-group"
		date = "2017-09-12"
		hash1 = "28143c7638f22342bff8edcd0bedd708e265948a5fcca750c302e2dca95ed9f0"
		id = "cff49e85-c8c3-5240-9948-0551e38e7040"

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 200KB and pe.imphash ( ) == "17a4bd9c95f2898add97f309fc6f9bcd" )
}

rule DragonFly_APT_Sep17_1 : hardened
{
	meta:
		description = "Detects malware from DrqgonFly APT report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.symantec.com/connect/blogs/dragonfly-western-energy-sector-targeted-sophisticated-attack-group"
		date = "2017-09-12"
		hash1 = "fc54d8afd2ce5cb6cc53c46783bf91d0dd19de604308d536827320826bc36ed9"
		id = "d219a54e-cb76-5c56-b64c-5019e811eeb1"

	strings:
		$s1 = {5c 00 55 00 70 00 64 00 61 00 74 00 65 00 5c 00 54 00 65 00 6d 00 70 00 5c 00 75 00 66 00 69 00 6c 00 65 00 73 00 2e 00 74 00 78 00 74 00}
		$s2 = {25 00 30 00 32 00 64 00 2e 00 25 00 30 00 32 00 64 00 2e 00 25 00 30 00 34 00 64 00 20 00 25 00 30 00 32 00 64 00 3a 00 25 00 30 00 32 00 64 00}
		$s3 = {2a 00 70 00 61 00 73 00 73 00 2a 00 2e 00 2a 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 100KB and all of them )
}

rule DragonFly_APT_Sep17_2 : hardened
{
	meta:
		description = "Detects malware from DrqgonFly APT report"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.symantec.com/connect/blogs/dragonfly-western-energy-sector-targeted-sophisticated-attack-group"
		date = "2017-09-12"
		modified = "2023-01-06"
		hash1 = "178348c14324bc0a3e57559a01a6ae6aa0cb4013aabbe324b51f906dcf5d537e"
		id = "e64f121d-a628-54b5-88f3-96eea388c155"

	strings:
		$s1 = {5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 52 00 6f 00 61 00 6d 00 69 00 6e 00 67 00 5c 00 4f 00 70 00 65 00 72 00 61 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4f 00 70 00 65 00 72 00 61 00 20 00 53 00 74 00 61 00 62 00 6c 00 65 00 5c 00 4c 00 6f 00 67 00 69 00 6e 00 20 00 44 00 61 00 74 00 61 00}
		$s2 = {43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 50 00 75 00 62 00 6c 00 69 00 63 00 5c 00 4c 00 6f 00 67 00 2e 00 74 00 78 00 74 00}
		$s3 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 68 00 6f 00 73 00 74 00 6e 00 61 00 6d 00 65 00 2c 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 55 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 2c 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 20 00 46 00 52 00 4f 00 4d 00 20 00 6d 00 6f 00 7a 00 5f 00 6c 00 6f 00 67 00 69 00 6e 00 73 00}
		$s4 = {2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 20 00 4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 20 00 46 00 69 00 72 00 65 00 66 00 6f 00 78 00 20 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00}
		$s5 = {2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 20 00 4f 00 70 00 65 00 72 00 61 00 20 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00}
		$s6 = {5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 43 00 72 00 65 00 64 00 65 00 6e 00 74 00 69 00 61 00 6c 00 73 00 5c 00}
		$s7 = {5c 00 41 00 70 00 70 00 64 00 61 00 74 00 61 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 5c 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 5c 00 43 00 68 00 72 00 6f 00 6d 00 65 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5c 00}
		$s8 = {2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 20 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 20 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 3000KB and 3 of them )
}

import "pe"

rule DragonFly_APT_Sep17_3 : hardened
{
	meta:
		description = "Detects malware from DrqgonFly APT report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.symantec.com/connect/blogs/dragonfly-western-energy-sector-targeted-sophisticated-attack-group"
		date = "2017-09-12"
		hash1 = "b051a5997267a5d7fa8316005124f3506574807ab2b25b037086e2e971564291"
		id = "4eafd732-80bc-5f50-bf0d-096df4d35d61"

	strings:
		$s1 = {6b 65 72 6e 65 6c 36 34 2e 64 6c 6c}
		$s2 = {77 73 32 5f 33 32 2e 64 51 48}
		$s3 = {48 47 46 45 44 43 42 41 44 43 42 41}
		$s4 = {41 57 41 56 41 55 41 54 57 56 53 55}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 40KB and ( pe.imphash ( ) == "6f03fb864ff388bac8680ac5303584be" or all of them ) )
}

rule DragonFly_APT_Sep17_4 : hardened
{
	meta:
		description = "Detects malware from DrqgonFly APT report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.symantec.com/connect/blogs/dragonfly-western-energy-sector-targeted-sophisticated-attack-group"
		date = "2017-09-12"
		hash1 = "2f159b71183a69928ba8f26b76772ec504aefeac71021b012bd006162e133731"
		id = "dbc0eebf-fc81-5a0b-b2e0-129d0b40b6f7"

	strings:
		$s1 = {73 00 63 00 72 00 65 00 65 00 6e 00 2e 00 65 00 78 00 65 00}
		$s2 = {50 6c 61 74 66 6f 72 6d 49 6e 76 6f 6b 65 55 53 45 52 33 32}
		$s3 = {47 65 74 44 65 73 6b 74 6f 70 49 6d 61 67 65 46}
		$s4 = {50 6c 61 74 66 6f 72 6d 49 6e 76 6f 6b 65 47 44 49 33 32}
		$s5 = {47 65 74 44 65 73 6b 74 6f 70 49 6d 61 67 65}
		$s6 = {54 00 6f 00 6f 00 20 00 6d 00 61 00 6e 00 79 00 20 00 61 00 72 00 67 00 75 00 6d 00 65 00 6e 00 74 00 73 00 2c 00 20 00 67 00 6f 00 69 00 6e 00 67 00 20 00 74 00 6f 00 20 00 73 00 74 00 6f 00 72 00 65 00 20 00 69 00 6e 00 20 00 63 00 75 00 72 00 72 00 65 00 6e 00 74 00 20 00 64 00 69 00 72 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 60KB and all of them )
}

