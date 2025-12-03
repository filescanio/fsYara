rule GRIZZLY_STEPPE_Malware_1 : hardened limited
{
	meta:
		description = "Auto-generated rule - file HRDG022184_certclint.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/WVflzO"
		date = "2016-12-29"
		hash1 = "9f918fb741e951a10e68ce6874b839aef5a26d60486db31e509f8dcaa13acec5"
		id = "7239a5f3-9c29-57d7-be95-946d14039353"

	strings:
		$s1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 53 3a 5c 4c 69 64 73 74 6f 6e 65 5c 72 65 6e 65 77 69 6e 67 5c 48 41 5c 64 69 73 61 62 6c 65 5c 49 6e 2e 70 64 62 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s2 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 52 00 65 00 70 00 65 00 61 00 74 00 20 00 6c 00 61 00 73 00 74 00 20 00 66 00 69 00 6e 00 64 00 20 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 29 00 52 00 65 00 70 00 6c 00 61 00 63 00 65 00 20 00 73 00 70 00 65 00 63 00 69 00 66 00 69 00 63 00 20 00 74 00 65 00 78 00 74 00 20 00 77 00 69 00 74 00 68 00 20 00 64 00 69 00 66 00 66 00 65 00 72 00 65 00 6e 00 74 00 20 00 74 00 65 00 78 00 74 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s3 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 6c 00 5c 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 6f 00 72 00 28 00 30 00 29 00 5c 00 25 00 20 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 6f 00 72 00 20 00 54 00 69 00 6d 00 65 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s6 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 53 00 65 00 6c 00 66 00 20 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s7 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 20 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s8 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 53 00 74 00 61 00 72 00 20 00 50 00 6f 00 6c 00 6b 00 2e 00 65 00 78 00 65 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 300KB and 4 of them )
}

rule GRIZZLY_STEPPE_Malware_2 : hardened limited
{
	meta:
		description = "Auto-generated rule"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/WVflzO"
		date = "2016-12-29"
		hash1 = "9acba7e5f972cdd722541a23ff314ea81ac35d5c0c758eb708fb6e2cc4f598a0"
		hash2 = "55058d3427ce932d8efcbe54dccf97c9a8d1e85c767814e34f4b2b6a6b305641"
		id = "37cfba67-af85-5efe-9b07-9f1e5d9f9195"

	strings:
		$x1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 47 6f 6f 67 6c 65 43 72 61 73 68 52 65 70 6f 72 74 2e 64 6c 6c (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 43 72 61 73 68 45 72 72 6f 72 73 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 43 72 61 73 68 53 65 6e 64 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 43 72 61 73 68 41 64 64 44 61 74 61 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s4 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 43 72 61 73 68 43 6c 65 61 6e 75 70 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s5 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 43 72 61 73 68 49 6e 69 74 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 1000KB and $x1 ) or ( all of them )
}

rule PAS_TOOL_PHP_WEB_KIT_mod : hardened
{
	meta:
		description = "Detects PAS Tool PHP Web Kit"
		reference = "https://www.us-cert.gov/security-publications/GRIZZLY-STEPPE-Russian-Malicious-Cyber-Activity"
		author = "US CERT - modified by Florian Roth due to performance reasons"
		date = "2016/12/29"
		id = "6bc75e44-7784-5e48-9bbc-052d84ebee83"

	strings:
		$php = {3c 3f 70 68 70}
		$base64decode1 = {3d 27 62 61 73 65 27 2e 28}
		$strreplace = {73 74 72 5f 72 65 70 6c 61 63 65 28 22 5c 6e 22 2c 20 27 27}
		$md5 = {2e 73 75 62 73 74 72 28 6d 64 35 28 73 74 72 72 65 76 28}
		$gzinflate = {67 7a 69 6e 66 6c 61 74 65}
		$cookie = {5f 43 4f 4f 4b 49 45}
		$isset = {69 73 73 65 74}

	condition:
		uint32( 0 ) == 0x68703f3c and $php at 0 and ( filesize > 10KB and filesize < 30KB ) and #cookie == 2 and #isset == 3 and all of them
}

rule APT_APT29_wellmess_dotnet_unique_strings : hardened
{
	meta:
		description = "Rule to detect WellMess .NET samples based on unique strings and function/variable names"
		author = "NCSC"
		reference = "https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development"
		hash = "2285a264ffab59ab5a1eb4e2b9bcab9baf26750b6c551ee3094af56a4442ac41"
		id = "7a058ec7-f795-5226-b511-ff469a969ee6"

	strings:
		$s1 = {48 00 65 00 61 00 6c 00 74 00 68 00 49 00 6e 00 74 00 65 00 72 00 76 00 61 00 6c 00}
		$s2 = {48 00 65 00 6c 00 6c 00 6f 00 20 00 66 00 72 00 6f 00 6d 00 20 00 50 00 72 00 6f 00 78 00 79 00}
		$s3 = {53 00 74 00 61 00 72 00 74 00 20 00 62 00 6f 00 74 00 3a 00}
		$s4 = {46 72 6f 6d 4e 6f 72 6d 61 6c 54 6f 42 61 73 65 36 34}
		$s5 = {46 72 6f 6d 42 61 73 65 36 34 54 6f 4e 6f 72 6d 61 6c}
		$s6 = {57 65 6c 6c 4d 65 73 73}

	condition:
		uint16( 0 ) == 0x5a4d and uint16( uint16( 0x3c ) ) == 0x4550 and 3 of them
}

rule APT_APT29_sorefang_encryption_key_schedule : hardened
{
	meta:
		description = "Rule to detect SoreFang based on the key schedule used for encryption"
		author = "NCSC"
		reference = "https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development"
		hash = "58d8e65976b53b77645c248bfa18c3b87a6ecfb02f306fe6ba4944db96a5ede2"
		id = "8d89edc1-a9fc-5155-9dc2-8d7f952f90d1"

	strings:
		$ = { C7 05 ?? ?? ?? ?? 63 51 E1 B7 B8 ?? ?? ?? ?? 8B 48 
            FC 81 E9 47 86 C8 61 89 08 83 C0 04 3D ?? ?? ?? ?? 
            7E EB 33 D2 33 C9 B8 2C 00 00 00 89 55 D4 33 F6 89 
            4D D8 33 DB 3B F8 0F 4F C7 8D 04 40 89 45 D0 83 F8 
            01 7C 4F 0F 1F 80 00 00 00 00 }

	condition:
		( uint16( 0 ) == 0x5A4D and uint16( uint32( 0x3c ) ) == 0x4550 ) and any of them
}

rule APT_APT29_sorefang_encryption_key_2b62 : hardened
{
	meta:
		description = "Rule to detect SoreFang based on hardcoded encryption key"
		author = "NCSC"
		reference = "https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development"
		hash = "58d8e65976b53b77645c248bfa18c3b87a6ecfb02f306fe6ba4944db96a5ede2"
		id = "9a7abad7-1cfa-52c8-9416-47cb80486714"

	strings:
		$ = {32 62 36 32 33 33 65 62 33 65 38 37 32 66 66 37 38 39 38 38 66 34 61 38 66 33 66 36 61 33 62 61}

	condition:
		( uint16( 0 ) == 0x5A4D and uint16( uint32( 0x3c ) ) == 0x4550 ) and any of them
}

rule APT_APT29_sorefang_directory_enumeration_output_strings : hardened
{
	meta:
		description = "Rule to detect SoreFang based on formatted string output for directory enumeration"
		author = "NCSC"
		reference = "https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development"
		hash = "58d8e65976b53b77645c248bfa18c3b87a6ecfb02f306fe6ba4944db96a5ede2"
		id = "e24dbda1-3d43-52a7-9249-70a648f4913e"

	strings:
		$ = {2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 41 6c 6c 20 75 73 72 65 73 20 64 69 72 65 63 74 6f 72 79 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d}
		$ = {2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 44 65 73 6b 74 6f 70 20 64 69 72 65 63 74 6f 72 79 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d}
		$ = {2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 44 6f 63 75 6d 65 6e 74 73 20 64 69 72 65 63 74 6f 72 79 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d}

	condition:
		( uint16( 0 ) == 0x5A4D and uint16( uint32( 0x3c ) ) == 0x4550 ) and 2 of them
}

rule APT_APT29_sorefang_command_elem_cookie_ga_boundary_string : hardened
{
	meta:
		description = "Rule to detect SoreFang based on scheduled task element and Cookie header/boundary strings"
		author = "NCSC"
		reference = "https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development"
		hash = "58d8e65976b53b77645c248bfa18c3b87a6ecfb02f306fe6ba4944db96a5ede2"
		id = "3c6ffbad-9b39-5518-aa66-d76531ddb9ea"

	strings:
		$ = {3c 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 3e 00}
		$ = {43 6f 6f 6b 69 65 3a 5f 67 61 3d}
		$ = {2d 2d 2d 2d 2d 2d 39 37 34 37 36 37 32 39 39 38 35 32 34 39 38 39 32 39 35 33 31 36 31 30 35 37 35}

	condition:
		( uint16( 0 ) == 0x5A4D and uint16( uint32( 0x3c ) ) == 0x4550 ) and 2 of them
}

rule APT_APT29_sorefang_encryption_round_function : hardened
{
	meta:
		description = "Rule to detect SoreFang based on the encryption round function"
		author = "NCSC"
		reference = "https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development"
		hash = "58d8e65976b53b77645c248bfa18c3b87a6ecfb02f306fe6ba4944db96a5ede2"
		id = "0be1c084-c8df-5920-a320-90364a7fb542"

	strings:
		$ = { 8A E9 8A FB 8A 5D 0F 02 C9 88 45 0F FE C1 0F BE C5 88 6D F3 8D
            14 45 01 00 00 00 0F AF D0 0F BE C5 0F BE C9 0F AF C8 C1 FA 1B C0 E1 05 0A D1 8B 4D EC 0F BE C1 89 55 E4 8D 14 45 01 00 00 00 0F AF D0 8B C1}

	condition:
		( uint16( 0 ) == 0x5A4D and uint16( uint32( 0x3c ) ) == 0x4550 ) and any of them
}

rule APT_APT29_sorefang_add_random_commas_spaces : hardened
{
	meta:
		description = "Rule to detect SoreFang based on function that adds commas and spaces"
		author = "NCSC"
		reference = "https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development"
		hash = "58d8e65976b53b77645c248bfa18c3b87a6ecfb02f306fe6ba4944db96a5ede2"
		id = "9a89c619-6309-500f-b4dc-c8a3e8fc4417"

	strings:
		$ = { E8 ?? ?? ?? ?? B9 06 00 00 00 99 F7 F9 8B CE 83 FA 04 7E 09 6A
            02 68 ?? ?? ?? ?? EB 07 6A 01 68 }

	condition:
		( uint16( 0 ) == 0x5A4D and uint16( uint32( 0x3c ) ) == 0x4550 ) and any of them
}

rule APT_APT29_sorefang_modify_alphabet_custom_encode : hardened
{
	meta:
		description = "Rule to detect SoreFang based on arguments passed into custom encoding algorithm function"
		author = "NCSC"
		reference = "https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development"
		hash = "58d8e65976b53b77645c248bfa18c3b87a6ecfb02f306fe6ba4944db96a5ede2"
		id = "7c5c1be0-ccad-5c8f-a026-445994b1f279"

	strings:
		$ = { 33 C0 8B CE 6A 36 6A 71 66 89 46 60 88 46 62 89 46 68 66 89 46
            64 }

	condition:
		( uint16( 0 ) == 0x5A4D and uint16( uint32( 0x3c ) ) == 0x4550 ) and any of them
}

rule APT_APT29_sorefang_custom_encode_decode : hardened
{
	meta:
		description = "Rule to detect SoreFang based on the custom encoding/decoding algorithm function"
		author = "NCSC"
		reference = "https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development"
		hash = "58d8e65976b53b77645c248bfa18c3b87a6ecfb02f306fe6ba4944db96a5ede2"
		id = "4885a659-bb3a-5e33-99cc-b827931bf58f"

	strings:
		$ = { 55 8B EC 8B D1 53 56 8B 75 08 8B DE 80 42 62 FA 8A 4A 62 66 D3
            EB 57 3A 5A 5C 74 0F}
		$ = { 3A 5A 5D 74 0A 3A 5A 58 74 05 3A 5A 59 75 05 FE C1 88 4A 62 8A 
            4A 62 B8 01 00 00 00}
		$ = { 8A 46 62 84 C0 74 3E 3C 06 73 12 0F B6 C0 B9 06 00 00 00 2B C8 
            C6 46 62 06 66 D3 66 60 0F B7 4E 60}
		$ = { 80 3C 38 0D 0F 84 93 01 00 00 C6 42 62 06 8B 56 14 83 FA 10 72 
            04 8B 06}
		$ = { 0F BE 0C 38 8B 45 EC 0F B6 40 5B 3B C8 75 07 8B 55 EC B3 3E}
		$ = { 0F BE 0C 38 8B 45 EC 0F B6 40 5E 3B C8 75 0B 8B 55 EC D0 EB C6 
            42 62 05}
		$ = { 8B 55 EC 0F BE 04 38 0F B6 DB 0F B6 4A 5F 3B C1 B8 3F 00 00 00 
            0F 44 D8}
		$ = { 8A 4A 62 66 8B 52 60 66 D3 E2 0F B6 C3 66 0B D0 8B 45 EC 66 89 
            50 60 8A 45 F3 02 C1 88 45 F3 3C 08 72 2E 04 F8 8A C8 88 45 F3 
            66 D3 EA 8B 4D 08 0F B6 C2 50 }
		$ = { 3A 5A 5C 74 0F 3A 5A 5D 74 0A 3A 5A 58 74 05 3A 5A 59 75 05 FE 
            C1 88 4A 62 }

	condition:
		( uint16( 0 ) == 0x5A4D and uint16( uint32( 0x3c ) ) == 0x4550 ) and any of them
}

rule APT_APT29_sorefang_remove_chars_comma_space_dot : hardened
{
	meta:
		description = "Rule to detect SoreFang based on function that removes commas, spaces and dots"
		author = "NCSC"
		reference = "https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development"
		hash = "58d8e65976b53b77645c248bfa18c3b87a6ecfb02f306fe6ba4944db96a5ede2"
		id = "c15779b0-6a5e-5345-94ad-95615b567f1f"

	strings:
		$ = {8A 18 80 FB 2C 74 03 88 19 41 42 40 3B D6 75 F0 8B 5D 08}
		$ = {8A 18 80 FB 2E 74 03 88 19 41 42 40 3B D6 75 F0 8B 5D 08}
		$ = {8A 18 80 FB 20 74 03 88 19 41 42 40 3B D6 75 F0 8B 5D 08}

	condition:
		( uint16( 0 ) == 0x5A4D and uint16( uint32( 0x3c ) ) == 0x4550 ) and all of them
}

rule APT_APT29_sorefang_disk_enumeration_strings : hardened
{
	meta:
		description = "Rule to detect SoreFang based on disk enumeration strings"
		author = "NCSC"
		reference = "https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development"
		hash = "a4b790ddffb3d2e6691dcacae08fb0bfa1ae56b6c73d70688b097ffa831af064"
		id = "0ff01793-6fb7-5cff-b4e4-6709269ab0f0"

	strings:
		$ = {0d 0a 46 72 65 65 20 6f 6e 20 64 69 73 6b 3a 20}
		$ = {54 6f 74 61 6c 20 64 69 73 6b 3a 20}
		$ = {45 72 72 6f 72 20 69 6e 20 47 65 74 44 69 73 6b 46 72 65 65 53 70 61 63 65 45 78 0d 0a}
		$ = {0d 0a 56 6f 6c 75 6d 65 20 6c 61 62 65 6c 3a 20}
		$ = {53 65 72 69 61 6c 20 6e 75 6d 62 65 72 3a 20}
		$ = {46 69 6c 65 20 73 79 73 74 65 6d 3a 20}
		$ = {45 72 72 6f 72 20 69 6e 20 47 65 74 56 6f 6c 75 6d 65 49 6e 66 6f 72 6d 61 74 69 6f 6e 0d 0a}
		$ = {49 20 63 61 6e 20 6e 6f 74 20 68 65 74 20 69 6e 66 6f 72 6d 61 74 69 6f 6e 20 61 62 6f 75 74 20 74 68 69 73 20 64 69 73 6b 0d 0a}

	condition:
		( uint16( 0 ) == 0x5A4D and uint16( uint32( 0x3c ) ) == 0x4550 ) and all of them
}

