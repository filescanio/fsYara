rule ZxShell_Related_Malware_CN_Group_Jul17_1 : hardened
{
	meta:
		description = "Detects a ZxShell related sample from a CN threat group"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blogs.rsa.com/cat-phishing/"
		date = "2017-07-08"
		hash1 = "ef56c2609bc1b90f3e04745890235e6052a4be94e35e38b6f69b64fb17a7064e"
		id = "a91e39bb-1bb3-54a8-b684-d673c445375c"
		score = 75

	strings:
		$x1 = {43 4d 44 2e 45 58 45 20 2f 43 20 4e 45 54 20 55 53 45 52 20 47 55 45 53 54 20 2f 41 43 54 49 56 45 3a 79 65 73 20 26 26 20 4e 45 54 20 55 53 45 52 20 47 55 45 53 54 20 2b 2b 2b 2b 2b 2b}
		$x2 = {73 79 73 74 65 6d 5c 63 55 52 52 45 4e 54 63 4f 4e 54 52 4f 4c 53 45 54 5c 73 45 52 56 49 43 45 53 5c 74 45 52 4d 53 45 52 56 49 43 45}
		$x3 = {5c 73 65 63 69 76 72 65 53 5c 74 65 53 6c 6f 72 74 6e 6f 43 74 6e 65 72 72 75 43 5c 4d 45 54 53 59 53}
		$x4 = {73 79 73 74 65 6d 5c 63 55 52 52 45 4e 54 43 4f 4e 54 52 4f 4c 53 45 54 5c 63 4f 4e 54 52 4f 4c 5c 74 45 52 4d 49 4e 41 4c 20 73 45 52 56 45 52}
		$x5 = {73 4f 46 54 57 41 52 45 5c 6d 49 43 52 4f 53 4f 46 54 5c 69 4e 54 45 52 4e 45 54 20 65 58 50 4c 4f 52 45 52 5c 6d 41 49 4e}
		$x6 = {65 4e 41 42 4c 45 61 44 4d 49 4e 74 73 52 45 4d 4f 54 45}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 400KB and 1 of them )
}

rule ZxShell_Related_Malware_CN_Group_Jul17_2 : hardened
{
	meta:
		description = "Detects a ZxShell related sample from a CN threat group"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blogs.rsa.com/cat-phishing/"
		date = "2017-07-08"
		hash1 = "204273675526649b7243ee48efbb7e2bc05239f7f9015fbc4fb65f0ada64759e"
		id = "37c1f26b-4b4f-510e-a7b7-b2afb17d6e71"

	strings:
		$u1 = {55 73 65 72 2d 41 67 65 6e 74 3a 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 25 64 2e 30 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 25 64 2e 30 3b 20 4d 79 49 45 20 33 2e 30 31 29}
		$u2 = {55 73 65 72 2d 41 67 65 6e 74 3a 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 25 64 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 25 64 2e 31 3b 20 53 56 31 29}
		$u3 = {55 73 65 72 2d 41 67 65 6e 74 3a 4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 58 31 31 3b 20 55 3b 20 4c 69 6e 75 78 20 69 36 38 36 3b 20 65 6e 2d 55 53 3b 20 72 65 3a 31 2e 34 2e 30 29 20 47 65 63 6b 6f 2f 32 30 30 38 30 38 30 38 20 46 69 72 65 66 6f 78 2f 25 64 2e 30}
		$u4 = {55 73 65 72 2d 41 67 65 6e 74 3a 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 36 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 31 3b 20 53 56 31 29}
		$x1 = {5c 5c 25 73 5c 61 64 6d 69 6e 24 5c 67 31 66 64 2e 65 78 65}
		$x2 = {43 3a 5c 67 31 66 64 2e 65 78 65}
		$x3 = {5c 5c 25 73 5c 43 24 5c 4e 65 77 41 72 65 61 6e 2e 65 78 65}
		$s0 = {61 74 20 5c 5c 25 73 20 25 64 3a 25 64 20 25 73}
		$s1 = {25 63 25 63 25 63 25 63 25 63 63 6e 2e 65 78 65}
		$s2 = {68 72 61 25 75 2e 64 6c 6c}
		$s3 = {52 65 66 65 72 65 72 3a 20 68 74 74 70 3a 2f 2f 25 73 3a 38 30 2f 68 74 74 70 3a 2f 2f 25 73}
		$s5 = {41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 20 7a 68 2d 63 6e}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 100KB and ( 1 of ( $x* ) or 3 of them )
}

rule ZxShell_Related_Malware_CN_Group_Jul17_3 : hardened
{
	meta:
		description = "Detects a ZxShell related sample from a CN threat group"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blogs.rsa.com/cat-phishing/"
		date = "2017-07-08"
		hash1 = "2e5cf8c785dc081e5c2b43a4a785713c0ae032c5f86ccbc7abf5c109b8854ed7"
		id = "1900b861-b4a2-50b5-a639-3eb442072139"

	strings:
		$s1 = {25 73 5c 6e 74 25 73 2e 64 6c 6c}
		$s2 = {52 65 67 51 75 65 72 79 56 61 6c 75 65 45 78 28 53 76 63 68 6f 73 74 5c 6e 65 74 73 76 63 73 29}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 600KB and all of them )
}

rule ZxShell_Jul17 : hardened
{
	meta:
		description = "Detects a ZxShell - CN threat group"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blogs.rsa.com/cat-phishing/"
		date = "2017-07-08"
		hash1 = "5d2a4cde9fa7c2fdbf39b2e2ffd23378d0c50701a3095d1e91e3cf922d7b0b16"
		id = "1b009b20-5a19-5cac-aaaf-ca61310eab9f"
		score = 80

	strings:
		$x1 = {7a 78 70 6c 75 67 20 2d 61 64 64}
		$x2 = {67 65 74 78 78 78 20 63 3a 5c 78 79 7a 2e 64 6c 6c}
		$x3 = {64 6f 77 6e 66 69 6c 65 20 2d 64 20 63 3a 5c 77 69 6e 64 6f 77 73 5c 75 70 64 61 74 65 2e 65 78 65}
		$x4 = {2d 66 72 6f 6d 75 72 6c 20 68 74 74 70 3a 2f 2f 78 2e 78 2e 78 2f 78 2e 64 6c 6c}
		$x5 = {70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 2d 6e 20 37 26 63 6d 64 2e 65 78 65 20 2f 63 20 6e 65 74 20 73 74 61 72 74 20 25 73}
		$x6 = {5a 58 4e 43 20 2d 65 20 63 6d 64 2e 65 78 65 20 78 2e 78 2e 78 2e 78}
		$x7 = {28 62 69 6e 64 20 61 20 63 6d 64 73 68 65 6c 6c 29}
		$x8 = {5a 58 46 74 70 53 65 72 76 65 72 20 32 31 20 32 30 20 7a 78}
		$x9 = {5a 58 48 74 74 70 53 65 72 76 65 72}
		$x10 = {63 3a 5c 65 72 72 6f 72 2e 68 74 6d 2c 2e 65 78 65 7c 63 3a 5c 61 2e 65 78 65 2c 2e 7a 69 70 7c 63 3a 5c 62 2e 7a 69 70 22}
		$x11 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 63 6c 69 70 62 6f 61 72 64 6c 6f 67 2e 74 78 74}
		$x12 = {41 6e 74 69 53 6e 69 66 66 20 2d 61 20 77 69 72 65 73 68 61 72 6b 2e 65 78 65}
		$x13 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 6b 65 79 6c 6f 67 2e 74 78 74}

	condition:
		( filesize < 10000KB and 1 of them ) or 3 of them
}

import "pe"

rule ZXshell_20171211_chrsben : hardened
{
	meta:
		description = "Detects ZxShell variant surfaced in Dec 17"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/snc85M"
		date = "2017-12-11"
		hash1 = "dd01e7a1c9b20d36ea2d961737780f2c0d56005c370e50247e38c5ca80dcaa4f"
		id = "3bbfddb8-011a-52dd-b0c8-b35e6f740507"

	strings:
		$x1 = {6e 63 50 72 6f 78 79 58 6c 6c}
		$s1 = {55 6e 69 73 63 72 69 62 65 2e 64 6c 6c}
		$s2 = {47 65 74 4d 6f 64 75 6c 65 46 69 6c 65 4e 61 6d 65 44 6c 6c}
		$s4 = {24 48 61 6e 67 7a 68 6f 75 20 53 68 75 6e 77 61 6e 67 20 54 65 63 68 6e 6f 6c 6f 67 79 20 43 6f 2e 2c 4c 74 64 30}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 2000KB and ( pe.imphash ( ) == "de481441d675e9aca4f20bd8e16a5faa" or pe.exports ( "PerfectWorld" ) or pe.exports ( "ncProxyXll" ) or 1 of ( $x* ) or 2 of them )
}

