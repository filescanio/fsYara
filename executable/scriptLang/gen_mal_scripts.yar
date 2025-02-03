rule PS_AMSI_Bypass : FILE hardened limited
{
	meta:
		description = "Detects PowerShell AMSI Bypass"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://gist.github.com/mattifestation/46d6a2ebb4a1f4f0e7229503dc012ef1"
		date = "2017-07-19"
		score = 65

	strings:
		$s1 = {2e 47 65 74 46 69 65 6c 64 28 27 61 6d 73 69 43 6f 6e 74 65 78 74 27 2c 5b 52 65 66 6c 65 63 74 69 6f 6e 2e 42 69 6e 64 69 6e 67 46 6c 61 67 73 5d 27 4e 6f 6e 50 75 62 6c 69 63 2c 53 74 61 74 69 63 27 29 2e}

	condition:
		1 of them
}

rule JS_Suspicious_Obfuscation_Dropbox : hardened
{
	meta:
		description = "Detects PowerShell AMSI Bypass"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/ItsReallyNick/status/887705105239343104"
		date = "2017-07-19"
		score = 70

	strings:
		$x1 = {6a 22 2b 22 61 22 2b 22 76 22 2b 22 61 22 2b 22 73 22 2b 22 63 22 2b 22 72 22 2b 22 69 22 2b 22 70 22 2b 22 74 22}
		$x2 = {73 63 72 69 70 74 3a 68 74 74 70 73 3a 2f 2f 77 77 77 2e 64 72 6f 70 62 6f 78 2e 63 6f 6d}

	condition:
		2 of them
}

rule JS_Suspicious_MSHTA_Bypass : hardened limited
{
	meta:
		description = "Detects MSHTA Bypass"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/ItsReallyNick/status/887705105239343104"
		date = "2017-07-19"
		score = 70

	strings:
		$s1 = {6d 73 68 74 6d 6c 2c 52 75 6e 48 54 4d 4c 41 70 70 6c 69 63 61 74 69 6f 6e}
		$s2 = {6e 65 77 20 41 63 74 69 76 65 58 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e 28}
		$s3 = {2f 63 20 73 74 61 72 74 20 6d 73 68 74 61 20 6a}

	condition:
		2 of them
}

rule JavaScript_Run_Suspicious : hardened
{
	meta:
		description = "Detects a suspicious Javascript Run command"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/craiu/status/900314063560998912"
		score = 60
		date = "2017-08-23"

	strings:
		$s1 = {77 20 3d 20 6e 65 77 20 41 63 74 69 76 65 58 4f 62 6a 65 63 74 28}
		$s2 = {20 77 2e 52 75 6e 28 72 29 3b}

	condition:
		all of them
}

private rule MSI : hardened
{
	strings:
		$r1 = { 52 00 6F 00 6F 00 74 00 20 00 45 00 6E 00 74 00 72 00 79 }

	condition:
		uint16( 0 ) == 0xCFD0 and $r1
}

rule Certutil_Decode_OR_Download : score hardened
{
	meta:
		description = "Certutil Decode"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		score = 65
		date = "2017-08-29"

	strings:
		$a1 = {((63 65 72 74 75 74 69 6c 20 2d 64 65 63 6f 64 65 20) | (63 00 65 00 72 00 74 00 75 00 74 00 69 00 6c 00 20 00 2d 00 64 00 65 00 63 00 6f 00 64 00 65 00 20 00))}
		$a2 = {((63 65 72 74 75 74 69 6c 20 20 2d 64 65 63 6f 64 65 20) | (63 00 65 00 72 00 74 00 75 00 74 00 69 00 6c 00 20 00 20 00 2d 00 64 00 65 00 63 00 6f 00 64 00 65 00 20 00))}
		$a3 = {((63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 64 65 63 6f 64 65 20) | (63 00 65 00 72 00 74 00 75 00 74 00 69 00 6c 00 2e 00 65 00 78 00 65 00 20 00 2d 00 64 00 65 00 63 00 6f 00 64 00 65 00 20 00))}
		$a4 = {((63 65 72 74 75 74 69 6c 2e 65 78 65 20 20 2d 64 65 63 6f 64 65 20) | (63 00 65 00 72 00 74 00 75 00 74 00 69 00 6c 00 2e 00 65 00 78 00 65 00 20 00 20 00 2d 00 64 00 65 00 63 00 6f 00 64 00 65 00 20 00))}
		$a5 = {((63 65 72 74 75 74 69 6c 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 68 74 74 70) | (63 00 65 00 72 00 74 00 75 00 74 00 69 00 6c 00 20 00 2d 00 75 00 72 00 6c 00 63 00 61 00 63 00 68 00 65 00 20 00 2d 00 73 00 70 00 6c 00 69 00 74 00 20 00 2d 00 66 00 20 00 68 00 74 00 74 00 70 00))}
		$a6 = {((63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 68 74 74 70) | (63 00 65 00 72 00 74 00 75 00 74 00 69 00 6c 00 2e 00 65 00 78 00 65 00 20 00 2d 00 75 00 72 00 6c 00 63 00 61 00 63 00 68 00 65 00 20 00 2d 00 73 00 70 00 6c 00 69 00 74 00 20 00 2d 00 66 00 20 00 68 00 74 00 74 00 70 00))}

	condition:
		( not MSI and filesize < 700KB and 1 of them )
}

rule Suspicious_JS_script_content : hardened
{
	meta:
		description = "Detects suspicious statements in JavaScript files"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research on Leviathan https://goo.gl/MZ7dRg"
		date = "2017-12-02"
		score = 70
		hash1 = "fc0fad39b461eb1cfc6be57932993fcea94fca650564271d1b74dd850c81602f"

	strings:
		$x1 = {6e 65 77 20 41 63 74 69 76 65 58 4f 62 6a 65 63 74 28 27 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 27 29 29 2e 52 75 6e 28 27 63 6d 64 20 2f 63 20}
		$x2 = {2e 52 75 6e 28 27 72 65 67 73 76 72 33 32 20 2f 73 20 2f 75 20 2f 69 3a}
		$x3 = {6e 65 77 20 41 63 74 69 76 65 58 4f 62 6a 65 63 74 28 27 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 27 29 29 2e 52 75 6e 28 27 72 65 67 73 76 72 33 32 20 2f 73}
		$x4 = {61 72 67 73 3d 27 2f 73 20 2f 75 20 2f 69 3a}

	condition:
		( filesize < 10KB and 1 of them )
}

rule Universal_Exploit_Strings : hardened
{
	meta:
		description = "Detects a group of strings often used in exploit codes"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "not set"
		date = "2017-12-02"
		score = 50
		hash1 = "9b07dacf8a45218ede6d64327c38478640ff17d0f1e525bd392c002e49fe3629"

	strings:
		$s1 = {45 78 70 6c 6f 69 74}
		$s2 = {50 61 79 6c 6f 61 64}
		$s3 = {43 56 45 2d 32 30 31}
		$s4 = {62 69 6e 64 73 68 65 6c 6c}

	condition:
		( filesize < 2KB and 3 of them )
}

rule VBS_Obfuscated_Mal_Feb18_1 : hardened
{
	meta:
		description = "Detects malicious obfuscated VBS observed in February 2018"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/zPsn83"
		date = "2018-02-12"
		hash1 = "06960cb721609fe5a857fe9ca3696a84baba88d06c20920370ddba1b0952a8ab"
		hash2 = "c5c0e28093e133d03c3806da0061a35776eed47d351e817709d2235b95d3a036"
		hash3 = "e1765a2b10e2ff10235762b9c65e9f5a4b3b47d292933f1a710e241fe0417a74"
		score = 50

	strings:
		$x1 = {41 28 20 41 72 72 61 79 28 20 28 31 2a 20 32 5e 31 20 29 2b}
		$x2 = {2e 61 64 64 63 6f 64 65 28 41 28 20 41 72 72 61 79 28}
		$x3 = {66 61 6c 73 65 3a 41 41 2e 73 65 6e 64 3a 45 78 65 63 75 74 65 28 41 41 2e 72 65 73 70 6f 6e 73 65 74 65 78 74 29 3a 65 6e 64}
		$x4 = {26 20 41 28 20 41 72 72 61 79 28 20 20 28 31 2a 20 32 5e 31 20 29 2b}
		$s1 = {2e 53 59 53 54 45 4d 54 59 50 45 3a 4e 45 58 54 3a 49 46 20 28 55 43 41 53 45 28}
		$s2 = {41 20 3d 20 53 54 52 3a 6e 65 78 74 3a 65 6e 64 20 66 75 6e 63 74 69 6f 6e}
		$s3 = {26 57 53 43 52 49 50 54 2e 53 43 52 49 50 54 46 55 4c 4c 4e 41 4d 45 26 43 48 52}

	condition:
		filesize < 600KB and ( 1 of ( $x* ) or 3 of them )
}

