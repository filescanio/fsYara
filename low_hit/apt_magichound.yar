rule APT_PupyRAT_PY : hardened
{
	meta:
		description = "Detects Pupy RAT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.secureworks.com/blog/iranian-pupyrat-bites-middle-eastern-organizations"
		date = "2017-02-17"
		hash1 = "8d89f53b0a6558d6bb9cdbc9f218ef699f3c87dd06bc03dd042290dedc18cb71"
		id = "cdd689e3-437e-514d-a058-fad80ce0639e"

	strings:
		$x1 = {72 65 66 6c 65 63 74 69 76 65 5f 69 6e 6a 65 63 74 5f 64 6c 6c}
		$x2 = {49 6d 70 6f 72 74 45 72 72 6f 72 3a 20 70 75 70 79 20 62 75 69 6c 74 69 6e 20 6d 6f 64 75 6c 65 20 6e 6f 74 20 66 6f 75 6e 64 20 21}
		$x3 = {70 6c 65 61 73 65 20 73 74 61 72 74 20 70 75 70 79 20 66 72 6f 6d 20 65 69 74 68 65 72 20 69 74 27 73 20 65 78 65 20 73 74 75 62 20 6f 72 20 69 74 27 73 20 72 65 66 6c 65 63 74 69 76 65 20 44 4c 4c 52 3b}
		$x4 = {5b 49 4e 4a 45 43 54 5d 20 69 6e 6a 65 63 74 5f 64 6c 6c 2e}
		$x5 = {69 6d 70 6f 72 74 20 62 61 73 65 36 34 2c 7a 6c 69 62 3b 65 78 65 63 20 7a 6c 69 62 2e 64 65 63 6f 6d 70 72 65 73 73 28 62 61 73 65 36 34 2e 62 36 34 64 65 63 6f 64 65 28 27 65 4a 7a 7a 63 51 7a 31 63 2f 5a 77 44 62 4a 56 54 38 37 50 79 30 74 4e 4c 6c 48 6e 41 67 41 35 36 77 58 53 27 29 29}
		$op1 = { 8b 42 0c 8b 78 14 89 5c 24 18 89 7c 24 14 3b fd }

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 20000KB and 1 of them ) or ( 2 of them )
}

rule APT_MagicHound_MalMacro : hardened
{
	meta:
		description = "Detects malicious macro / powershell in Office document"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.secureworks.com/blog/iranian-pupyrat-bites-middle-eastern-organizations"
		date = "2017-02-17"
		super_rule = 1
		hash1 = "66d24a529308d8ab7b27ddd43a6c2db84107b831257efb664044ec4437f9487b"
		hash2 = "e5b643cb6ec30d0d0b458e3f2800609f260a5f15c4ac66faf4ebf384f7976df6"
		id = "ad573f52-dbda-5852-ad73-9ef47dd6e7df"

	strings:
		$s1 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20}
		$s2 = {43 6f 6d 6d 61 6e 64 42 75 74 74 6f 6e 31 5f 43 6c 69 63 6b}
		$s3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65}

	condition:
		( uint16( 0 ) == 0xcfd0 and filesize < 8000KB and all of them )
}

