rule CN_disclosed_20180208_lsls : hardened
{
	meta:
		description = "Detects malware from disclosed CN malware set"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/cyberintproject/status/961714165550342146"
		date = "2018-02-08"
		score = 45
		hash1 = "94c6a92984df9ed255f4c644261b01c4e255acbe32ddfd0debe38b558f29a6c9"
		id = "c6c4aa72-1a84-552f-bea0-38b332a74233"

	strings:
		$x1 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 31 30 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 36 2e 31 3b 20 57 4f 57 36 34 3b 20 54 72 69 64 65 6e 74 2f 36 2e 30 29}

	condition:
		uint16( 0 ) == 0x457f and filesize < 3000KB and $x1
}

rule CN_disclosed_20180208_c : hardened
{
	meta:
		description = "Detects malware from disclosed CN malware set"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/cyberintproject/status/961714165550342146"
		date = "2018-02-08"
		hash1 = "17475d25d40c877284e73890a9dd55fccedc6a5a071c351a8c342c8ef7f9cea7"
		id = "cb0bcdc4-7eca-59b7-a947-85c232d4e599"

	strings:
		$x1 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 70 00 69 00 6e 00 67 00 20 00 30 00 20 00 2d 00 6e 00 20 00 32 00 20 00 26 00 20 00 64 00 65 00 6c 00 20 00 22 00}
		$x2 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 20 00 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 73 00 63 00 20 00 6d 00 69 00 6e 00 75 00 74 00 65 00 20 00 2f 00 6d 00 6f 00 20 00 31 00 20 00 2f 00 74 00 6e 00 20 00 53 00 65 00 72 00 76 00 65 00 72 00 20 00 2f 00 74 00 72 00 20 00}
		$x3 = {77 00 77 00 77 00 2e 00 75 00 70 00 6c 00 6f 00 61 00 64 00 2e 00 65 00 65 00 2f 00 69 00 6d 00 61 00 67 00 65 00 2f 00}
		$s1 = {77 00 69 00 6e 00 6d 00 67 00 6d 00 74 00 73 00 3a 00 5c 00 5c 00 2e 00 5c 00 72 00 6f 00 6f 00 74 00 5c 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 43 00 65 00 6e 00 74 00 65 00 72 00 32 00}
		$s2 = {2f 00 53 00 65 00 72 00 76 00 65 00 72 00 2e 00 65 00 78 00 65 00}
		$s3 = {45 00 78 00 65 00 63 00 75 00 74 00 65 00 64 00 20 00 41 00 73 00 20 00}
		$s4 = {57 00 6d 00 69 00 50 00 72 00 76 00 53 00 45 00 2e 00 65 00 78 00 65 00}
		$s5 = {53 74 75 62 2e 65 78 65}
		$s6 = {44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 20 00 45 00 52 00 52 00 4f 00 52 00}
		$s7 = {73 00 68 00 75 00 74 00 64 00 6f 00 77 00 6e 00 20 00 2d 00 72 00 20 00 2d 00 74 00 20 00 30 00 30 00}
		$s8 = {53 00 65 00 6c 00 65 00 63 00 74 00 20 00 2a 00 20 00 46 00 72 00 6f 00 6d 00 20 00 41 00 6e 00 74 00 69 00 56 00 69 00 72 00 75 00 73 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 100KB and ( 1 of ( $x* ) or 4 of them )
}

rule CN_disclosed_20180208_System3 : hardened
{
	meta:
		description = "Detects malware from disclosed CN malware set"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/cyberintproject/status/961714165550342146"
		date = "2018-02-08"
		hash1 = "73fa84cff51d384c2d22d9e53fc5d42cb642172447b07e796c81dd403fb010c2"
		id = "097f4506-295d-5066-8895-2148436731c1"

	strings:
		$a1 = {57 00 6d 00 69 00 50 00 72 00 76 00 53 00 45 00 2e 00 65 00 78 00 65 00}
		$s1 = {43 3a 5c 55 73 65 72 73 5c 73 67 6c 5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c}
		$s2 = {54 65 6d 70 6f 72 61 72 79 20 50 72 6f 6a 65 63 74 73 5c 57 6d 69 50 72 76 53 45 5c}
		$s3 = {24 31 35 61 33 32 61 35 64 2d 34 39 30 36 2d 34 35 38 61 2d 38 66 35 37 2d 34 30 32 33 31 31 61 66 63 31 63 31}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 200KB and $a1 and 1 of ( $s* )
}

import "pe"

rule CN_disclosed_20180208_Mal1 : hardened
{
	meta:
		description = "Detects malware from disclosed CN malware set"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.virustotal.com/graph/#/selected/n120z79z208z189/drawer/graph-details"
		date = "2018-02-08"
		hash1 = "173d69164a6df5bced94ab7016435c128ccf7156145f5d26ca59652ef5dcd24e"
		id = "8516bbfb-a2ad-565d-bf6c-71629b1831a1"

	strings:
		$x1 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 74 65 72 6d 73 72 76 68 61 63 6b 2e 64 6c 6c}
		$x2 = {55 73 65 72 2d 41 67 65 6e 74 3a 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 36 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 31 3b 20 53 56 31 29}
		$a1 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 63 6d 64 2e 65 78 65}
		$a2 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 6d 73 74 73 63 2e 65 78 65}
		$a3 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 74 61 73 6b 6d 67 72 2e 65 78 65}
		$a4 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 72 65 67 65 64 69 74 2e 65 78 65}
		$a5 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 6d 6d 63 2e 65 78 65}
		$s1 = {4b 37 54 53 65 63 75 72 69 74 79 2e 65 78 65}
		$s2 = {53 65 72 76 55 44 61 65 6d 6f 6e 2e 65 78 65}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 2000KB and ( pe.imphash ( ) == "28e3a58132364197d7cb29ee104004bf" or 1 of ( $x* ) or 3 of them )
}

rule CN_disclosed_20180208_KeyLogger_1 : hardened
{
	meta:
		description = "Detects malware from disclosed CN malware set"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.virustotal.com/graph/#/selected/n120z79z208z189/drawer/graph-details"
		date = "2018-02-08"
		hash1 = "c492889e1d271a98e15264acbb21bfca9795466882520d55dc714c4899ed2fcf"
		id = "12eff9b6-1a65-5efc-b39c-88297bdae9c3"

	strings:
		$x2 = {50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 61 00 6c 00 72 00 65 00 61 00 64 00 79 00 20 00 65 00 6c 00 65 00 76 00 61 00 74 00 65 00 64 00 2e 00}
		$x3 = {47 65 74 4b 65 79 6c 6f 67 67 45 72 4c 6f 67 73 52 65 73 70 6f 6e 73 65}
		$x4 = {67 65 74 5f 65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64}
		$x5 = {44 6f 44 6f 77 6e 6c 6f 61 64 41 6e 64 45 78 65 63 75 74 65}
		$x6 = {47 65 74 4b 65 79 6c 6f 67 67 65 52 4c 6f 67 73}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1000KB and 2 of them
}

import "pe"

rule CN_disclosed_20180208_Mal4 : hardened
{
	meta:
		description = "Detects malware from disclosed CN malware set"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.virustotal.com/graph/#/selected/n120z79z208z189/drawer/graph-details"
		date = "2018-02-08"
		hash1 = "f7549c74f09be7e4dbfb64006e535b9f6d17352e236edc2cdb102ec3035cf66e"
		id = "6165caf5-157f-5381-a77e-6ed775187ab1"

	strings:
		$s1 = {4d 69 63 72 6f 73 6f 66 74 20 2e 4e 65 74 20 46 72 61 6d 65 77 6f 72 6b 20 43 4f 4d 2b 20 53 75 70 70 6f 72 74}
		$s2 = {4d 69 63 72 6f 73 6f 66 74 20 2e 4e 45 54 20 61 6e 64 20 57 69 6e 64 6f 77 73 20 58 50 20 43 4f 4d 2b 20 49 6e 74 65 67 72 61 74 69 6f 6e 20 77 69 74 68 20 53 4f 41 50}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 3000KB and 1 of them and pe.exports ( "SPACE" )
}

rule CN_disclosed_20180208_Mal5 : hardened
{
	meta:
		description = "Detects malware from disclosed CN malware set"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.virustotal.com/graph/#/selected/n120z79z208z189/drawer/graph-details"
		date = "2018-02-08"
		hash1 = "24c05cd8a1175fbd9aca315ec67fb621448d96bd186e8d5e98cb4f3a19482af4"
		hash2 = "05696db46144dab3355dcefe0408f906a6d43fced04cb68334df31c6dfd12720"
		id = "b1933610-9e6d-5eed-ba30-ccdd0d3a6124"

	strings:
		$s1 = {34 53 79 73 74 65 6d 2e 57 65 62 2e 53 65 72 76 69 63 65 73 2e 50 72 6f 74 6f 63 6f 6c 73 2e 53 6f 61 70 48 74 74 70 43 6c 69 65 6e 74 50 72 6f 74 6f 63 6f 6c}
		$s2 = {53 65 72 76 65 72 2e 65 78 65}
		$s3 = {53 79 73 74 65 6d 2e 57 69 6e 64 6f 77 73 2e 46 6f 72 6d 73 2e 46 6f 72 6d}
		$s4 = {53 74 75 62 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73}
		$s5 = {4d 79 2e 43 6f 6d 70 75 74 65 72}
		$s6 = {4d 79 54 65 6d 70 6c 61 74 65}
		$s7 = {53 74 75 62 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 300KB and all of them
}

