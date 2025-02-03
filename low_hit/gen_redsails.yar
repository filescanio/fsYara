rule redSails_EXE : hardened
{
	meta:
		description = "Detects Red Sails Hacktool by WinDivert references"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/BeetleChunks/redsails"
		date = "2017-10-02"
		hash1 = "7a7861d25b0c038d77838ecbd5ea5674650ad4f5faf7432a6f3cfeb427433fac"
		id = "e7ebbebf-e2d6-5cd3-b859-b804d39d1641"

	strings:
		$s1 = {62 57 69 6e 44 69 76 65 72 74 36 34 2e 64 6c 6c}
		$s2 = {62 57 69 6e 44 69 76 65 72 74 33 32 2e 64 6c 6c}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 6000KB and all of them )
}

rule redSails_PY : hardened
{
	meta:
		description = "Detects Red Sails Hacktool - Python"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/BeetleChunks/redsails"
		date = "2017-10-02"
		hash1 = "6ebedff41992b9536fe9b1b704a29c8c1d1550b00e14055e3c6376f75e462661"
		hash2 = "5ec20cb99030f48ba512cbc7998b943bebe49396b20cf578c26debbf14176e5e"
		id = "59d5e784-70ff-5061-9867-54c905ecfd8c"

	strings:
		$x1 = {47 61 69 6e 65 64 20 63 6f 6d 6d 61 6e 64 20 73 68 65 6c 6c 20 6f 6e 20 68 6f 73 74}
		$x2 = {5b 21 5d 20 52 65 63 65 69 76 65 64 20 61 6e 20 45 52 52 4f 52 20 69 6e 20 73 68 65 6c 6c 28 29}
		$x3 = {54 61 72 67 65 74 20 49 50 20 61 64 64 72 65 73 73 20 77 69 74 68 20 62 61 63 6b 64 6f 6f 72 20 69 6e 73 74 61 6c 6c 65 64}
		$x4 = {4f 70 65 6e 20 62 61 63 6b 64 6f 6f 72 20 70 6f 72 74 20 6f 6e 20 74 61 72 67 65 74 20 6d 61 63 68 69 6e 65}
		$x5 = {42 61 63 6b 64 6f 6f 72 20 70 6f 72 74 20 74 6f 20 6f 70 65 6e 20 6f 6e 20 76 69 63 74 69 6d 20 6d 61 63 68 69 6e 65}

	condition:
		1 of them
}

