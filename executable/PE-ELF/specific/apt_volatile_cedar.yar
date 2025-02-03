rule Explosive_EXE : APT hardened
{
	meta:
		description = "Explosion/Explosive Malware - Volatile Cedar APT"
		author = "Check Point Software Technologies Inc."
		id = "3a9fb6b2-2f19-5d70-81ed-a08c3b8b2d80"

	strings:
		$DLD_S = {44 4c 44 2d 53 3a}
		$DLD_E = {44 4c 44 2d 45 3a}

	condition:
		all of them and uint16( 0 ) == 0x5A4D
}

rule Explosion_Sample_1 : hardened
{
	meta:
		description = "Explosion/Explosive Malware - Volatile Cedar APT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/5vYaNb"
		date = "2015/04/03"
		score = 70
		hash = "c97693ecb36247bdb44ab3f12dfeae8be4d299bb"
		id = "dcf28185-75a8-5c9f-9f60-edb8dc187e16"

	strings:
		$s5 = {52 45 47 20 41 44 44 20 22 48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e}
		$s9 = {57 69 6e 41 75 74 6f 6c 6f 67 6f 6e 20 46 72 6f 6d 20 57 69 6e 6c 6f 67 6f 6e 20 52 65 67}
		$s10 = {38 32 42 44 30 45 36 37 2d 39 46 45 41 2d 34 37 34 38 2d 38 36 37 32 2d 44 35 45 46 45 35 42 37 37 39 42 30}
		$s11 = {49 45 3a 50 61 73 73 77 6f 72 64 2d 50 72 6f 74 65 63 74 65 64 20 73 69 74 65 73}
		$s12 = {5c 68 69 73 2e 73 79 73}
		$s13 = {48 54 54 50 20 50 61 73 73 77 6f 72 64}
		$s14 = {5c 64 61 74 61 2e 73 79 73}
		$s15 = {45 00 4c 00 24 00 5f 00 52 00 61 00 73 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 43 00 72 00 65 00 64 00 65 00 6e 00 74 00 69 00 61 00 6c 00 73 00 23 00 30 00}
		$s17 = {4f 66 66 69 63 65 20 4f 75 74 6c 6f 6f 6b 20 48 54 54 50}
		$s20 = {48 69 73 74 20 3a 3c 62 3e 20 25 77 73 3c 2f 62 3e 20 20 3a 25 73 20 3c 2f 62 72 3e 3c 2f 62 72 3e}

	condition:
		all of them and uint16( 0 ) == 0x5A4D
}

rule Explosion_Sample_2 : hardened
{
	meta:
		description = "Explosion/Explosive Malware - Volatile Cedar APT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/5vYaNb"
		date = "2015/04/03"
		score = 70
		hash = "62fe6e9e395f70dd632c70d5d154a16ff38dcd29"
		id = "8be7ed50-0bfc-5302-b4fa-8817bf1750d7"

	strings:
		$s0 = {73 00 65 00 72 00 76 00 65 00 72 00 68 00 65 00 6c 00 70 00 2e 00 64 00 6c 00 6c 00}
		$s1 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 48 00 65 00 6c 00 70 00 20 00 44 00 4c 00 4c 00}
		$s5 = {53 65 74 57 69 6e 48 6f 4b}

	condition:
		all of them and uint16( 0 ) == 0x5A4D
}

rule Explosion_Generic_1 : hardened
{
	meta:
		description = "Generic Rule for Explosion/Explosive Malware - Volatile Cedar APT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "not set"
		date = "2015/04/03"
		score = 70
		super_rule = 1
		hash0 = "d0f059ba21f06021579835a55220d1e822d1233f95879ea6f7cb9d301408c821"
		hash1 = "1952fa94b582e9af9dca596b5e51c585a78b8b1610639e3b878bbfa365e8e908"
		hash2 = "d8fdcdaad652c19f4f4676cd2f89ae834dbc19e2759a206044b18601875f2726"
		hash3 = "e2e6ed82703de21eb4c5885730ba3db42f3ddda8b94beb2ee0c3af61bc435747"
		hash4 = "03641e5632673615f23b2a8325d7355c4499a40f47b6ae094606a73c56e24ad0"
		id = "dc3721b6-c19e-5449-9962-2a6f844e49b4"

	strings:
		$s0 = {61 75 74 6f 72 75 6e 2e 65 78 65}
		$s1 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 37 2e 30 3b 20 4d 53 49 45 20 36 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 31 3b 20 2e 4e 45 54 20 43 4c}
		$s2 = {25 64 72 70 2e 65 78 65}
		$s3 = {25 73 5f 25 73 25 64 2e 65 78 65}
		$s4 = {6f 70 65 6e 3d 61 75 74 6f 72 75 6e 2e 65 78 65}
		$s5 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d 2f 65 6e 2d 75 73 2f 64 65 66 61 75 6c 74 2e 61 73 70 78}
		$s10 = {65 72 72 6f 72 2e 72 65 6e 61 6d 65 66 69 6c 65}
		$s12 = {69 6e 73 75 66 66 69 63 69 65 6e 74 20 6c 6f 6f 6b 61 68 65 61 64}
		$s13 = {25 73 20 25 73 7c}
		$s16 = {3a 5c 61 75 74 6f 72 75 6e 2e 65 78 65}

	condition:
		7 of them and uint16( 0 ) == 0x5A4D
}

rule Explosive_UA : hardened
{
	meta:
		description = "Explosive Malware Embedded User Agent - Volatile Cedar APT http://goo.gl/HQRCdw"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/HQRCdw"
		date = "2015/04/03"
		score = 60
		id = "d88d5fd6-adf9-5ced-8b79-e47e3ffbde50"

	strings:
		$x1 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 37 2e 30 3b 20 4d 53 49 45 20 36 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 31 3b 20 2e 4e 45 54 20 43 4c 52 20 32 2e 30 2e 35 30 37 32 37 29}

	condition:
		$x1 and uint16( 0 ) == 0x5A4D
}

rule Webshell_Caterpillar_ASPX : hardened
{
	meta:
		description = "Volatile Cedar Webshell - from file caterpillar.aspx"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/emons5"
		date = "2015/04/03"
		super_rule = 1
		hash0 = "af4c99208fb92dc42bc98c4f96c3536ec8f3fe56"
		id = "9af48c64-3768-5765-8245-38df000598a7"

	strings:
		$s0 = {44 69 6d 20 6f 62 6a 4e 65 77 52 65 71 75 65 73 74 20 41 73 20 57 65 62 52 65 71 75 65 73 74 20 3d 20 48 74 74 70 57 65 62 52 65 71 75 65 73 74 2e 43 72 65 61 74 65 28 73 55 52 4c 29}
		$s1 = {63 6f 6d 6d 61 6e 64 20 3d 20 22 69 70 63 6f 6e 66 69 67 20 2f 61 6c 6c 22}
		$s3 = {46 6f 72 20 45 61 63 68 20 78 66 69 6c 65 20 49 6e 20 6d 79 64 69 72 2e 47 65 74 46 69 6c 65 73 28 29}
		$s6 = {44 69 6d 20 6f 53 63 72 69 70 74 4e 65 74 20 3d 20 53 65 72 76 65 72 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 43 52 49 50 54 2e 4e 45 54 57 4f 52 4b 22 29}
		$s10 = {72 65 63 52 65 73 75 6c 74 20 3d 20 61 64 6f 43 6f 6e 6e 2e 45 78 65 63 75 74 65 28 73 74 72 51 75 65 72 79 29}
		$s12 = {62 20 3d 20 52 65 71 75 65 73 74 2e 51 75 65 72 79 53 74 72 69 6e 67 28 22 73 72 63 22 29}
		$s13 = {72 77 28 22 3c 61 20 68 72 65 66 3d 27 22 20 2b 20 6c 69 6e 6b 20 2b 20 22 27 20 74 61 72 67 65 74 3d 27 22 20 2b 20 74 61 72 67 65 74 20 2b 20 22 27 3e 22 20 2b 20 74 69 74 6c 65 20 2b 20 22 3c 2f 61 3e 22 29}

	condition:
		all of them
}

