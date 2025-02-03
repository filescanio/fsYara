rule BTC_Miner_lsass1_chrome_2 : hardened
{
	meta:
		description = "Detects a Bitcoin Miner"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research - CN Actor"
		date = "2017-06-22"
		super_rule = 1
		score = 60
		hash1 = "048e9146387d6ff2ac055eb9ddfbfb9a7f70e95c7db9692e2214fa4bec3d5b2e"
		hash2 = "c8db8469287d47ffdc74fe86ce0e9d6e51de67ba1df318573c9398742116a6e8"
		id = "7960d96a-7bd3-5135-867d-e39a02274c45"

	strings:
		$x1 = {2d 74 2c 20 2d 2d 74 68 72 65 61 64 73 3d 4e 20 20 20 20 20 20 20 6e 75 6d 62 65 72 20 6f 66 20 6d 69 6e 65 72 20 74 68 72 65 61 64 73 20 28 64 65 66 61 75 6c 74 3a 20 6e 75 6d 62 65 72 20 6f 66 20 70 72 6f 63 65 73 73 6f 72 73 29}
		$x2 = {2d 4f 2c 20 2d 2d 75 73 65 72 70 61 73 73 3d 55 3a 50 20 20 20 20 75 73 65 72 6e 61 6d 65 3a 70 61 73 73 77 6f 72 64 20 70 61 69 72 20 66 6f 72 20 6d 69 6e 69 6e 67 20 73 65 72 76 65 72}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 6000KB and 1 of them )
}

rule CN_Actor_RA_Tool_Ammyy_mscorsvw : hardened
{
	meta:
		description = "Detects Ammyy remote access tool"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research - CN Actor"
		date = "2017-06-22"
		hash1 = "1831806fc27d496f0f9dcfd8402724189deaeb5f8bcf0118f3d6484d0bdee9ed"
		hash2 = "d9ec0a1be7cd218042c54bfbc12000662b85349a6b78731a09ed336e5d3cf0b4"
		id = "71a0c5a9-b4dc-508d-a6b7-4b85b75bc34b"

	strings:
		$s1 = {50 6c 65 61 73 65 20 65 6e 74 65 72 20 70 61 73 73 77 6f 72 64 20 66 6f 72 20 61 63 63 65 73 73 69 6e 67 20 72 65 6d 6f 74 65 20 63 6f 6d 70 75 74 65 72}
		$s2 = {44 69 65 20 5a 75 67 72 69 66 66 73 61 6e 66 6f 72 64 65 72 75 6e 67 20 77 75 72 64 65 20 76 6f 6d 20 52 65 6d 6f 74 65 63 6f 6d 70 75 74 65 72 20 61 62 67 65 6c 65 68 6e 74}
		$s3 = {49 74 20 77 69 6c 6c 20 61 75 74 6f 6d 61 74 69 63 61 6c 6c 79 20 62 65 20 72 75 6e 20 74 68 65 20 6e 65 78 74 20 74 69 6d 65 20 74 68 69 73 20 63 6f 6d 70 75 74 65 72 20 69 73 20 72 65 73 74 61 72 74 20 6f 72 20 79 6f 75 20 63 61 6e 20 73 74 61 72 74 20 69 74 20 6d 61 6e 75 61 6c 6c 79}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 4000KB and 3 of them )
}

rule CN_Actor_AmmyyAdmin : hardened
{
	meta:
		description = "Detects Ammyy Admin Downloader"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research - CN Actor"
		date = "2017-06-22"
		score = 60
		hash1 = "1831806fc27d496f0f9dcfd8402724189deaeb5f8bcf0118f3d6484d0bdee9ed"
		id = "08ffb61a-e2de-538e-9d9f-040276324af9"

	strings:
		$x2 = {5c 41 6d 6d 79 79 5c 73 6f 75 72 63 65 73 5c 6d 61 69 6e 5c 44 6f 77 6e 6c 6f 61 64 65 72 2e 63 70 70}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 2000KB and all of them )
}

