import "pe"

rule apt_RU_Turla_Kazuar_DebugView_peFeatures : hardened
{
	meta:
		description = "Turla mimicking SysInternals Tools- peFeatures"
		reference = "https://www.epicturla.com/blog/sysinturla"
		version = "2.0"
		author = "JAG-S"
		score = 85
		hash1 = "1749c96cc1a4beb9ad4d6e037e40902fac31042fa40152f1d3794f49ed1a2b5c"
		hash2 = "44cc7f6c2b664f15b499c7d07c78c110861d2cc82787ddaad28a5af8efc3daac"
		id = "0a1675c0-8645-5288-9ef6-e68ffbfe0c3b"

	condition:
		uint16( 0 ) == 0x5a4d and ( pe.version_info [ "LegalCopyright" ] == "Test Copyright" and ( ( pe.version_info [ "ProductName" ] == "Sysinternals DebugView" and pe.version_info [ "Description" ] == "Sysinternals DebugView" ) or ( pe.version_info [ "FileVersion" ] == "4.80.0.0" and pe.version_info [ "Comments" ] == "Sysinternals DebugView" ) or ( pe.version_info [ "OriginalName" ] contains "DebugView.exe" and pe.version_info [ "InternalName" ] contains "DebugView.exe" ) or ( pe.version_info [ "OriginalName" ] == "Agent.exe" and pe.version_info [ "InternalName" ] == "Agent.exe" ) ) )
}

rule APT_MAL_RU_Turla_Kazuar_May20_1 : hardened limited
{
	meta:
		description = "Detects Turla Kazuar malware"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.epicturla.com/blog/sysinturla"
		date = "2020-05-28"
		hash1 = "1749c96cc1a4beb9ad4d6e037e40902fac31042fa40152f1d3794f49ed1a2b5c"
		hash2 = "1fca5f41211c800830c5f5c3e355d31a05e4c702401a61f11e25387e25eeb7fa"
		hash3 = "2d8151dabf891cf743e67c6f9765ee79884d024b10d265119873b0967a09b20f"
		hash4 = "44cc7f6c2b664f15b499c7d07c78c110861d2cc82787ddaad28a5af8efc3daac"
		id = "cd0d1fa2-5303-55f8-90a7-4a699ec79230"

	strings:
		$s1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 53 79 73 69 6e 74 65 72 6e 61 6c 73 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s2 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 54 00 65 00 73 00 74 00 20 00 43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$op1 = { 0d 01 00 08 34 2e 38 30 2e 30 2e 30 00 00 13 01 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 2000KB and all of them
}

