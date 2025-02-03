rule APT_Malware_PutterPanda_Rel : hardened
{
	meta:
		description = "Detects an APT malware related to PutterPanda"
		author = "Florian Roth"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "5367e183df155e3133d916f7080ef973f7741d34"

	strings:
		$x0 = {61 70 70 2e 73 74 72 65 61 6d 2d 6d 65 64 69 61 2e 6e 65 74}
		$x1 = {46 69 6c 65 20 25 73 20 64 6f 65 73 27 6e 74 20 65 78 69 73 74 20 6f 72 20 69 73 20 66 6f 72 62 69 64 64 65 6e 20 74 6f 20 61 63 65 73 73 21}
		$s6 = {47 65 74 50 72 6f 63 65 73 73 41 64 64 72 65 73 73 73 20 6f 66 20 70 48 74 74 70 51 75 65 72 79 49 6e 66 6f 41 20 46 61 69 6c 65 64 21}
		$s7 = {43 6f 6e 6e 65 63 74 20 25 73 20 65 72 72 6f 72 21}
		$s9 = {44 6f 77 6e 6c 6f 61 64 20 66 69 6c 65 20 25 73 20 73 75 63 63 65 73 73 66 75 6c 6c 79 21}
		$s10 = {69 6e 64 65 78 2e 74 6d 70}
		$s11 = {45 78 65 63 75 74 65 20 50 45 20 53 75 63 63 65 73 73 66 75 6c 6c 79}
		$s13 = {61 61 2f 32 32 2f 73 75 63 63 65 73 73 2e 78 6d 6c}
		$s16 = {61 61 2f 32 32 2f 69 6e 64 65 78 2e 61 73 70}
		$s18 = {46 69 6c 65 20 25 73 20 61 20 4e 6f 6e 2d 50 65 20 46 69 6c 65}
		$s19 = {53 65 6e 64 52 65 71 75 73 65 74 20 65 72 72 6f 72 21}
		$s20 = {66 69 6c 65 6c 69 73 74 5b 25 64 5d 3d 25 73}

	condition:
		( uint16( 0 ) == 0x5a4d and 1 of ( $x* ) ) or ( 4 of ( $s* ) )
}

rule APT_Malware_PutterPanda_Rel_2 : hardened
{
	meta:
		description = "APT Malware related to PutterPanda Group"
		author = "Florian Roth"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "f97e01ee04970d1fc4d988a9e9f0f223ef2a6381"

	strings:
		$s0 = {68 74 74 70 3a 2f 2f 75 70 64 61 74 65 2e 6b 6f 6e 61 6d 69 64 61 74 61 2e 63 6f 6d 2f 74 65 73 74 2f 7a 6c 2f 73 6f 70 68 6f 73 2f 74 64 2f 72 65 73 75 6c 74 2f 72 7a 2e 64 61 74 3f}
		$s1 = {68 74 74 70 3a 2f 2f 75 70 64 61 74 65 2e 6b 6f 6e 61 6d 69 64 61 74 61 2e 63 6f 6d 2f 74 65 73 74 2f 7a 6c 2f 73 6f 70 68 6f 73 2f 74 64 2f 69 6e 64 65 78 2e 64 61 74 3f}
		$s2 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 43 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 36 2e 30 3b 29}
		$s3 = {49 6e 74 65 72 6e 65 74 20 63 6f 6e 6e 65 63 74 20 65 72 72 6f 72 3a 25 64}
		$s4 = {50 72 6f 78 79 2d 41 75 74 68 6f 72 69 7a 61 74 69 6f 6e 3a 42 61 73 69 63}
		$s5 = {48 74 74 70 51 75 65 72 79 49 6e 66 6f 20 66 61 69 6c 65 64 3a 25 64}
		$s6 = {72 65 61 64 20 66 69 6c 65 20 65 72 72 6f 72 3a 25 64}
		$s7 = {64 6f 77 6e 64 6c 6c 2e 64 6c 6c}
		$s8 = {72 7a 2e 64 61 74}
		$s9 = {49 6e 76 61 6c 69 64 20 75 72 6c}
		$s10 = {43 72 65 61 74 65 20 66 69 6c 65 20 66 61 69 6c 65 64}
		$s11 = {6d 79 41 67 65 6e 74}
		$s12 = {25 73 25 73 25 64 25 64}
		$s13 = {64 6f 77 6e 20 66 69 6c 65 20 73 75 63 63 65 73 73}
		$s15 = {65 72 72 6f 72 21}
		$s18 = {41 76 61 6c 69 61 62 6c 65 20 64 61 74 61 3a 25 75 20 62 79 74 65 73}

	condition:
		uint16( 0 ) == 0x5a4d and 6 of them
}

rule APT_Malware_PutterPanda_PSAPI : hardened
{
	meta:
		description = "Detects a malware related to Putter Panda"
		author = "Florian Roth"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "f93a7945a33145bb6c106a51f08d8f44eab1cdf5"

	strings:
		$s0 = {4c 4f 41 44 45 52 20 45 52 52 4f 52}
		$s1 = {54 68 65 20 70 72 6f 63 65 64 75 72 65 20 65 6e 74 72 79 20 70 6f 69 6e 74 20 25 73 20 63 6f 75 6c 64 20 6e 6f 74 20 62 65 20 6c 6f 63 61 74 65 64 20 69 6e 20 74 68 65 20 64 79 6e 61 6d 69 63 20 6c 69 6e 6b 20 6c 69 62 72 61 72 79 20 25 73}
		$s2 = {70 73 61 70 69 2e 64 6c 6c}
		$s3 = {75 72 6c 6d 6f 6e 2e 64 6c 6c}
		$s4 = {57 69 6e 48 74 74 70 47 65 74 50 72 6f 78 79 46 6f 72 55 72 6c}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 300KB and all of them
}

rule APT_Malware_PutterPanda_WUAUCLT : hardened
{
	meta:
		description = "Detects a malware related to Putter Panda"
		author = "Florian Roth"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "fd5ca5a2d444865fa8320337467313e4026b9f78"

	strings:
		$x0 = {57 00 55 00 41 00 55 00 43 00 4c 00 54 00 2e 00 45 00 58 00 45 00}
		$x1 = {25 73 5c 74 6d 70 25 64 2e 65 78 65}
		$x2 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 20 00 41 00 6c 00 6c 00 20 00 72 00 69 00 67 00 68 00 74 00 73 00 20 00 72 00 65 00 73 00 65 00 72 00 76 00 65 00 64 00 2e 00}
		$s1 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4f 00 70 00 65 00 72 00 61 00 74 00 69 00 6e 00 67 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00}
		$s2 = {49 6e 74 65 72 6e 65 74 51 75 65 72 79 4f 70 74 69 6f 6e 41}
		$s3 = {4c 6f 6f 6b 75 70 50 72 69 76 69 6c 65 67 65 56 61 6c 75 65 41}
		$s4 = {57 4e 65 74 45 6e 75 6d 52 65 73 6f 75 72 63 65 41}
		$s5 = {48 74 74 70 53 65 6e 64 52 65 71 75 65 73 74 45 78 41}
		$s6 = {50 53 41 50 49 2e 44 4c 4c}
		$s7 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 28 00 52 00 29 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 28 00 52 00 29 00 20 00 4f 00 70 00 65 00 72 00 61 00 74 00 69 00 6e 00 67 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00}
		$s8 = {43 72 65 61 74 65 50 69 70 65}
		$s9 = {45 6e 75 6d 50 72 6f 63 65 73 73 4d 6f 64 75 6c 65 73}

	condition:
		all of ( $x* ) or ( 1 of ( $x* ) and all of ( $s* ) )
}

rule APT_Malware_PutterPanda_Gen1 : hardened
{
	meta:
		description = "Detects a malware "
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015-06-03"
		super_rule = 1
		hash0 = "bf1d385e637326a63c4d2f253dc211e6a5436b6a"
		hash1 = "76459bcbe072f9c29bb9703bc72c7cd46a692796"
		hash2 = "e105a7a3a011275002aec4b930c722e6a7ef52ad"

	strings:
		$s1 = {25 73 25 64 75 73 65 72 69 64 3d 25 64 74 68 72 65 61 64 69 64 3d 25 64 67 72 6f 75 70 69 64 3d 25 64}
		$s2 = {73 73 64 70 73 76 63 2e 64 6c 6c}
		$s3 = {46 61 69 6c 20 25 73 20}
		$s4 = {25 73 25 64 70 61 72 61 31 3d 25 64 70 61 72 61 32 3d 25 64 70 61 72 61 33 3d 25 64}
		$s5 = {4c 73 61 53 65 72 76 69 63 65 49 6e 69 74}
		$s6 = {25 2d 38 64 20 46 73 20 25 2d 31 32 73 20 42 73 20}
		$s7 = {4d 69 63 72 6f 73 6f 66 74 20 44 48 20 53 43 68 61 6e 6e 65 6c 20 43 72 79 70 74 6f 67 72 61 70 68 69 63 20 50 72 6f 76 69 64 65 72}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1000KB and 5 of them
}

rule Malware_MsUpdater_String_in_EXE : hardened
{
	meta:
		description = "MSUpdater String in Executable"
		author = "Florian Roth"
		score = 50
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "b1a2043b7658af4d4c9395fa77fde18ccaf549bb"

	strings:
		$x1 = {6d 00 73 00 75 00 70 00 64 00 61 00 74 00 65 00 2e 00 65 00 78 00 65 00}
		$x3 = {6d 73 75 70 64 61 74 65 72 2e 65 78 65}
		$x4 = {6d 73 75 70 64 61 74 65 72 33 32 2e 65 78 65}
		$x5 = {6d 00 73 00 75 00 70 00 64 00 61 00 74 00 65 00 72 00 33 00 32 00 2e 00 65 00 78 00 65 00}
		$x6 = {6d 73 75 70 64 61 74 65 2e 70 69 66}
		$fp1 = {5f 00 6d 00 73 00 75 00 70 00 64 00 61 00 74 00 65 00 5f 00}
		$fp2 = {5f 6d 73 75 70 64 61 74 65 5f}
		$fp3 = {2f 00 6b 00 69 00 65 00 73 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 500KB and ( 1 of ( $x* ) ) and not ( 1 of ( $fp* ) )
}

rule APT_Malware_PutterPanda_MsUpdater_3 : hardened
{
	meta:
		description = "Detects Malware related to PutterPanda - MSUpdater"
		author = "Florian Roth"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "464149ff23f9c7f4ab2f5cadb76a4f41f969bed0"

	strings:
		$s0 = {6d 73 75 70 64 61 74 65 72 2e 65 78 65}
		$s1 = {45 78 70 6c 6f 72 65 72 2e 65 78 65 20 22}
		$s2 = {46 41 56 4f 52 49 54 45 53 2e 44 41 54}
		$s4 = {43 4f 4d 53 50 45 43}

	condition:
		uint16( 0 ) == 0x5a4d and 3 of them
}

rule APT_Malware_PutterPanda_MsUpdater_1 : hardened
{
	meta:
		description = "Detects Malware related to PutterPanda - MSUpdater"
		author = "Florian Roth"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "b55072b67543f58c096571c841a560c53d72f01a"

	strings:
		$x0 = {6d 00 73 00 75 00 70 00 64 00 61 00 74 00 65 00 2e 00 65 00 78 00 65 00}
		$x1 = {6d 00 73 00 75 00 70 00 64 00 61 00 74 00 65 00}
		$s1 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 20 00 41 00 6c 00 6c 00 20 00 72 00 69 00 67 00 68 00 74 00 73 00 20 00 72 00 65 00 73 00 65 00 72 00 76 00 65 00 64 00 2e 00}
		$s2 = {41 00 75 00 74 00 6f 00 6d 00 61 00 74 00 69 00 63 00 20 00 55 00 70 00 64 00 61 00 74 00 65 00 73 00}
		$s3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 45 78}
		$s4 = {49 6e 76 61 6c 69 64 20 70 61 72 61 6d 65 74 65 72}
		$s5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78}
		$s6 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79}

	condition:
		( uint16( 0 ) == 0x5a4d and 1 of ( $x* ) and 4 of ( $s* ) ) or ( 1 of ( $x* ) and all of ( $s* ) )
}

rule APT_Malware_PutterPanda_MsUpdater_2 : hardened
{
	meta:
		description = "Detects Malware related to PutterPanda - MSUpdater"
		author = "Florian Roth"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "365b5537e3495f8ecfabe2597399b1f1226879b1"

	strings:
		$s0 = {77 69 6e 73 74 61 30 5c 64 65 66 61 75 6c 74}
		$s1 = {45 58 50 4c 4f 52 45 52 2e 45 58 45}
		$s2 = {57 4e 65 74 45 6e 75 6d 52 65 73 6f 75 72 63 65 41}
		$s3 = {65 78 70 6c 6f 72 65 72 2e 65 78 65}
		$s4 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 41 73 55 73 65 72 41}
		$s5 = {48 74 74 70 53 65 6e 64 52 65 71 75 65 73 74 45 78 41}
		$s6 = {48 74 74 70 45 6e 64 52 65 71 75 65 73 74 41}
		$s7 = {47 65 74 4d 6f 64 75 6c 65 42 61 73 65 4e 61 6d 65 41}
		$s8 = {47 65 74 4d 6f 64 75 6c 65 46 69 6c 65 4e 61 6d 65 45 78 41}
		$s9 = {48 74 74 70 53 65 6e 64 52 65 71 75 65 73 74 41}
		$s10 = {48 74 74 70 4f 70 65 6e 52 65 71 75 65 73 74 41}
		$s11 = {49 6e 74 65 72 6e 65 74 43 6f 6e 6e 65 63 74 41}
		$s12 = {50 72 6f 63 65 73 73 33 32 4e 65 78 74}
		$s13 = {50 72 6f 63 65 73 73 33 32 46 69 72 73 74}
		$s14 = {43 72 65 61 74 65 50 69 70 65}
		$s15 = {45 6e 75 6d 50 72 6f 63 65 73 73 65 73}
		$s16 = {4c 6f 6f 6b 75 70 50 72 69 76 69 6c 65 67 65 56 61 6c 75 65 41}
		$s17 = {50 65 65 6b 4e 61 6d 65 64 50 69 70 65}
		$s18 = {45 6e 75 6d 50 72 6f 63 65 73 73 4d 6f 64 75 6c 65 73}
		$s19 = {50 53 41 50 49 2e 44 4c 4c}
		$s20 = {53 50 53 53 53 51}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 220KB and all of them
}

rule APT_Malware_PutterPanda_Gen4 : hardened
{
	meta:
		description = "Detects Malware related to PutterPanda"
		author = "Florian Roth"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		super_rule = 1
		hash0 = "71a8378fa8e06bcf8ee9f019c807c6bfc58dca0c"
		hash1 = "8fdd6e5ed9d69d560b6fdd5910f80e0914893552"
		hash2 = "3c4a762175326b37035a9192a981f7f4cc2aa5f0"
		hash3 = "598430b3a9b5576f03cc4aed6dc2cd8a43324e1e"
		hash4 = "6522b81b38747f4aa09c98fdaedaed4b00b21689"

	strings:
		$x1 = {72 7a 2e 64 61 74}
		$s0 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 43 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 36 2e 30 3b 29}
		$s1 = {49 6e 74 65 72 6e 65 74 20 63 6f 6e 6e 65 63 74 20 65 72 72 6f 72 3a 25 64}
		$s2 = {50 72 6f 78 79 2d 41 75 74 68 6f 72 69 7a 61 74 69 6f 6e 3a 42 61 73 69 63 20}
		$s5 = {49 6e 76 61 6c 69 64 20 75 72 6c}
		$s6 = {43 72 65 61 74 65 20 66 69 6c 65 20 66 61 69 6c 65 64}
		$s7 = {6d 79 41 67 65 6e 74}
		$z1 = {25 73 25 73 25 64 25 64}
		$z2 = {48 74 74 70 51 75 65 72 79 49 6e 66 6f 20 66 61 69 6c 65 64 3a 25 64}
		$z3 = {72 65 61 64 20 66 69 6c 65 20 65 72 72 6f 72 3a 25 64}
		$z4 = {64 6f 77 6e 20 66 69 6c 65 20 73 75 63 63 65 73 73}
		$z5 = {6b 50 53 74 6f 72 65 43 72 65 61 74 65 49 6e 73 74 61 6e 63 65}
		$z6 = {41 76 61 6c 69 61 62 6c 65 20 64 61 74 61 3a 25 75 20 62 79 74 65 73}
		$z7 = {61 62 65 32 38 36 39 66 2d 39 62 34 37 2d 34 63 64 39 2d 61 33 35 38 2d 63 32 32 39 30 34 64 62 61 37 66 37}

	condition:
		filesize < 300KB and ( ( uint16( 0 ) == 0x5a4d and $x1 and 3 of ( $s* ) ) or ( 3 of ( $s* ) and 4 of ( $z* ) ) )
}

