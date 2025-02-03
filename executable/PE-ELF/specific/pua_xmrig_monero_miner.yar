rule XMRIG_Monero_Miner : HIGHVOL hardened
{
	meta:
		description = "Detects Monero mining software"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/xmrig/xmrig/releases"
		date = "2018-01-04"
		modified = "2022-11-10"
		modified = "2022-11-10"
		hash1 = "5c13a274adb9590249546495446bb6be5f2a08f9dcd2fc8a2049d9dc471135c0"
		hash2 = "08b55f9b7dafc53dfc43f7f70cdd7048d231767745b76dc4474370fb323d7ae7"
		hash3 = "f3f2703a7959183b010d808521b531559650f6f347a5830e47f8e3831b10bad5"
		hash4 = "0972ea3a41655968f063c91a6dbd31788b20e64ff272b27961d12c681e40b2d2"
		id = "71bf1b9c-c806-5737-83a9-d6013872b11d"
		score = 70

	strings:
		$s1 = {27 68 27 20 68 61 73 68 72 61 74 65 2c 20 27 70 27 20 70 61 75 73 65 2c 20 27 72 27 20 72 65 73 75 6d 65}
		$s2 = {2d 2d 63 70 75 2d 61 66 66 69 6e 69 74 79}
		$s3 = {73 65 74 20 70 72 6f 63 65 73 73 20 61 66 66 69 6e 69 74 79 20 74 6f 20 43 50 55 20 63 6f 72 65 28 73 29 2c 20 6d 61 73 6b 20 30 78 33 20 66 6f 72 20 63 6f 72 65 73 20 30 20 61 6e 64 20 31}
		$s4 = {70 61 73 73 77 6f 72 64 20 66 6f 72 20 6d 69 6e 69 6e 67 20 73 65 72 76 65 72}
		$s5 = {58 4d 52 69 67 2f 25 73 20 6c 69 62 75 76 2f 25 73 25 73}

	condition:
		( uint16( 0 ) == 0x5a4d or uint16( 0 ) == 0x457f ) and filesize < 10MB and 2 of them
}

rule XMRIG_Monero_Miner_Config : hardened
{
	meta:
		description = "Auto-generated rule - from files config.json, config.json"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/xmrig/xmrig/releases"
		date = "2018-01-04"
		hash1 = "031333d44a3a917f9654d7e7257e00c9d961ada3bee707de94b7c7d06234909a"
		hash2 = "409b6ec82c3bdac724dae702e20cb7f80ca1e79efa4ff91212960525af016c41"
		id = "374efe7f-9ef2-5974-8e24-f749183ab2d0"

	strings:
		$s2 = {22 63 70 75 2d 61 66 66 69 6e 69 74 79 22 3a 20 6e 75 6c 6c 2c 20 20 20 2f 2f 20 73 65 74 20 70 72 6f 63 65 73 73 20 61 66 66 69 6e 69 74 79 20 74 6f 20 43 50 55 20 63 6f 72 65 28 73 29 2c 20 6d 61 73 6b 20 22 30 78 33 22 20 66 6f 72 20 63 6f 72 65 73 20 30 20 61 6e 64 20 31}
		$s5 = {22 6e 69 63 65 68 61 73 68 22 3a 20 66 61 6c 73 65 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 2f 2f 20 65 6e 61 62 6c 65 20 6e 69 63 65 68 61 73 68 2f 78 6d 72 69 67 2d 70 72 6f 78 79 20 73 75 70 70 6f 72 74}
		$s8 = {22 61 6c 67 6f 22 3a 20 22 63 72 79 70 74 6f 6e 69 67 68 74 22 2c 20 20 2f 2f 20 63 72 79 70 74 6f 6e 69 67 68 74 20 28 64 65 66 61 75 6c 74 29 20 6f 72 20 63 72 79 70 74 6f 6e 69 67 68 74 2d 6c 69 74 65}

	condition:
		( uint16( 0 ) == 0x0a7b or uint16( 0 ) == 0x0d7b ) and filesize < 5KB and 1 of them
}

rule PUA_LNX_XMRIG_CryptoMiner : hardened
{
	meta:
		description = "Detects XMRIG CryptoMiner software"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2018-06-28"
		modified = "2023-01-06"
		hash1 = "10a72f9882fc0ca141e39277222a8d33aab7f7a4b524c109506a407cd10d738c"
		id = "bbdeff2e-68cc-5bbe-b843-3cba9c8c7ea8"
		score = 70

	strings:
		$x1 = {6e 75 6d 62 65 72 20 6f 66 20 68 61 73 68 20 62 6c 6f 63 6b 73 20 74 6f 20 70 72 6f 63 65 73 73 20 61 74 20 61 20 74 69 6d 65 20 28 64 6f 6e 27 74 20 73 65 74 20 6f 72 20 30 20 65 6e 61 62 6c 65 73 20 61 75 74 6f 6d 61 74 69 63 20 73 65 6c 65 63 74 69 6f 6e 20 6f}
		$s2 = {27 68 27 20 68 61 73 68 72 61 74 65 2c 20 27 70 27 20 70 61 75 73 65 2c 20 27 72 27 20 72 65 73 75 6d 65 2c 20 27 71 27 20 73 68 75 74 64 6f 77 6e}
		$s3 = {2a 20 54 48 52 45 41 44 53 3a 20 20 20 20 20 20 25 64 2c 20 25 73 2c 20 61 65 73 3d 25 64 2c 20 68 66 3d 25 7a 75 2c 20 25 73 64 6f 6e 61 74 65 3d 25 64 25 25}
		$s4 = {2e 6e 69 63 65 68 61 73 68 2e 63 6f 6d}

	condition:
		uint16( 0 ) == 0x457f and filesize < 8000KB and ( 1 of ( $x* ) or 2 of them )
}

rule SUSP_XMRIG_String : hardened
{
	meta:
		description = "Detects a suspicious XMRIG crypto miner executable string in filr"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2018-12-28"
		hash1 = "eb18ae69f1511eeb4ed9d4d7bcdf3391a06768f384e94427f4fc3bd21b383127"
		id = "8c6f3e6e-df2a-51b7-81b8-21cd33b3c603"

	strings:
		$x1 = {78 6d 72 69 67 2e 65 78 65}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 2000KB and 1 of them
}

