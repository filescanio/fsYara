rule WindowsShell_s3 : hardened
{
	meta:
		description = "Detects simple Windows shell - file s3.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/odzhan/shells/"
		date = "2016-03-26"
		hash = "344575a58db288c9b5dacc654abc36d38db2e645acff05e894ff51183c61357d"
		id = "064754a7-8639-5dbd-93f3-906662b8e9bc"

	strings:
		$s1 = {63 6d 64 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 2d 20 65 78 65 63 75 74 65 20 63 6d 64 2e 65 78 65}
		$s2 = {5c 5c 2e 5c 70 69 70 65 5c 25 30 38 58}
		$s3 = {67 65 74 20 3c 72 65 6d 6f 74 65 3e 20 3c 6c 6f 63 61 6c 3e 20 2d 20 64 6f 77 6e 6c 6f 61 64 20 66 69 6c 65}
		$s4 = {5b 20 73 69 6d 70 6c 65 20 72 65 6d 6f 74 65 20 73 68 65 6c 6c 20 66 6f 72 20 77 69 6e 64 6f 77 73 20 76 33}
		$s5 = {52 45 4d 4f 54 45 3a 20 43 72 65 61 74 65 46 69 6c 65 28 22 25 73 22 29}
		$s6 = {70 75 74 20 3c 6c 6f 63 61 6c 3e 20 3c 72 65 6d 6f 74 65 3e 20 2d 20 75 70 6c 6f 61 64 20 66 69 6c 65}
		$s7 = {74 65 72 6d 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 2d 20 74 65 72 6d 69 6e 61 74 65 20 72 65 6d 6f 74 65 20 63 6c 69 65 6e 74}
		$s8 = {5b 20 64 6f 77 6e 6c 6f 61 64 69 6e 67 20 22 25 73 22 20 74 6f 20 22 25 73 22}
		$s9 = {2d 6c 20 20 20 20 20 20 20 20 20 20 20 4c 69 73 74 65 6e 20 66 6f 72 20 69 6e 63 6f 6d 69 6e 67 20 63 6f 6e 6e 65 63 74 69 6f 6e 73}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 150KB and 2 of them ) or ( 5 of them )
}

rule WindosShell_s1 : hardened
{
	meta:
		description = "Detects simple Windows shell - file s1.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/odzhan/shells/"
		date = "2016-03-26"
		hash = "4a397497cfaf91e05a9b9d6fa6e335243cca3f175d5d81296b96c13c624818bd"
		id = "b4e783a2-4a93-5c72-9b09-4692b383ac00"

	strings:
		$s1 = {5b 20 65 78 65 63 75 74 69 6e 67 20 63 6d 64 2e 65 78 65}
		$s2 = {5b 20 73 69 6d 70 6c 65 20 72 65 6d 6f 74 65 20 73 68 65 6c 6c 20 66 6f 72 20 77 69 6e 64 6f 77 73 20 76 31}
		$s3 = {2d 70 20 3c 6e 75 6d 62 65 72 3e 20 20 50 6f 72 74 20 6e 75 6d 62 65 72 20 74 6f 20 75 73 65 20 28 64 65 66 61 75 6c 74 20 69 73 20 34 34 33 29}
		$s4 = {75 73 61 67 65 3a 20 73 31 20 3c 61 64 64 72 65 73 73 3e 20 5b 6f 70 74 69 6f 6e 73 5d}
		$s5 = {5b 20 77 61 69 74 69 6e 67 20 66 6f 72 20 63 6f 6e 6e 65 63 74 69 6f 6e 73 20 6f 6e 20 25 73}
		$s6 = {2d 6c 20 20 20 20 20 20 20 20 20 20 20 4c 69 73 74 65 6e 20 66 6f 72 20 69 6e 63 6f 6d 69 6e 67 20 63 6f 6e 6e 65 63 74 69 6f 6e 73}
		$s7 = {5b 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 66 72 6f 6d 20 25 73}
		$s8 = {5b 20 25 63 25 63 20 72 65 71 75 69 72 65 73 20 70 61 72 61 6d 65 74 65 72}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 150KB and 2 of them ) or ( 5 of them )
}

rule WindowsShell_s4 : hardened
{
	meta:
		description = "Detects simple Windows shell - file s4.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/odzhan/shells/"
		date = "2016-03-26"
		hash = "f00a1af494067b275407c449b11dfcf5cb9b59a6fac685ebd3f0eb193337e1d6"
		id = "838771dc-f885-5332-9813-2bc01af8e5fe"

	strings:
		$s1 = {63 6d 64 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 2d 20 65 78 65 63 75 74 65 20 63 6d 64 2e 65 78 65}
		$s2 = {5c 5c 2e 5c 70 69 70 65 5c 25 30 38 58}
		$s3 = {67 65 74 20 3c 72 65 6d 6f 74 65 3e 20 3c 6c 6f 63 61 6c 3e 20 2d 20 64 6f 77 6e 6c 6f 61 64 20 66 69 6c 65}
		$s4 = {5b 20 73 69 6d 70 6c 65 20 72 65 6d 6f 74 65 20 73 68 65 6c 6c 20 66 6f 72 20 77 69 6e 64 6f 77 73 20 76 34}
		$s5 = {52 45 4d 4f 54 45 3a 20 43 72 65 61 74 65 46 69 6c 65 28 22 25 73 22 29}
		$s6 = {5b 20 64 6f 77 6e 6c 6f 61 64 69 6e 67 20 22 25 73 22 20 74 6f 20 22 25 73 22}
		$s7 = {5b 20 75 70 6c 6f 61 64 69 6e 67 20 22 25 73 22 20 74 6f 20 22 25 73 22}
		$s8 = {2d 6c 20 20 20 20 20 20 20 20 20 20 20 4c 69 73 74 65 6e 20 66 6f 72 20 69 6e 63 6f 6d 69 6e 67 20 63 6f 6e 6e 65 63 74 69 6f 6e 73}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 175KB and 2 of them ) or ( 5 of them )
}

rule WindowsShell_Gen : hardened
{
	meta:
		description = "Detects simple Windows shell - from files keygen.exe, s1.exe, s2.exe, s3.exe, s4.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/odzhan/shells/"
		date = "2016-03-26"
		super_rule = 1
		hash1 = "a7c3d85eabac01e7a7ec914477ea9f17e3020b3b2f8584a46a98eb6a2a7611c5"
		hash2 = "4a397497cfaf91e05a9b9d6fa6e335243cca3f175d5d81296b96c13c624818bd"
		hash3 = "df0693caae2e5914e63e9ee1a14c1e9506f13060faed67db5797c9e61f3907f0"
		hash4 = "344575a58db288c9b5dacc654abc36d38db2e645acff05e894ff51183c61357d"
		hash5 = "f00a1af494067b275407c449b11dfcf5cb9b59a6fac685ebd3f0eb193337e1d6"
		id = "6b871e8a-8fe3-5cc6-9f2c-ba2359861ea1"

	strings:
		$s0 = {5b 20 25 63 25 63 20 72 65 71 75 69 72 65 73 20 70 61 72 61 6d 65 74 65 72}
		$s1 = {5b 20 25 73 20 3a 20 25 69}
		$s2 = {5b 20 25 73 20 3a 20 25 73}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 175KB and 2 of them ) or ( all of them )
}

rule WindowsShell_Gen2 : hardened
{
	meta:
		description = "Detects simple Windows shell - from files s3.exe, s4.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/odzhan/shells/"
		date = "2016-03-26"
		super_rule = 1
		hash1 = "344575a58db288c9b5dacc654abc36d38db2e645acff05e894ff51183c61357d"
		hash2 = "f00a1af494067b275407c449b11dfcf5cb9b59a6fac685ebd3f0eb193337e1d6"
		id = "8ed8443d-491b-5cb0-b12b-0d25267ba462"

	strings:
		$s1 = {63 6d 64 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 2d 20 65 78 65 63 75 74 65 20 63 6d 64 2e 65 78 65}
		$s2 = {67 65 74 20 3c 72 65 6d 6f 74 65 3e 20 3c 6c 6f 63 61 6c 3e 20 2d 20 64 6f 77 6e 6c 6f 61 64 20 66 69 6c 65}
		$s3 = {52 45 4d 4f 54 45 3a 20 43 72 65 61 74 65 46 69 6c 65 28 22 25 73 22 29}
		$s4 = {70 75 74 20 3c 6c 6f 63 61 6c 3e 20 3c 72 65 6d 6f 74 65 3e 20 2d 20 75 70 6c 6f 61 64 20 66 69 6c 65}
		$s5 = {74 65 72 6d 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 2d 20 74 65 72 6d 69 6e 61 74 65 20 72 65 6d 6f 74 65 20 63 6c 69 65 6e 74}
		$s6 = {5b 20 75 70 6c 6f 61 64 69 6e 67 20 22 25 73 22 20 74 6f 20 22 25 73 22}
		$s7 = {5b 20 65 72 72 6f 72 20 3a 20 72 65 63 65 69 76 65 64 20 25 69 20 62 79 74 65 73}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 175KB and 2 of them ) or ( 5 of them )
}

