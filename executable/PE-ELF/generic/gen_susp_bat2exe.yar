rule SUSP_BAT2EXE_BDargo_Converted_BAT : hardened
{
	meta:
		description = "Detects binaries created with BDARGO Advanced BAT to EXE converter"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.majorgeeks.com/files/details/advanced_bat_to_exe_converter.html"
		date = "2018-07-28"
		modified = "2022-06-23"
		score = 45
		hash1 = "d428d79f58425d831c2ee0a73f04749715e8c4dd30ccd81d92fe17485e6dfcda"
		hash1 = "a547a02eb4fcb8f446da9b50838503de0d46f9bb2fd197c9ff63021243ea6d88"
		id = "c9da4184-1530-5525-bdba-2dcc8a221bb1"

	strings:
		$s1 = {45 72 72 6f 72 20 23 62 64 65 6d 62 65 64 31 20 2d 2d 20 51 75 69 74 69 6e 67}
		$s2 = {25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73}
		$s3 = {5c 61 2e 74 78 74}
		$s4 = {63 6f 6d 6d 61 6e 64 2e 63 6f 6d}
		$s6 = {44 46 44 48 45 52 47 44 43 56}
		$s7 = {44 46 44 48 45 52 47 47 5a 56}
		$s8 = {25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 300KB and 5 of them
}

