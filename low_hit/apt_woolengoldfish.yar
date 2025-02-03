rule WoolenGoldfish_Sample_1 : hardened
{
	meta:
		description = "Detects a operation Woolen-Goldfish sample - http://goo.gl/NpJpVZ"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/NpJpVZ"
		date = "2015/03/25"
		score = 60
		hash = "7ad0eb113bc575363a058f4bf21dbab8c8f7073a"
		id = "923de51a-8422-5318-95f5-79613d2d642e"

	strings:
		$s1 = {43 61 6e 6e 6f 74 20 65 78 65 63 75 74 65 20 28 25 64 29}
		$s16 = {53 76 63 4e 61 6d 65}

	condition:
		all of them
}

rule WoolenGoldfish_Generic_1 : hardened
{
	meta:
		description = "Detects a operation Woolen-Goldfish sample - http://goo.gl/NpJpVZ"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/NpJpVZ"
		date = "2015/03/25"
		score = 90
		super_rule = 1
		hash0 = "5d334e0cb4ff58859e91f9e7f1c451ffdc7544c3"
		hash1 = "d5b2b30fe2d4759c199e3659d561a50f88a7fb2e"
		hash2 = "a42f1ad2360833baedd2d5f59354c4fc3820c475"
		id = "351f5ee5-c0ec-51b6-9953-2b64e3e74b09"

	strings:
		$x0 = {55 73 65 72 73 5c 57 6f 6f 6c 33 6e 2e 48 34 74 5c}
		$x1 = {43 2d 43 50 50 5c 43 57 6f 6f 6c 67 65 72}
		$x2 = {4e 00 54 00 53 00 75 00 73 00 65 00 72 00 2e 00 65 00 78 00 65 00}
		$s1 = {31 00 30 00 37 00 2e 00 36 00 2e 00 31 00 38 00 31 00 2e 00 31 00 31 00 36 00}
		$s2 = {6f 53 68 65 6c 6c 4c 69 6e 6b 2e 48 6f 74 6b 65 79 20 3d 20 22 43 54 52 4c 2b 53 48 49 46 54 2b 46 22}
		$s3 = {73 65 74 20 57 73 68 53 68 65 6c 6c 20 3d 20 57 53 63 72 69 70 74 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29}
		$s4 = {6f 53 68 65 6c 6c 4c 69 6e 6b 2e 49 63 6f 6e 4c 6f 63 61 74 69 6f 6e 20 3d 20 22 6e 6f 74 65 70 61 64 2e 65 78 65 2c 20 30 22}
		$s5 = {73 65 74 20 6f 53 68 65 6c 6c 4c 69 6e 6b 20 3d 20 57 73 68 53 68 65 6c 6c 2e 43 72 65 61 74 65 53 68 6f 72 74 63 75 74 28 73 74 72 53 54 55 50 20 26 20 22 5c 57 69 6e 44 65 66 65 6e 64 65 72 2e 6c 6e 6b 22 29}
		$s6 = {77 6c 67 2e 64 61 74}
		$s7 = {77 00 6f 00 6f 00 6c 00 67 00 65 00 72 00}
		$s8 = {5b 45 6e 74 65 72 5d}
		$s9 = {5b 43 6f 6e 74 72 6f 6c 5d}

	condition:
		(1 of ( $x* ) and 2 of ( $s* ) ) or ( 6 of ( $s* ) )
}

rule WoolenGoldfish_Generic_2 : hardened
{
	meta:
		description = "Detects a operation Woolen-Goldfish sample - http://goo.gl/NpJpVZ"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/NpJpVZ"
		date = "2015/03/25"
		score = 90
		hash1 = "47b1c9caabe3ae681934a33cd6f3a1b311fd7f9f"
		hash2 = "62172eee1a4591bde2658175dd5b8652d5aead2a"
		hash3 = "7fef48e1303e40110798dfec929ad88f1ad4fbd8"
		hash4 = "c1edf6e3a271cf06030cc46cbd90074488c05564"
		id = "930b928f-ff32-56b2-9e3c-dd80036ff7ef"

	strings:
		$s0 = {6d 6f 64 75 6c 65 73 5c 65 78 70 6c 6f 69 74 73 5c 6c 69 74 74 6c 65 74 6f 6f 6c 73 5c 61 67 65 6e 74 5f 77 72 61 70 70 65 72 5c 72 65 6c 65 61 73 65}

	condition:
		all of them
}

rule WoolenGoldfish_Generic_3 : hardened
{
	meta:
		description = "Detects a operation Woolen-Goldfish sample - http://goo.gl/NpJpVZ"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/NpJpVZ"
		date = "2015/03/25"
		score = 90
		hash1 = "86222ef166474e53f1eb6d7e6701713834e6fee7"
		hash2 = "e8dbcde49c7f760165ebb0cb3452e4f1c24981f5"
		id = "5c227d24-624c-5fb5-a2ea-a971fda8bfba"

	strings:
		$x1 = {2e 2e 2e 20 67 65 74 20 68 65 61 64 65 72 20 46 41 54 41 4c 20 45 52 52 4f 52 20 21 21 21 20 20 25 64 20 62 79 74 65 73 20 72 65 61 64 20 3e 20 68 65 61 64 65 72 5f 73 69 7a 65}
		$x2 = {69 00 6e 00 64 00 65 00 78 00 2e 00 70 00 68 00 70 00 3f 00 63 00 3d 00 25 00 53 00 26 00 72 00 3d 00 25 00 78 00 26 00 75 00 3d 00 31 00 26 00 74 00 3d 00 25 00 53 00}
		$x3 = {63 6f 6e 6e 65 63 74 5f 62 61 63 6b 5f 74 63 70 5f 63 68 61 6e 6e 65 6c 23 64 6f 5f 63 6f 6e 6e 65 63 74 3a 3a 20 45 72 72 6f 72 20 72 65 73 6f 6c 76 69 6e 67 20 63 6f 6e 6e 65 63 74 20 62 61 63 6b 20 68 6f 73 74 6e 61 6d 65}
		$s0 = {6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 20 47 65 74 50 72 6f 63 41 64 64 72 65 73 73 4c 6f 61 64 4c 69 62 72 61 72 79 41 77 73 32 5f 33 32 2e 64 6c 6c}
		$s1 = {43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 2d 00 54 00 79 00 70 00 65 00 3a 00 20 00 6d 00 75 00 6c 00 74 00 69 00 70 00 61 00 72 00 74 00 2f 00 66 00 6f 00 72 00 6d 00 2d 00 64 00 61 00 74 00 61 00 3b 00 20 00 62 00 6f 00 75 00 6e 00 64 00 61 00 72 00 79 00 3d 00 25 00 53 00}
		$s2 = {41 74 74 65 6d 70 74 69 6e 67 20 74 6f 20 75 6e 6c 6f 63 6b 20 75 6e 69 6e 69 74 69 61 6c 69 7a 65 64 20 6c 6f 63 6b 21}
		$s4 = {75 6e 61 62 6c 65 20 74 6f 20 6c 6f 61 64 20 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c}
		$s5 = {69 00 6e 00 64 00 65 00 78 00 2e 00 70 00 68 00 70 00 3f 00 63 00 3d 00 25 00 53 00 26 00 72 00 3d 00 25 00 78 00}
		$s6 = {25 73 20 6c 65 6e 3a 25 64 20}
		$s7 = {45 6e 63 6f 75 6e 74 65 72 65 64 20 65 72 72 6f 72 20 73 65 6e 64 69 6e 67 20 73 79 73 63 61 6c 6c 20 72 65 73 70 6f 6e 73 65 20 74 6f 20 63 6c 69 65 6e 74}
		$s9 = {2f 69 6e 66 6f 2e 64 61 74}
		$s10 = {45 72 72 6f 72 20 65 6e 74 65 72 69 6e 67 20 74 68 72 65 61 64 20 6c 6f 63 6b}
		$s11 = {45 72 72 6f 72 20 65 78 69 74 69 6e 67 20 74 68 72 65 61 64 20 6c 6f 63 6b}
		$s12 = {63 6f 6e 6e 65 63 74 5f 62 61 63 6b 5f 74 63 70 5f 63 68 61 6e 6e 65 6c 5f 69 6e 69 74 3a 3a 20 73 6f 63 6b 65 74 28 29 20 66 61 69 6c 65 64}

	condition:
		(1 of ( $x* ) ) or ( 8 of ( $s* ) )
}

