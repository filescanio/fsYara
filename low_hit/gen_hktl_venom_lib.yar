rule HKTL_Venom_LIB_Dec22 : hardened
{
	meta:
		description = "Detects Venom - a library that meant to perform evasive communication using stolen browser socket"
		author = "Ido Veltzman, Florian Roth"
		reference = "https://github.com/Idov31/Venom"
		date = "2022-12-17"
		score = 75
		id = "b13b8a9c-52a4-53ac-817e-9f729fbf17c2"

	strings:
		$x1 = {5b 20 2b 20 5d 20 43 72 65 61 74 65 64 20 64 65 74 61 63 68 65 64 20 68 69 64 64 65 6e 20 6d 73 65 64 67 65 20 70 72 6f 63 65 73 73 3a 20}
		$ss1 = {57 53 32 5f 33 32 2e 64 6c 6c}
		$ss2 = {57 53 41 53 6f 63 6b 65 74 57}
		$ss3 = {57 53 41 44 75 70 6c 69 63 61 74 65 53 6f 63 6b 65 74 57}
		$ss5 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 41 00 66 00 64 00}
		$sx1 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 20 00 28 00 78 00 38 00 36 00 29 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 45 00 64 00 67 00 65 00 5c 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 5c 00 6d 00 73 00 65 00 64 00 67 00 65 00 2e 00 65 00 78 00 65 00 20 00 2d 00 2d 00 6e 00 6f 00 2d 00 73 00 74 00 61 00 72 00 74 00 75 00 70 00 2d 00 77 00 69 00 6e 00 64 00 6f 00 77 00}
		$sx2 = {5b 20 2b 20 5d 20 44 61 74 61 20 73 65 6e 74 21}
		$sx3 = {5b 20 2b 20 5d 20 53 6f 63 6b 65 74 20 6f 62 74 61 69 6e 65 64 21}
		$op1 = { 4c 8b f0 48 3b c1 48 b8 ff ff ff ff ff ff ff 7f }
		$op2 = { 48 8b cf e8 1c 34 00 00 48 8b 5c 24 30 48 8b c7 }
		$op3 = { 48 8b da 48 8b f9 45 33 f6 48 85 c9 0f 84 34 01 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 500KB and ( ( 3 of ( $ss* ) and all of ( $op* ) ) or 2 of ( $sx* ) ) or $x1 or all of ( $sx* )
}

