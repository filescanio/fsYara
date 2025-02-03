rule MAL_RANSOM_Lorenz_May21_1 : hardened
{
	meta:
		description = "Detects Lorenz Ransomware samples"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research - DACH TE"
		date = "2021-05-04"
		hash1 = "4b1170f7774acfdc5517fbe1c911f2bd9f1af498f3c3d25078f05c95701cc999"
		hash2 = "8258c53a44012f6911281a6331c3ecbd834b6698b7d2dbf4b1828540793340d1"
		hash3 = "c0c99b141b014c8e2a5c586586ae9dc01fd634ea977e2714fbef62d7626eb3fb"
		id = "0b18a4a3-82da-574b-8d10-daf2176448b9"
		score = 75

	strings:
		$x1 = {70 72 6f 63 65 73 73 20 63 61 6c 6c 20 63 72 65 61 74 65 20 22 63 6d 64 2e 65 78 65 20 2f 63 20 73 63 68 74 61 73 6b 73 20 2f 43 72 65 61 74 65 20 2f 46 20 2f 52 55 20 53 79 73 74 65 6d 20 2f 53 43 20 4f 4e 4c 4f 47 4f 4e 20}
		$x2 = {2d 2d 2d 2d 2d 42 45 47 49 4e 20 50 55 42 4c 49 43 20 4b 45 59 2d 2d 2d 2d 2d 4d 49 47 66 4d 41 30 47 43 53 71 47 53 49 62 33 44 51 45 42 41 51 55 41 41 34 47 4e 41 44 43 42 69 51 4b 42 67 51 43 6e 37 66 4c 2f 31 71 73 57 6b 4a 6b 55 74 58 4b 5a 49 4a 4e 71 59 66 6e 56 42 79 56 68 4b}
		$s1 = {70 72 6f 63 65 73 73 20 63 61 6c 6c 20 63 72 65 61 74 65 20 22 63 6d 64 2e 65 78 65 20 2f 63 20 73 63 68 74 61 73 6b 73 20 2f 43 72 65 61 74 65 20 2f 46 20}
		$s2 = {74 77 72 2e 69 6e 69}
		$s3 = {2f 63 20 77 6d 69 63 20 2f 6e 6f 64 65 3a 27}
		$op1 = { 0f 4f d9 81 ff dc 0f 00 00 5f 8d 4b 0? 0f 4e cb 83 fe 3c 5e 5b }
		$op2 = { 6a 02 e8 ?? ?? 0? 00 83 c4 18 83 f8 01 75 01 cc 6a 00 68 ?? ?? 00 00 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 4000KB and ( 1 of ( $x* ) or all of ( $op* ) or 3 of them )
}

