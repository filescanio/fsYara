rule locdoor_ransomware : hardened
{
	meta:
		description = "Rule to detect Locdoor/DryCry"
		author = "Marc Rivero | @seifreed"
		reference = "https://twitter.com/leotpsc/status/1036180615744376832"

	strings:
		$s1 = {63 6f 70 79 20 22 4c 6f 63 64 6f 6f 72 2e 65 78 65 22 20 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 55 70 5c 74 65 6d 70 30 30 30 30 30 30 30 30 2e 65 78 65 22}
		$s2 = {63 6f 70 79 20 77 73 63 72 69 70 74 2e 76 62 73 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 55 70 5c 77 73 63 72 69 70 74 2e 76 62 73}
		$s3 = {21 21 20 59 6f 75 72 20 63 6f 6d 70 75 74 65 72 27 73 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 21 20 59 6f 75 72 20 63 6f 6d 70 75 74 65 72 27 73 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 21}
		$s4 = {65 63 68 6f 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 41 50 49 2e 53 70 56 6f 69 63 65 22 29 2e 53 70 65 61 6b 20 22 59 6f 75 72 20 63 6f 6d 70 75 74 65 72 27 73 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 21 20}
		$s5 = {21 20 59 6f 75 72 20 63 6f 6d 70 75 74 65 72 27 73 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 21 20}
		$s7 = {54 68 69 73 20 70 72 6f 67 72 61 6d 20 69 73 20 6e 6f 74 20 73 75 70 70 6f 72 74 65 64 20 6f 6e 20 79 6f 75 72 20 6f 70 65 72 61 74 69 6e 67 20 73 79 73 74 65 6d 2e}
		$s8 = {65 63 68 6f 20 59 6f 75 72 20 63 6f 6d 70 75 74 65 72 27 73 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 74 6f 20 4c 6f 63 64 6f 6f 72 20 52 61 6e 73 6f 6d 77 61 72 65 21 20 54 6f 20 6d 61 6b 65 20 61 20 72 65 63 6f 76 65 72 79 20 67 6f 20 74 6f 20 6c 6f 63 61 6c 62 69 74 63 6f 69 6e 73 2e 63 6f 6d 20 61 6e 64 20 63 72 65 61 74 65 20 61 20 77 61}
		$s9 = {50 6c 65 61 73 65 20 65 6e 74 65 72 20 74 68 65 20 70 61 73 73 77 6f 72 64 2e}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 600KB ) and all of them
}

