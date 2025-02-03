rule AthenaHTTP : hardened
{
	meta:
		author = "Brian Wallace @botnet_hunter"
		author_email = "bwall@ballastsecurity.net"
		date = "2014-08-09"
		description = "Identify Athena HTTP"

	strings:
		$s1 = {25 73 28 25 73 29}
		$s2 = {74 79 70 65 3a 6f 6e 5f 65 78 65 63}
		$s3 = {75 69 64 3a 25 73}
		$s4 = {70 72 69 76 3a 25 73}
		$s5 = {61 72 63 68 3a 78 25 73}
		$s6 = {67 65 6e 64 3a 25 73}
		$s7 = {63 6f 72 65 73 3a 25 69}
		$s8 = {76 65 72 3a 25 73}
		$s9 = {6e 65 74 3a 25 73}

	condition:
		uint16( 0 ) == 0x5a4d and all of them
}

rule AthenaHTTP_v2 : hardened
{
	meta:
		author = "Jason Jones <jasonjones@arbor.net>"
		description = "Athena HTTP identification"
		source = "https://github.com/arbor/yara/blob/master/athena.yara"

	strings:
		$fmt_str1 = {7c 74 79 70 65 3a 6f 6e 5f 65 78 65 63 7c 75 69 64 3a 25 73 7c 70 72 69 76 3a 25 73 7c 61 72 63 68 3a 78 25 73 7c 67 65 6e 64 3a 25 73 7c 63 6f 72 65 73 3a 25 69 7c 6f 73 3a 25 73 7c 76 65 72 3a 25 73 7c 6e 65 74 3a 25 73 7c}
		$fmt_str2 = {7c 74 79 70 65 3a 72 65 70 65 61 74 7c 75 69 64 3a 25 73 7c 72 61 6d 3a 25 6c 64 7c 62 6b 5f 6b 69 6c 6c 65 64 3a 25 69 7c 62 6b 5f 66 69 6c 65 73 3a 25 69 7c 62 6b 5f 6b 65 79 73 3a 25 69 7c 62 75 73 79 3a 25 73 7c}
		$cmd1 = {66 69 6c 65 73 65 61 72 63 68 2e 73 74 6f 70}
		$cmd2 = {72 61 70 69 64 67 65 74}
		$cmd3 = {6c 61 79 65 72 34 2e}
		$cmd4 = {73 6c 6f 77 6c 6f 72 69 73}
		$cmd5 = {72 75 64 79}

	condition:
		uint16( 0 ) == 0x5a4d and all of ( $fmt_str* ) and 3 of ( $cmd* )
}

rule AthenaIRC : hardened
{
	meta:
		author = "Jason Jones <jasonjones@arbor.net>"
		description = "Athena IRC v1.8.x, 2.x identification"
		source = "https://github.com/arbor/yara/blob/master/athena.yara"

	strings:
		$cmd1 = {64 64 6f 73 2e}
		$cmd2 = {6c 61 79 65 72 34 2e}
		$cmd3 = {77 61 72 2e}
		$cmd4 = {73 6d 61 72 74 76 69 65 77}
		$cmd5 = {66 74 70 2e 75 70 6c 6f 61 64}
		$msg1 = {25 73 20 25 73 20 3a 25 73 20 4c 41 59 45 52 34 20 43 6f 6d 62 6f 20 46 6c 6f 6f 64 3a 20 53 74 6f 70 70 65 64}
		$msg2 = {25 73 20 25 73 20 3a 25 73 20 49 52 43 20 57 61 72 3a 20 46 6c 6f 6f 64 20 73 74 61 72 74 65 64 20 5b 54 79 70 65 3a 20 25 73 20 7c 20 54 61 72 67 65 74 3a 20 25 73 5d}
		$msg3 = {25 73 20 25 73 20 3a 25 73 20 46 54 50 20 55 70 6c 6f 61 64 3a 20 46 61 69 6c 65 64}
		$msg4 = {41 74 68 65 6e 61 20 76 32}
		$msg5 = {25 73 20 25 73 20 3a 25 73 20 45 43 46 20 46 6c 6f 6f 64 3a 20 53 74 6f 70 70 65 64 20 5b 54 6f 74 61 6c 20 43 6f 6e 6e 65 63 74 69 6f 6e 73 3a 20 25 6c 64 20 7c 20 52 61 74 65 3a 20 25 6c 64 20 43 6f 6e 6e 65 63 74 69 6f 6e 73 2f 53 65 63 6f 6e 64 5d}
		$amsg1 = {41 52 4d 45 20 66 6c 6f 6f 64 20 6f 6e 20 25 73 2f 25 73 3a 25 69 20 66 6f 72 20 25 69 20 73 65 63 6f 6e 64 73 20 5b 48 6f 73 74 20 63 6f 6e 66 69 72 6d 65 64 20 76 75 6c 6e 65 72 61 62 6c 65}
		$amsg2 = {20 52 61 70 69 64 20 48 54 54 50 20 43 6f 6d 62 6f 20 66 6c 6f 6f 64 20 6f 6e 20 25 73 3a 25 69 20 66 6f 72 20 25 69 20 73 65 63 6f 6e 64 73}
		$amsg3 = {42 65 67 61 6e 20 66 6c 6f 6f 64 3a 20 25 69 20 63 6f 6e 6e 65 63 74 69 6f 6e 73 20 65 76 65 72 79 20 25 69 20 6d 73 20 74 6f 20 25 73 3a 25 69}
		$amsg4 = {49 50 4b 69 6c 6c 65 72 3e 41 74 68 65 6e 61}
		$amsg5 = {41 74 68 65 6e 61 3d 53 68 69 74 21}
		$amsg6 = {41 74 68 65 6e 61 2d 76 31}
		$amsg7 = {42 54 43 20 77 61 6c 6c 65 74 2e 64 61 74 20 66 69 6c 65 20 66 6f 75 6e 64}
		$amsg8 = {4d 69 6e 65 43 72 61 66 74 20 6c 61 73 74 6c 6f 67 69 6e 20 66 69 6c 65 20 66 6f 75 6e 64}
		$amsg9 = {50 72 6f 63 65 73 73 20 27 25 73 27 20 77 61 73 20 66 6f 75 6e 64 20 61 6e 64 20 73 63 68 65 64 75 6c 65 64 20 66 6f 72 20 64 65 6c 65 74 69 6f 6e 20 75 70 6f 6e 20 6e 65 78 74 20 72 65 62 6f 6f 74}
		$amsg10 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 37 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 31 3b 20 54 72 69 64 65 6e 74 2f 34 2e 30 3b 20 2e 4e 45 54 20 43 4c 52 20 31 2e 31 2e 34 33 32 32 3b 20 2e 4e 45 54 20 43 4c 52 20 32 2e 30 2e 35 30 33 6c 33 3b 20 2e 4e 45 54 20 43 4c 52 20 33 2e 30 2e 34 35 30 36 2e 32 31 35 32 3b 20 2e 4e 45 54 20 43 4c 52 20 33 2e 35 2e 33 30 37 32 39 3b 20 4d 53 4f 66 66 69 63 65 20 31 32 29}
		$amsg11 = {52 61 70 69 64 20 43 6f 6e 6e 65 63 74 2f 44 69 73 63 6f 6e 6e 65 63 74}
		$amsg12 = {42 54 43 20 77 61 6c 6c 65 74 2e 64 61 74 20 66 6f 75 6e 64 2c}
		$acmd1 = {3a 21 61 72 6d 65}
		$acmd2 = {3a 21 6f 70 65 6e 75 72 6c}
		$acmd3 = {3a 21 63 6f 6e 64 69 73}
		$acmd4 = {3a 21 68 74 74 70 63 6f 6d 62 6f}
		$acmd5 = {3a 21 75 72 6c 62 6c 6f 63 6b}
		$acmd6 = {3a 21 75 64 70}
		$acmd7 = {3a 21 62 74 63 77 61 6c 6c 65 74}

	condition:
		uint16( 0 ) == 0x5a4d and ( all of ( $cmd* ) and 3 of ( $msg* ) ) or ( 5 of ( $amsg* ) and 5 of ( $acmd* ) )
}

