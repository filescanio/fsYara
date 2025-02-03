rule HKTL_Khepri_Beacon_Sep21_1 : hardened
{
	meta:
		description = "Detects Khepri C2 framework beacons"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/geemion/Khepri/"
		date = "2021-09-08"
		score = 90
		hash1 = "86c48679db5f4c085fd741ebec5235bc6cf0cdf8ef2d98fd8a689ceb5088f431"
		id = "b2c8aaf7-7953-55a3-8499-565800fa01f1"

	strings:
		$x1 = {4e 54 20 25 64 2e 25 64 20 42 75 69 6c 64 20 25 64 20 20 50 72 6f 64 75 63 74 54 79 70 65 3a 25 73}
		$xe1 = {59 7a 49 75 51 30 31 45 55 45 46 53 51 55 30 75 59 32 31 6b}
		$xe2 = {4d 79 4c 6b 4e 4e 52 46 42 42 55 6b 46 4e 4c 6d 4e 74 5a}
		$xe3 = {6a 4d 69 35 44 54 55 52 51 51 56 4a 42 54 53 35 6a 62 57}
		$sx1 = {63 32 2e 50 72 6f 63 65 73 73 49 74 65 6d 2e 75 73 65 72}
		$sx2 = {63 32 2e 43 4d 44 50 41 52 41 4d 2e 63 6d 64}
		$sx3 = {63 32 2e 44 6f 77 6e 4c 6f 61 64 46 69 6c 65 2e 66 69 6c 65 5f 70 61 74 68}
		$sa1 = {66 69 6c 65 20 73 69 7a 65 20 7a 65 72 6f}
		$sa2 = {63 6d 64 2e 65 78 65 20 2f 63 20}
		$sa3 = {65 72 72 6f 72 20 70 61 72 73 65 20 70 61 72 61 6d}
		$sa4 = {69 6e 6e 65 74 5f 69 70}
		$op1 = { c3 b9 b4 98 49 00 87 01 5d c3 b8 b8 98 49 00 c3 8b ff }
		$op2 = { 8b f1 80 3d 58 97 49 00 00 0f 85 96 00 00 00 33 c0 40 b9 50 97 49 00 87 01 33 db }
		$op3 = { 90 d5 0c 43 00 34 0d 43 00 ea 0c 43 00 7e 0d 43 00 b6 0d 43 00 cc }
		$op4 = { 69 c0 ff 00 00 00 8b 4d c0 23 88 40 7c 49 00 89 4d c0 8b 45 cc 0b 45 c0 89 45 cc 8b 45 d0 }

	condition:
		( uint16( 0 ) == 0x5a4d or uint32be( 0 ) == 0x7f454c46 ) and filesize < 2000KB and ( 1 of ( $x* ) or 2 of ( $sx* ) or all of ( $sa* ) or 3 of ( $op* ) ) or ( filesize < 10MB and 1 of ( $xe* ) ) or 5 of them
}

