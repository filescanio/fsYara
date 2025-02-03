rule RAN_CryLock_Oct_2020_1 : hardened
{
	meta:
		description = "Detect CryLock ransomware V2.0.0"
		author = "Arkbird_SOLG"
		reference1 = "https://twitter.com/Kangxiaopao/status/1316334926728318977"
		reference2 = "https://twitter.com/JAMESWT_MHT/status/1316426560803680257"
		date = "2020-10-14"
		hash1 = "04d8109c6c78055d772c01fefe1e5f48a70f2a65535cff17227b5a2c8506b831"

	strings:
		$s1 = {41 6c 6c 20 63 6f 6d 6d 61 6e 64 73 20 73 65 6e 64 65 64 20 74 6f 20 65 78 65 63 75 74 69 6f 6e}
		$s2 = {50 72 6f 63 65 73 73 65 73 62 6c 61 63 6b 6c 69 73 74 31}
		$s3 = {45 78 65 63 75 74 65 20 61 6c 6c}
		$s4 = {63 6f 6e 66 69 67 2e 74 78 74}
		$debug1 = {50 72 6f 63 65 73 73 65 64 20 66 69 6c 65 73 3a 20}
		$debug2 = {4e 65 78 74 20 2d 2d 3e}
		$debug3 = {53 74 61 74 75 73 3a 20 73 63 61 6e 20 6e 65 74 77 6f 72 6b}
		$debug4 = { 49 45 28 41 4c 28 22 25 73 22 2c 34 29 2c 22 41 4c 28 5c 22 25 30 3a 73 5c 22 2c 33 29 22 2c 22 4a 4b 28 5c 22 25 31 3a 73 5c 22 2c 5c 22 25 30 3a 73 5c 22 29 22 29 }
		$debug5 = { 4a 75 6d 70 49 44 28 22 22 2c 22 25 73 22 29 }
		$debug6 = { 45 6e 63 72 79 70 74 65 64 20 62 79 20 42 6c 61 63 6b 52 61 62 62 69 74 2e 20 28 [3-10] 29 }
		$ran1 = {77 00 5f 00 74 00 6f 00 5f 00 64 00 65 00 63 00 72 00 79 00 70 00 74 00 2e 00 68 00 74 00 61 00}
		$ran2 = {3c 25 55 4e 44 45 43 52 59 50 54 5f 44 41 54 45 54 49 4d 45 25 3e}
		$ran3 = {3c 25 53 54 41 52 54 5f 44 41 54 45 54 49 4d 45 25 3e}
		$ran4 = {3c 25 4d 41 49 4e 5f 43 4f 4e 54 41 43 54 25 3e}
		$ran5 = {3c 25 52 45 53 45 52 56 45 5f 43 4f 4e 54 41 43 54 25 3e}
		$ran6 = {3c 25 48 49 44 25 3e}

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 300KB and 3 of ( $s* ) and 4 of ( $debug* ) and 4 of ( $ran* )
}

