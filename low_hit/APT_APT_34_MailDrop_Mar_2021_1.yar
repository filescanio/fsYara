rule APT_APT_34_MailDrop_Mar_2021_1 : hardened
{
	meta:
		description = "Detect MailDrop malware used by APT34"
		author = "Arkbird_SOLG"
		reference = "Internal Research"
		date = "2021-04-03"
		hash1 = "d6b876d72dba94fc0bacbe1cb45aba493e4b71572a7713a1a0ae844609a72504"
		hash2 = "ebae23be2e24139245cc32ceda4b05c77ba393442482109cc69a6cecc6ad1393"

	strings:
		$EWSInitCom = { 7e ?? 00 00 04 28 ?? 00 00 06 ?? 4f [0-3] 02 7b ?? 00 00 04 28 ?? 00 00 06 28 ?? 00 00 06 02 7b ?? 00 00 04 6f ?? 00 00 06 02 7b ?? 00 00 04 28 ?? 00 00 06 72 ?? 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 06 02 7b ?? 00 00 04 6f ?? 00 00 06 7e ?? 00 00 04 72 ?? 00 00 70 28 ?? 00 00 06 7e 06 00 00 04 28 ?? 00 00 06 [2-4] 00 00 [3-4] 00 00 [3] 00 00 [3] 00 00 [3] 00 00 }
		$EWSCom = { 13 30 ?? 00 ?? 00 00 00 00 00 00 00 02 28 ?? 00 00 ?? 02 03 05 0e 04 0e 05 0e 06 [0-4] 73 ?? 00 00 06 7d ?? 00 00 04 04 [2-6] 00 00 ?? 02 ?? 7d ?? 00 00 04 [0-2] 02 ?? 7d ?? 00 00 04 [2-4] 00 00 [0-18] 04 02 28 ?? 00 00 06 2a }
		$EWSDecrypt = { 13 30 03 00 27 00 00 00 ?? 00 00 11 0f 00 20 00 01 00 00 16 28 ?? 00 00 06 28 ?? 00 00 06 0a 0f 00 1f 10 16 28 ?? 00 00 06 0b 02 06 07 28 ?? 00 00 06 2a }
		$EWSRandomData = { 1b 30 ?? 00 ?? 00 00 00 ?? 00 00 11 02 19 28 ?? 00 00 0a 0a 16 0b ?? 35 [0-3] 06 16 6a 16 6f ?? 00 00 0a 26 06 6f ?? 00 00 0a d4 8d ?? 00 00 01 0c 7e ?? 00 00 04 08 6f ?? 00 00 0a 06 08 16 06 6f ?? 00 00 0a b7 6f ?? 00 00 0a 07 17 d6 0b 07 1f 32 32 c6 [5-11] 06 6f ?? 00 00 0a dc 2a [0-1] 01 10 00 00 02 00 08 00 }
		$s1 = {48 4d 69 63 72 6f 73 6f 66 74 20 4f 66 66 69 63 65 2f 31 35 2e 30 20 28 57 69 6e 64 6f 77 73 20 4e 54 20 7b 30 7d 3b 20 4d 69 63 72 6f 73 6f 66 74 20 4f 75 74 6c 6f 6f 6b 20 31 35 2e 30 2e 34 36 37 35 3b 20 50 72 6f 29}
		$s2 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 7b 00 30 00 7d 00 2f 00 65 00 77 00 73 00 2f 00 65 00 78 00 63 00 68 00 61 00 6e 00 67 00 65 00 2e 00 61 00 73 00 6d 00 78 00}
		$s3 = {53 65 6e 64 5f 4c 6f 67}
		$s4 = {43 68 65 63 6b 45 57 53 43 6f 6e 6e 65 63 74 69 6f 6e}
		$s5 = {44 00 6f 00 6e 00 65 00 3a 00 44 00}
		$s6 = {45 78 65 63 41 6c 6c 43 6d 64 73}
		$s7 = {45 78 63 68 61 6e 67 65 55 72 69}
		$s8 = {67 65 74 5f 63 6d 64 53 75 62 6a 65 63 74}

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 20KB and 2 of ( $EWS* ) and 5 of ( $s* )
}

