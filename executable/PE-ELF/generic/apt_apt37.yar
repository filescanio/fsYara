rule APT_NK_Methodology_Artificial_UserAgent_IE_Win7 : hardened
{
	meta:
		author = "Steve Miller aka @stvemillertime"
		description = "Detects hard-coded User-Agent string that has been present in several APT37 malware families."
		hash1 = "e63efbf8624a531bb435b7446dbbfc25"
		score = 45
		id = "a747c908-7af7-5c29-8386-a71db7648061"

	strings:
		$a1 = {4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 6f 77 73 20 4e 54 20 36 2e 31 3b 20 57 4f 57 36 34 3b 20 54 72 69 64 65 6e 74 2f 37 2e 30 3b 20 72 76 3a 31 31 2e 30 29 20 6c 69 6b 65 20 47 65 63 6b 6f}
		$a2 = {4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 6f 77 73 20 4e 54 20 36 2e 31 3b 20 57 4f 57 36 34 3b 20 54 72 69 64 65 6e 74 2f 37 2e 30 3b 20 72 76 3a 31 31 2e 30 29 20 6c 69 6b 65 20 47 65 63 6b 6f 00 00 00 00}
		$fp1 = {45 00 73 00 75 00 6d 00 73 00 6f 00 66 00 74 00}
		$fp2 = {((41 63 75 6e 65 74 69 78) | (41 00 63 00 75 00 6e 00 65 00 74 00 69 00 78 00))}
		$fp3 = {54 41 53 45 52 20 53 59 4e 43}

	condition:
		uint16( 0 ) == 0x5A4D and all of ( $a* ) and not 1 of ( $fp* )
}

