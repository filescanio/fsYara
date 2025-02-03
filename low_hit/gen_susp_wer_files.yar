rule SUSP_WER_Critical_HeapCorruption : hardened
{
	meta:
		description = "Detects a crashed application that crashed due to a heap corruption error (could be a sign of exploitation)"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/cyb3rops/status/1185459425710092288"
		date = "2019-10-18"
		score = 45
		id = "2b1dad5f-cc2c-5d8c-8275-ebb56d079895"

	strings:
		$a1 = {52 00 65 00 70 00 6f 00 72 00 74 00 49 00 64 00 65 00 6e 00 74 00 69 00 66 00 69 00 65 00 72 00 3d 00}
		$a2 = {2e 00 4e 00 61 00 6d 00 65 00 3d 00 46 00 61 00 75 00 6c 00 74 00 20 00 4d 00 6f 00 64 00 75 00 6c 00 65 00 20 00 4e 00 61 00 6d 00 65 00}
		$s1 = {63 00 30 00 30 00 30 00 30 00 33 00 37 00 34 00}

	condition:
		( uint32be( 0 ) == 0x56006500 or uint32be( 0 ) == 0xfffe5600 ) and all of them
}

rule SUSP_WER_Suspicious_Crash_Directory : hardened limited
{
	meta:
		description = "Detects a crashed application executed in a suspicious directory"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/cyb3rops/status/1185585050059976705"
		date = "2019-10-18"
		score = 45
		id = "bf91e20c-aa35-5b13-86ed-a63e6fb4d1a2"

	strings:
		$a1 = {52 00 65 00 70 00 6f 00 72 00 74 00 49 00 64 00 65 00 6e 00 74 00 69 00 66 00 69 00 65 00 72 00 3d 00}
		$a2 = {2e 00 4e 00 61 00 6d 00 65 00 3d 00 46 00 61 00 75 00 6c 00 74 00 20 00 4d 00 6f 00 64 00 75 00 6c 00 65 00 20 00 4e 00 61 00 6d 00 65 00}
		$a3 = {41 00 70 00 70 00 50 00 61 00 74 00 68 00 3d 00}
		$l1 = {41 00 70 00 70 00 50 00 61 00 74 00 68 00 3d 00 43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00}
		$l2 = {41 00 70 00 70 00 50 00 61 00 74 00 68 00 3d 00 43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00}
		$l3 = {41 00 70 00 70 00 50 00 61 00 74 00 68 00 3d 00 43 00 3a 00 5c 00 50 00 79 00 74 00 68 00 6f 00 6e 00}
		$l4 = {41 00 70 00 70 00 50 00 61 00 74 00 68 00 3d 00 43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00}
		$s6 = {41 00 70 00 70 00 50 00 61 00 74 00 68 00 3d 00 43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 50 00 75 00 62 00 6c 00 69 00 63 00 5c 00}
		$s7 = {41 00 70 00 70 00 50 00 61 00 74 00 68 00 3d 00 43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5c 00}
		$s8 = /AppPath=C:\\Users\\[^\\]{1,64}\\AppData\\(Local|Roaming)\\[^\\]{1,64}\.exe/ wide nocase

	condition:
		( uint32be( 0 ) == 0x56006500 or uint32be( 0 ) == 0xfffe5600 ) and all of ( $a* ) and ( not 1 of ( $l* ) or 1 of ( $s* ) )
}

