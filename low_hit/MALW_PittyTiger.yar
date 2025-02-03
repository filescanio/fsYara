rule PittyTiger : hardened limited
{
	meta:
		author = " (@chort0)"
		description = "Detect PittyTiger Trojan via common strings"

	strings:
		$ptUserAgent = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 36 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 3b 20 53 56 31 29}
		$ptFC001 = {46 43 30 30 31}
		$ptPittyTiger = {50 69 74 74 79 54 69 67 65 72}
		$trjHTMLerr = {74 72 6a 3a 48 54 4d 4c 20 45 72 72 2e}
		$trjworkFunc = {74 72 6a 3a 77 6f 72 6b 46 75 6e 63 20 73 74 61 72 74 2e}
		$trjcmdtout = {74 72 6a 3a 63 6d 64 20 74 69 6d 65 20 6f 75 74 2e}
		$trjThrtout = {74 72 6a 3a 54 68 72 65 61 64 20 74 69 6d 65 20 6f 75 74 2e}
		$trjCrPTdone = {74 72 6a 3a 43 72 65 61 74 65 20 50 54 20 64 6f 6e 65 2e}
		$trjCrPTerr = {74 72 6a 3a 43 72 65 61 74 65 20 50 54 20 65 72 72 6f 72 3a 20 6d 75 74 65 78 20 61 6c 72 65 61 64 79 20 65 78 69 73 74 73 2e}
		$oddPippeFailed = {43 72 65 61 74 65 20 50 69 70 70 65 20 46 61 69 6c 65 64 21}
		$oddXferingFile = {54 72 61 6e 73 66 65 72 69 6e 67 20 46 69 6c 65}
		$oddParasError = {70 75 74 20 50 61 72 61 73 20 45 72 72 6f 72 3a}
		$oddCmdTOutkilled = {43 6d 64 20 54 69 6d 65 20 4f 75 74 2e 2e 43 6d 64 20 68 61 73 20 62 65 65 6e 20 6b 69 6c 6c 65 64 2e}

	condition:
		( any of ( $pt* ) ) and ( any of ( $trj* ) ) and ( any of ( $odd* ) )
}

