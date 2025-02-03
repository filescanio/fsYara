rule MiniAsp3_mem : memory hardened
{
	meta:
		author = "chort (@chort0)"
		description = "Detect MiniASP3 in memory"

	strings:
		$pdb = {4d 69 6e 69 41 73 70 33 5c 52 65 6c 65 61 73 65 5c 4d 69 6e 69 41 73 70 2e 70 64 62}
		$httpAbout = {68 74 74 70 3a 2f 2f 25 73 2f 61 62 6f 75 74 2e 68 74 6d}
		$httpResult = {68 74 74 70 3a 2f 2f 25 73 2f 72 65 73 75 6c 74 5f 25 73 2e 68 74 6d}
		$msgInetFail = {6f 70 65 6e 20 69 6e 74 65 72 6e 65 74 20 66 61 69 6c 65 64 e2 80 a6}
		$msgRunErr = {72 75 6e 20 65 72 72 6f 72 21}
		$msgRunOk = {72 75 6e 20 6f 6b 21}
		$msgTimeOutM0 = {74 69 6d 65 20 6f 75 74 2c 63 68 61 6e 67 65 20 74 6f 20 6d 6f 64 65 20 30}
		$msgCmdNull = {63 6f 6d 6d 61 6e 64 20 69 73 20 6e 75 6c 6c 21}

	condition:
		($pdb and ( all of ( $http* ) ) and any of ( $msg* ) )
}

