rule MAL_Github_Repo_Compromise_MyJino_Ru_Aug22 : hardened
{
	meta:
		description = "Detects URL mentioned in report on compromised Github repositories in August 2022"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/stephenlacy/status/1554697077430505473"
		date = "2022-08-03"
		score = 90
		id = "1eaabad5-d0de-5d17-a5fa-3c638354843d"

	strings:
		$x1 = {((63 75 72 6c 20 68 74 74 70 3a 2f 2f 6f 76 7a 31 2e 6a 31 39 35 34 34 35 31 39 2e 70 72 34 36 6d 2e 76 70 73 2e 6d 79 6a 69 6e 6f 2e 72 75) | (63 00 75 00 72 00 6c 00 20 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6f 00 76 00 7a 00 31 00 2e 00 6a 00 31 00 39 00 35 00 34 00 34 00 35 00 31 00 39 00 2e 00 70 00 72 00 34 00 36 00 6d 00 2e 00 76 00 70 00 73 00 2e 00 6d 00 79 00 6a 00 69 00 6e 00 6f 00 2e 00 72 00 75 00))}
		$x2 = {((68 74 74 70 5f 5f 2e 50 6f 73 74 28 22 68 74 74 70 3a 2f 2f 6f 76 7a 31 2e 6a 31 39 35 34 34 35 31 39 2e 70 72 34 36 6d 2e 76 70 73 2e 6d 79 6a 69 6e 6f 2e 72 75) | (68 00 74 00 74 00 70 00 5f 00 5f 00 2e 00 50 00 6f 00 73 00 74 00 28 00 22 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6f 00 76 00 7a 00 31 00 2e 00 6a 00 31 00 39 00 35 00 34 00 34 00 35 00 31 00 39 00 2e 00 70 00 72 00 34 00 36 00 6d 00 2e 00 76 00 70 00 73 00 2e 00 6d 00 79 00 6a 00 69 00 6e 00 6f 00 2e 00 72 00 75 00))}

	condition:
		1 of them
}

