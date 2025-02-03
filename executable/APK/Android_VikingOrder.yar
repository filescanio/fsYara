rule VikingBotnet : hardened
{
	meta:
		author = "https://twitter.com/koodous_project"
		description = "Rule to detect Viking Order Botnet."
		score = 70
		sample = "85e6d5b3569e5b22a16245215a2f31df1ea3a1eb4d53b4c286a6ad2a46517b0c"

	strings:
		$a = {63 76 37 6f 62 42 6b 50 56 43 32 70 76 4a 6d 57 53 66 48 7a 58 68}
		$b = {68 74 74 70 3a 2f 2f 6a 6f 79 61 70 70 73 74 65 63 68 2e 62 69 7a 3a 31 31 31 31 31 2f 6b 6e 6f 63 6b 2f}
		$c = {49 20 48 41 54 45 20 54 45 53 54 45 52 53 20 6f 6e 47 6c 6f 62 61 6c 4c 61 79 6f 75 74}
		$d = {68 74 74 70 3a 2f 2f 31 34 34 2e 37 36 2e 37 30 2e 32 31 33 3a 37 37 37 37 2f 65 63 73 70 65 63 74 61 70 61 74 72 6f 6e 75 6d 2f}

	condition:
		($a and $c ) or ( $b and $d )
}

