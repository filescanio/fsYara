rule Crimson : RAT hardened
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		Description = "Crimson Rat"
		date = "2015/05"
		ref = "http://malwareconfig.com/stats/Crimson"
		maltype = "Remote Access Trojan"
		filetype = "jar"

	strings:
		$a1 = {63 6f 6d 2f 63 72 69 6d 73 6f 6e 2f 50 4b}
		$a2 = {63 6f 6d 2f 63 72 69 6d 73 6f 6e 2f 62 6f 6f 74 73 74 72 61 70 4a 61 72 2f 50 4b}
		$a3 = {63 6f 6d 2f 63 72 69 6d 73 6f 6e 2f 70 65 72 6d 61 4a 61 72 4d 75 6c 74 69 2f 50 65 72 6d 61 4a 61 72 52 65 70 6f 72 74 65 72 24 31 2e 63 6c 61 73 73 50 4b}
		$a4 = {63 6f 6d 2f 63 72 69 6d 73 6f 6e 2f 75 6e 69 76 65 72 73 61 6c 2f 63 6f 6e 74 61 69 6e 65 72 73 2f 4b 65 79 6c 6f 67 67 65 72 4c 6f 67 2e 63 6c 61 73 73 50 4b}
		$a5 = {63 6f 6d 2f 63 72 69 6d 73 6f 6e 2f 75 6e 69 76 65 72 73 61 6c 2f 55 70 6c 6f 61 64 54 72 61 6e 73 66 65 72 2e 63 6c 61 73 73 50 4b}

	condition:
		all of ( $a* )
}

