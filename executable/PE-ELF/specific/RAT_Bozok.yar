rule Bozok : RAT hardened limited
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		score = 60
		ref = "http://malwareconfig.com/stats/Bozok"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = {67 65 74 56 65 72}
		$b = {53 74 61 72 74 56 4e 43}
		$c = {53 65 6e 64 43 61 6d 4c 69 73 74}
		$d = {75 6e 74 50 6c 75 67 69 6e}
		$e = {67 65 74 68 6f 73 74 62 79 6e 61 6d 65}

	condition:
		all of them
}

