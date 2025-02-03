rule diamond_fox : hardened
{
	meta:
		author = "Brian Wallace @botnet_hunter"
		author_email = "bwall@ballastsecurity.net"
		date = "2015-08-22"
		description = "Identify DiamondFox"

	strings:
		$s1 = {55 50 44 41 54 45 5f 42}
		$s2 = {55 4e 49 53 54 41 4c 4c 5f 42}
		$s3 = {53 5f 50 52 4f 54 45 43 54}
		$s4 = {50 5f 57 41 4c 4c 45 54}
		$s5 = {47 52 5f 43 4f 4d 4d 41 4e 44}
		$s6 = {46 54 50 55 50 4c 4f 41 44}

	condition:
		all of them
}

