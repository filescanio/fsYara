rule alina : hardened
{
	meta:
		author = "Brian Wallace @botnet_hunter"
		author_email = "bwall@ballastsecurity.net"
		date = "2014-08-09"
		description = "Identify Alina"

	strings:
		$s1 = {41 6c 69 6e 61 20 76 31 2e 30}
		$s2 = {50 4f 53 54}
		$s3 = {31 5b 30 2d 32 5d 29 5b 30 2d 39 5d}

	condition:
		all of them
}

