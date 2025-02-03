rule Cythosia : hardened
{
	meta:
		author = "Brian Wallace @botnet_hunter"
		author_email = "bwall@ballastsecurity.net"
		date = "2015-03-21"
		description = "Identify Cythosia"

	strings:
		$str1 = {48 00 61 00 72 00 76 00 65 00 73 00 74 00 65 00 72 00 53 00 6f 00 63 00 6b 00 73 00 42 00 6f 00 74 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00}

	condition:
		all of them
}

