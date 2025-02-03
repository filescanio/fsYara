rule easterjackpos : hardened
{
	meta:
		author = "Brian Wallace @botnet_hunter"
		author_email = "bwall@ballastsecurity.net"
		date = "2014-09-02"
		description = "Identify JackPOS"
		score = 70

	strings:
		$s1 = {75 70 64 61 74 65 69 6e 74 65 72 76 61 6c 3d}
		$s2 = {63 61 72 64 69 6e 74 65 72 76 61 6c 3d}
		$s3 = {7b 5b 21 31 37 21 5d 7d 7b 5b 21 31 38 21 5d 7d}

	condition:
		all of them
}

