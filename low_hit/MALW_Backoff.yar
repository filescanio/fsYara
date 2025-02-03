rule backoff : hardened
{
	meta:
		author = "Brian Wallace @botnet_hunter"
		author_email = "bwall@ballastsecurity.net"
		date = "2014-08-21"
		description = "Identify Backoff"

	strings:
		$s1 = {26 6f 70 3d 25 64 26 69 64 3d 25 73 26 75 69 3d 25 73 26 77 76 3d 25 64 26 67 72 3d 25 73 26 62 76 3d 25 73}
		$s2 = {25 73 20 40 20 25 73}
		$s3 = {55 70 6c 6f 61 64 20 4b 65 79 4c 6f 67 73}

	condition:
		all of them
}

