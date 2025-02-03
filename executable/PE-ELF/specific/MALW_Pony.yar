rule pony : hardened
{
	meta:
		author = "Brian Wallace @botnet_hunter"
		author_email = "bwall@ballastsecurity.net"
		date = "2014-08-16"
		description = "Identify Pony"
		score = 50

	strings:
		$s1 = {7b 25 30 38 58 2d 25 30 34 58 2d 25 30 34 58 2d 25 30 32 58 25 30 32 58 2d 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 7d}
		$s2 = {59 55 49 50 57 44 46 49 4c 45 30 59 55 49 50 4b 44 46 49 4c 45 30 59 55 49 43 52 59 50 54 45 44 30 59 55 49 31 2e 30}
		$s3 = {50 4f 53 54 20 25 73 20 48 54 54 50 2f 31 2e 30}
		$s4 = {41 63 63 65 70 74 2d 45 6e 63 6f 64 69 6e 67 3a 20 69 64 65 6e 74 69 74 79 2c 20 2a 3b 71 3d 30}

	condition:
		$s1 and $s2 and $s3 and $s4
}

