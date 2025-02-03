rule Scarcruft_malware_Feb18_1 : hardened
{
	meta:
		description = "Detects Scarcruft malware - February 2018"
		author = "Florian rootpath"
		reference = "https://twitter.com/craiu/status/959477129795731458"
		date = "2018-02-03"
		score = 90
		id = "43a87f2a-cf60-5035-8d40-c360a789a1ac"

	strings:
		$x1 = {64 3a 5c 48 69 67 68 53 63 68 6f 6f 6c 5c 76 65 72 73 69 6f 6e 20 31 33 5c 32 6e 64 42 44 5c 54 2b 4d 5c}
		$x2 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 43 00 20 00 70 00 69 00 6e 00 67 00 20 00 30 00 2e 00 31 00 2e 00 31 00 2e 00 32 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 2000KB and 1 of them
}

