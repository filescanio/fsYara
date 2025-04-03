rule MAL_Payload_F5_BIG_IP_Exploitations_Jul20_1 : hardened limited
{
	meta:
		description = "Detects code found in report on exploits against CVE-2020-5902 F5 BIG-IP vulnerability by NCC group"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://research.nccgroup.com/2020/07/05/rift-f5-networks-k52145254-tmui-rce-vulnerability-cve-2020-5902-intelligence/"
		date = "2020-06-07"
		score = 75
		id = "57705ba1-c0ad-5ca6-8539-44d9da6b5942"

	strings:
		$x1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 72 6d 20 2d 66 20 2f 65 74 63 2f 6c 64 2e 73 6f 2e 70 72 65 6c 6f 61 64 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$x2 = {65 63 68 6f 20 22 2a 20 2a 20 2a 20 2a 20 2a 20 24 4c 44 52}
		$x3 = {2e 73 68 20 2d 6f 20 2f 74 6d 70 2f 69 6e 2e 73 68}
		$x4 = {63 68 6d 6f 64 20 61 2b 78 20 2f 65 74 63 2f 2e 6d 6f 64 75 6c 65 73 2f 2e 74 6d 70}
		$x5 = {63 68 6d 6f 64 20 2b 78 20 2f 76 61 72 2f 6c 6f 67 2f 46 35 2d 6c 6f 67 63 68 65 63 6b}
		$s1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 75 6c 69 6d 69 74 20 2d 6e 20 36 35 35 33 35 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s2 = {2d 73 20 2f 75 73 72 2f 62 69 6e 2f 77 67 65 74 20}
		$s3 = {2e 73 68 20 7c 20 73 68}

	condition:
		filesize < 300KB and ( 1 of ( $x* ) or 3 of them )
}

