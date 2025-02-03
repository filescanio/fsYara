rule Metasploit_Payload : refined hardened
{
	meta:
		author = "https://www.twitter.com/SadFud75"
		information = "Detection of payloads generated with metasploit"
		socre = 65

	strings:
		$s1 = {2d 63 6f 6d 2e 6d 65 74 61 73 70 6c 6f 69 74 2e 6d 65 74 65 72 70 72 65 74 65 72 2e 41 6e 64 72 6f 69 64 4d 65 74 65 72 70 72 65 74 65 72}
		$s2 = {2c 4c 63 6f 6d 2f 6d 65 74 61 73 70 6c 6f 69 74 2f 73 74 61 67 65 2f 4d 61 69 6e 42 72 6f 61 64 63 61 73 74 52 65 63 65 69 76 65 72 3b}
		$s3 = {23 4c 63 6f 6d 2f 6d 65 74 61 73 70 6c 6f 69 74 2f 73 74 61 67 65 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 3b}
		$s4 = {4c 63 6f 6d 2f 6d 65 74 61 73 70 6c 6f 69 74 2f 73 74 61 67 65 2f 50 61 79 6c 6f 61 64 3b}
		$s5 = {4c 63 6f 6d 2f 6d 65 74 61 73 70 6c 6f 69 74 2f 73 74 61 67 65 2f 61 3b}
		$s6 = {4c 63 6f 6d 2f 6d 65 74 61 73 70 6c 6f 69 74 2f 73 74 61 67 65 2f 63 3b}
		$s7 = {4c 63 6f 6d 2f 6d 65 74 61 73 70 6c 6f 69 74 2f 73 74 61 67 65 2f 62 3b}

	condition:
		any of them
}

