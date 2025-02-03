rule BlackWorm : hardened
{
	meta:
		author = "Brian Wallace @botnet_hunter"
		author_email = "bwall@ballastsecurity.net"
		date = "2015-05-20"
		description = "Identify BlackWorm"

	strings:
		$str1 = {6d 5f 43 6f 6d 70 75 74 65 72 4f 62 6a 65 63 74 50 72 6f 76 69 64 65 72}
		$str2 = {4d 79 57 65 62 53 65 72 76 69 63 65 73}
		$str3 = {67 65 74 5f 45 78 65 63 75 74 61 62 6c 65 50 61 74 68}
		$str4 = {67 65 74 5f 57 65 62 53 65 72 76 69 63 65 73}
		$str5 = {4d 79 2e 57 65 62 53 65 72 76 69 63 65 73}
		$str6 = {4d 79 2e 55 73 65 72}
		$str7 = {6d 5f 55 73 65 72 4f 62 6a 65 63 74 50 72 6f 76 69 64 65 72}
		$str8 = {44 65 6c 65 67 61 74 65 43 61 6c 6c 62 61 63 6b}
		$str9 = {54 61 72 67 65 74 4d 65 74 68 6f 64}
		$str10 = {30 00 30 00 30 00 30 00 30 00 34 00 62 00 30 00}
		$str11 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00}

	condition:
		all of them
}

