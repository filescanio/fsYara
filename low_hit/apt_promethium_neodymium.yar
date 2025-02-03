rule PROMETHIUM_NEODYMIUM_Malware_1 : hardened
{
	meta:
		description = "Detects PROMETHIUM and NEODYMIUM malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/8abDE6"
		date = "2016-12-14"
		hash1 = "e12031da58c0b08e8b610c3786ca2b66fcfea8ddc9ac558d08a29fd27e95a3e7"
		id = "21e858b1-2cfa-5757-96f0-7c44a5da6898"

	strings:
		$s1 = {63 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 73 00 79 00 73 00 77 00 69 00 6e 00 64 00 78 00 72 00 33 00 32 00 2e 00 64 00 6c 00 6c 00}
		$s2 = {63 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 65 00 6d 00 70 00 5c 00 54 00 72 00 75 00 65 00 43 00 72 00 79 00 70 00 74 00 2d 00 53 00 65 00 74 00 75 00 70 00 2d 00 37 00 2e 00 31 00 61 00 2d 00 74 00 61 00 6d 00 69 00 6e 00 64 00 69 00 72 00 2e 00 65 00 78 00 65 00}
		$s3 = {25 00 73 00 5c 00 73 00 73 00 6c 00 65 00 61 00 79 00 33 00 32 00 2e 00 64 00 6c 00 6c 00}
		$s4 = {25 00 73 00 5c 00 6c 00 69 00 62 00 65 00 61 00 79 00 33 00 32 00 2e 00 64 00 6c 00 6c 00}
		$s5 = {25 00 73 00 5c 00 66 00 70 00 72 00 6f 00 74 00 33 00 32 00 2e 00 65 00 78 00 65 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 10000KB and 3 of them ) or ( all of them )
}

rule PROMETHIUM_NEODYMIUM_Malware_2 : hardened
{
	meta:
		description = "Detects PROMETHIUM and NEODYMIUM malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/8abDE6"
		date = "2016-12-14"
		hash1 = "1aef507c385a234e8b10db12852ad1bd66a04730451547b2dcb26f7fae16e01f"
		id = "5858541b-c394-5be8-9db3-fcff66f635de"

	strings:
		$s1 = {77 69 6e 61 73 79 73 33 32 2e 65 78 65}
		$s2 = {61 6c 67 33 32 2e 65 78 65}
		$s3 = {77 6d 73 72 76 33 32 2e 65 78 65}
		$s4 = {76 6d 6e 61 74 33 32 2e 65 78 65}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 2000KB and 1 of them ) or ( 3 of them )
}

rule PROMETHIUM_NEODYMIUM_Malware_3 : hardened
{
	meta:
		description = "Detects PROMETHIUM and NEODYMIUM malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/8abDE6"
		date = "2016-12-14"
		hash1 = "2f98ac11c78ad1b4c5c5c10a88857baf7af43acb9162e8077709db9d563bcf02"
		id = "bff79813-0d72-50d9-9676-794801edc34b"

	strings:
		$s1 = {25 73 20 53 73 6c 48 61 6e 64 73 68 61 6b 65 44 6f 6e 65 28 25 64 29 20 25 64 2e 20 53 65 63 75 72 65 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 77 69 74 68 20 25 73 2c 20 63 69 70 68 65 72 20 25 73 2c 20 25 64 20 73 65 63 72 65 74 20 62 69 74 73 20 28 25 64 20 74 6f 74 61 6c 29 2c 20 73 65 73 73 69 6f 6e 20 72 65 75 73 65 64 3d 25 73}
		$s2 = {6d 76 68 6f 73 74 33 32 2e 64 6c 6c}
		$s3 = {73 64 77 69 6e 33 32 2e 64 6c 6c}
		$s4 = {6f 66 78 36 34 2e 64 6c 6c}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 2000KB and 2 of them ) or ( all of them )
}

rule PROMETHIUM_NEODYMIUM_Malware_4 : hardened
{
	meta:
		description = "Detects PROMETHIUM and NEODYMIUM malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/8abDE6"
		date = "2016-12-14"
		hash1 = "15ededb19ec5ab6f03db1106d2ccdeeacacdb8cd708518d065cacb1b0d7e955d"
		id = "4e926b1c-bf10-5337-8c3a-964008a37d8b"

	strings:
		$s1 = {63 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 65 00 6d 00 70 00 5c 00 77 00 69 00 6e 00 72 00 61 00 72 00 2e 00 65 00 78 00 65 00}
		$s2 = {69 6e 66 6f 40 61 61 64 6f 62 65 74 65 63 68 2e 63 6f 6d}
		$s3 = {25 00 73 00 5c 00 73 00 73 00 6c 00 65 00 61 00 79 00 33 00 32 00 2e 00 64 00 6c 00 6c 00}
		$s4 = {25 00 73 00 5c 00 6c 00 69 00 62 00 65 00 61 00 79 00 33 00 32 00 2e 00 64 00 6c 00 6c 00}
		$s5 = {25 00 73 00 5c 00 66 00 70 00 72 00 6f 00 74 00 33 00 32 00 2e 00 65 00 78 00 65 00}
		$s6 = {41 44 4f 42 45 20 43 6f 72 70 2e 31}
		$s7 = {41 64 6f 62 65 20 46 6c 61 73 68 20 50 6c 61 79 65 72 31 22 30 20}
		$s8 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 49 00 6e 00 64 00 65 00 78 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 700KB and 4 of them ) or ( 6 of them )
}

rule PROMETHIUM_NEODYMIUM_Malware_5 : hardened
{
	meta:
		description = "Detects PROMETHIUM and NEODYMIUM malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/8abDE6"
		date = "2016-12-14"
		hash1 = "a8b7e3edaa18c6127e98741503c3a2a66b7720d2abd967c94b8a5f2e99575ac5"
		id = "4bd60f61-a595-5289-9595-a7e33f265748"

	strings:
		$s1 = {57 00 69 00 6e 00 78 00 73 00 79 00 73 00 2e 00 65 00 78 00 65 00}
		$s2 = {25 00 73 00 5c 00 73 00 73 00 6c 00 65 00 61 00 79 00 33 00 32 00 2e 00 64 00 6c 00 6c 00}
		$s3 = {25 00 73 00 5c 00 6c 00 69 00 62 00 65 00 61 00 79 00 33 00 32 00 2e 00 64 00 6c 00 6c 00}
		$s4 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 49 00 6e 00 64 00 65 00 78 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00}
		$s5 = {3c 46 20 52 41 54}
		$s6 = {57 00 49 00 4e 00 49 00 4e 00 44 00 58 00 2d 00 30 00 38 00 38 00 46 00 41 00 38 00 34 00 30 00 2d 00 42 00 31 00 30 00 44 00 2d 00 31 00 31 00 44 00 33 00 2d 00 42 00 43 00 33 00 36 00 2d 00 30 00 30 00 36 00 30 00 36 00 37 00 37 00 30 00 39 00 36 00 37 00 34 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 5000KB and 3 of them )
}

rule PROMETHIUM_NEODYMIUM_Malware_6 : hardened
{
	meta:
		description = "Detects PROMETHIUM and NEODYMIUM malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/8abDE6"
		date = "2016-12-14"
		hash1 = "dbd8cbbaf59d19cf7566042945e36409cd090bc711e339d3f2ec652bc26d6a03"
		id = "0f36eb56-39d8-536c-93ff-4a2352163612"

	strings:
		$s1 = {63 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 73 00 79 00 73 00 77 00 69 00 6e 00 64 00 78 00 72 00 33 00 32 00 2e 00 64 00 6c 00 6c 00}
		$s2 = {63 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 65 00 6d 00 70 00 5c 00 54 00 72 00 75 00 65 00 43 00 72 00 79 00 70 00 74 00 2d 00 37 00 2e 00 32 00 2e 00 65 00 78 00 65 00}
		$s3 = {25 00 73 00 5c 00 73 00 73 00 6c 00 65 00 61 00 79 00 33 00 32 00 2e 00 64 00 6c 00 6c 00}
		$s4 = {25 00 73 00 5c 00 6c 00 69 00 62 00 65 00 61 00 79 00 33 00 32 00 2e 00 64 00 6c 00 6c 00}
		$s5 = {25 00 73 00 5c 00 66 00 70 00 72 00 6f 00 74 00 33 00 32 00 2e 00 65 00 78 00 65 00}
		$s6 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 49 00 6e 00 64 00 65 00 78 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 7000KB and 4 of them )
}

