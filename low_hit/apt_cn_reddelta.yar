rule APT_CN_MAL_RedDelta_Shellcode_Loader_Oct20_1 : hardened
{
	meta:
		description = "Detects Red Delta samples"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/JAMESWT_MHT/status/1316387482708119556"
		date = "2020-10-14"
		hash1 = "30b2bbce0ca4cb066721c94a64e2c37b7825dd72fc19c20eb0ab156bea0f8efc"
		hash2 = "42ed73b1d5cc49e09136ec05befabe0860002c97eb94e9bad145e4ea5b8be2e2"
		hash3 = "480a8c883006232361c5812af85de9799b1182f1b52145ccfced4fa21b6daafa"
		hash4 = "7ea7c6406c5a80d3c15511c4d97ec1e45813e9c58431f386710d0486c4898b98"
		id = "47417488-e843-5346-9baa-fcce30b884d1"

	strings:
		$x1 = {49 6e 6a 65 63 74 53 68 65 6c 6c 43 6f 64 65}
		$s1 = {((44 6f 74 4e 65 74 4c 6f 61 64 65 72 2e 65 78 65) | (44 00 6f 00 74 00 4e 00 65 00 74 00 4c 00 6f 00 61 00 64 00 65 00 72 00 2e 00 65 00 78 00 65 00))}
		$s2 = {63 6c 69 70 62 6f 61 72 64 69 6e 6a 65 63 74}
		$s3 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 2e 00 70 00 68 00 70 00 3f 00 72 00 61 00 77 00 3d 00 31 00}
		$s4 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 41 00 70 00 70 00 43 00 6f 00 6d 00 70 00 61 00 74 00 46 00 6c 00 61 00 67 00 73 00 5c 00 54 00 65 00 6c 00 65 00 6d 00 65 00 74 00 72 00 79 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 6c 00 65 00 72 00 5c 00 4c 00 65 00 76 00 69 00 6e 00 74 00}
		$s5 = {46 00 6c 00 61 00 73 00 68 00 55 00 70 00 64 00 61 00 74 00 65 00 2e 00 65 00 78 00 65 00}
		$s6 = {72 61 77 5f 63 63 5f 75 72 6c}
		$op1 = { 48 8b 4c 24 78 48 89 01 e9 1a ff ff ff 48 8b 44 }
		$op2 = { ff ff 00 00 77 2a 8b 44 24 38 8b 8c 24 98 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 200KB and $x1 or 3 of them
}

rule APT_CN_MAL_RedDelta_Shellcode_Loader_Oct20_2 : hardened
{
	meta:
		description = "Detects Red Delta samples"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/JAMESWT_MHT/status/1316387482708119556"
		date = "2020-10-14"
		hash1 = "260ebbf392498d00d767a5c5ba695e1a124057c1c01fff2ae76db7853fe4255b"
		hash2 = "9ccb4ed133be5c9c554027347ad8b722f0b4c3f14bfd947edfe75a015bf085e5"
		hash3 = "b3fd750484fca838813e814db7d6491fea36abe889787fb7cf3fb29d9d9f5429"
		id = "acb1024a-64af-51ac-84c8-7fe9a5bd4538"

	strings:
		$x1 = {5c 00 43 00 4c 00 52 00 4c 00 6f 00 61 00 64 00 65 00 72 00 2e 00 65 00 78 00 65 00}
		$x2 = {2f 63 61 6c 6c 62 61 63 6b 2e 70 68 70 3f 74 6f 6b 65 6e 3d 25 73 26 63 6f 6d 70 75 74 65 72 6e 61 6d 65 3d 25 73 26 75 73 65 72 6e 61 6d 65 3d 25 73}
		$s1 = {44 00 6f 00 74 00 4e 00 65 00 74 00 4c 00 6f 00 61 00 64 00 65 00 72 00 2e 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00}
		$s2 = {2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 3f 61 70 69 3d 34 30}
		$s3 = {67 65 74 20 25 64 20 55 52 4c 44 69 72}
		$s4 = {52 65 61 64 20 63 6f 64 65 20 66 61 69 6c 65 64}
		$s5 = {4f 00 70 00 65 00 6e 00 46 00 69 00 6c 00 65 00 20 00 66 00 61 00 69 00 6c 00 21 00}
		$s6 = {57 00 72 00 69 00 74 00 65 00 66 00 69 00 6c 00 65 00 20 00 73 00 75 00 63 00 63 00 65 00 73 00 73 00}
		$op1 = { 4c 8d 45 e0 49 8b cc 41 8d 51 c3 e8 34 77 02 00 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 3000KB and 1 of ( $x* ) or 4 of them
}

rule APT_CN_MAL_RedDelta_Shellcode_Loader_Oct20_3 : hardened
{
	meta:
		description = "Detects Red Delta samples"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/JAMESWT_MHT/status/1316387482708119556"
		date = "2020-10-14"
		modified = "2022-12-21"
		hash1 = "740992d40b84b10aa9640214a4a490e989ea7b869cea27dbbdef544bb33b1048"
		id = "b52836bb-cdef-5416-a8e1-72d0b2298546"

	strings:
		$s1 = {54 61 73 6b 73 63 68 64 2e 64 6c 6c}
		$s2 = {41 64 64 54 61 73 6b 50 6c 61 6e 44 6c 6c 56 65 72 73 6f 6e 2e 64 6c 6c}
		$s3 = {5c 46 6c 61 73 68 55 70 64 61 74 65 2e 65 78 65}
		$s4 = {44 3a 5c 50 72 6f 6a 65 63 74 5c 46 42 49 52 65 64 54 65 61 6d}
		$s5 = {45 72 72 6f 72 20 25 73 3a 25 64 2c 20 45 72 72 6f 72 43 6f 64 65 3a 20 25 78}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 400KB and 4 of them
}

