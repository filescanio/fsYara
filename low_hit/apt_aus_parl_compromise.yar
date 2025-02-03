rule APT_WebShell_Tiny_1 : hardened
{
	meta:
		description = "Detetcs a tiny webshell involved in the Australian Parliament House network compromise"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
		date = "2019-02-18"
		id = "e65a8920-0684-5aae-a2b8-079c2beae08a"

	strings:
		$x1 = {((65 76 61 6c 28) | (65 00 76 00 61 00 6c 00 28 00))}

	condition:
		( uint16( 0 ) == 0x3f3c or uint16( 0 ) == 0x253c ) and filesize < 40 and $x1
}

rule APT_WebShell_AUS_Tiny_2 : hardened
{
	meta:
		description = "Detetcs a tiny webshell involved in the Australian Parliament House network compromise"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
		date = "2019-02-18"
		hash1 = "0d6209d86f77a0a69451b0f27b476580c14e0cda15fa6a5003aab57a93e7e5a5"
		id = "4746d4ce-628a-59b0-9032-7e0759d96ad3"

	strings:
		$x1 = {52 65 71 75 65 73 74 2e 49 74 65 6d 5b 53 79 73 74 65 6d 2e 54 65 78 74 2e 45 6e 63 6f 64 69 6e 67 2e 55 54 46 38 2e 47 65 74 53 74 72 69 6e 67 28 43 6f 6e 76 65 72 74 2e 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 22 5b 70 61 73 73 77 6f 72 64 5d 22 29 29 5d 3b}
		$x2 = {65 76 61 6c 28 61 72 67 75 6d 65 6e 74 73 2c 53 79 73 74 65 6d 2e 54 65 78 74 2e 45 6e 63 6f 64 69 6e 67 2e 55 54 46 38 2e 47 65 74 53 74 72 69 6e 67 28 43 6f 6e 76 65 72 74 2e 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 22}

	condition:
		( uint16( 0 ) == 0x3f3c or uint16( 0 ) == 0x253c ) and filesize < 1KB and 1 of them
}

rule APT_WebShell_AUS_JScript_3 : hardened
{
	meta:
		description = "Detetcs a webshell involved in the Australian Parliament House network compromise"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
		date = "2019-02-18"
		hash1 = "7ac6f973f7fccf8c3d58d766dec4ab7eb6867a487aa71bc11d5f05da9322582d"
		id = "ff7e780b-ccf9-53b6-b741-f04a8cbaf580"

	strings:
		$s1 = {3c 25 40 20 50 61 67 65 20 4c 61 6e 67 75 61 67 65 3d 22 4a 73 63 72 69 70 74 22 20 76 61 6c 69 64 61 74 65 52 65 71 75 65 73 74 3d 22 66 61 6c 73 65 22 25 3e 3c 25 74 72 79 7b 65 76 61 6c 28 53 79 73 74 65 6d 2e 54 65 78 74 2e 45 6e 63 6f 64 69 6e 67 2e 55 54 46 38 2e 47 65 74 53 74 72 69 6e 67 28 43 6f 6e 76 65 72 74 2e 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67}
		$s2 = {2e 49 74 65 6d 5b 22 5b 70 61 73 73 77 6f 72 64 5d 22 5d 29 29 2c 22 75 6e 73 61 66 65 22 29 3b 7d}

	condition:
		uint16( 0 ) == 0x6568 and filesize < 1KB and all of them
}

rule APT_WebShell_AUS_4 : hardened
{
	meta:
		description = "Detetcs a webshell involved in the Australian Parliament House network compromise"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
		date = "2019-02-18"
		hash1 = "83321c02339bb51735fbcd9a80c056bd3b89655f3dc41e5fef07ca46af09bb71"
		id = "bb5b10d1-3528-5361-92fc-8440c65dcda4"

	strings:
		$s1 = {77 50 72 6f 78 79 2e 43 72 65 64 65 6e 74 69 61 6c 73 20 3d 20 6e 65 77 20 53 79 73 74 65 6d 2e 4e 65 74 2e 4e 65 74 77 6f 72 6b 43 72 65 64 65 6e 74 69 61 6c 28 70 75 73 72 2c 20 70 70 77 64 29 3b}
		$s2 = {7b 72 65 74 75 72 6e 20 53 79 73 74 65 6d 2e 54 65 78 74 2e 45 6e 63 6f 64 69 6e 67 2e 55 54 46 38 2e 47 65 74 53 74 72 69 6e 67 28 43 6f 6e 76 65 72 74 2e 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28}
		$s3 = {2e 45 71 75 61 6c 73 28 27 55 73 65 72 2d 41 67 65 6e 74 27 2c 20 53 74 72 69 6e 67 43 6f 6d 70 61 72 69 73 6f 6e 2e 4f 72 64 69 6e 61 6c 49 67 6e 6f 72 65 43 61 73 65 29 29}
		$s4 = {67 65 6e 2e 45 6d 69 74 28 53 79 73 74 65 6d 2e 52 65 66 6c 65 63 74 69 6f 6e 2e 45 6d 69 74 2e 4f 70 43 6f 64 65 73 2e 52 65 74 29 3b}

	condition:
		uint16( 0 ) == 0x7566 and filesize < 10KB and 3 of them
}

rule APT_Script_AUS_4 : hardened
{
	meta:
		description = "Detetcs a script involved in the Australian Parliament House network compromise"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
		date = "2019-02-18"
		hash1 = "fdf15f388a511a63fbad223e6edb259abdd4009ec81fcc87ce84f0f2024c8057"
		id = "5cbf2476-5ce8-540d-b87b-e400daf49b43"

	strings:
		$x1 = {6d 79 4d 75 74 65 78 20 3d 20 43 72 65 61 74 65 4d 75 74 65 78 28 30 2c 20 31 2c 20 22 74 65 58 32 33 73 74 4e 65 77 22 29}
		$x2 = {6d 6d 70 61 74 68 20 3d 20 45 6e 76 69 72 6f 6e 28 61 70 70 64 61 74 61 50 61 74 68 29 20 26 20 22 5c 5c 22 20 26 20 22 4d 69 63 72 6f 73 6f 66 74 22 20 26 20 22 5c 5c 22 20 26 20 22 6d 6d 2e 61 63 63 64 62 22}
		$x3 = {44 69 6d 20 6d 6d 70 61 74 68 20 41 73 20 53 74 72 69 6e 67 2c 20 6e 65 77 6d 6d 70 61 74 68 20 20 41 73 20 53 74 72 69 6e 67 2c 20 61 70 70 64 61 74 61 50 61 74 68 20 41 73 20 53 74 72 69 6e 67}
		$x4 = {27 4d 73 67 42 6f 78 20 22 6d 79 4d 75 74 65 78 20 43 72 65 61 74 65 64 22 20 44 6f 20 6e 6f 74 69 6e 67}
		$x5 = {61 70 70 64 61 74 61 50 61 74 68 20 3d 20 22 61 70 70 22 20 26 20 22 44 61 74 41 22}
		$x6 = {2e 44 6f 43 6d 64 2e 43 6c 6f 73 65 20 2c 20 2c 20 61 63 53 61 76 65 59 65 73}

	condition:
		filesize < 7KB and 1 of them
}

rule APT_WebShell_AUS_5 : hardened
{
	meta:
		description = "Detetcs a webshell involved in the Australian Parliament House network compromise"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
		date = "2019-02-18"
		hash1 = "54a17fb257db2d09d61af510753fd5aa00537638a81d0a8762a5645b4ef977e4"
		id = "59b3f6aa-2d3b-54b4-b543-57bd9d981e87"

	strings:
		$a1 = {66 75 6e 63 74 69 6f 6e 20 44 45 43 28 64 29 7b 72 65 74 75 72 6e 20 53 79 73 74 65 6d 2e 54 65 78 74 2e 45 6e 63 6f 64 69 6e 67 2e 55 54 46 38 2e 47 65 74 53 74 72 69 6e 67 28 43 6f 6e 76 65 72 74 2e 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 64 29 29 3b 7d}
		$a2 = {66 75 6e 63 74 69 6f 6e 20 45 4e 43 28 64 29 7b 72 65 74 75 72 6e 20 43 6f 6e 76 65 72 74 2e 54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 28 53 79 73 74 65 6d 2e 54 65 78 74 2e 45 6e 63 6f 64 69 6e 67 2e 55 54 46 38 2e 47 65 74 42 79 74 65 73 28 64 29 29 3b 7d}
		$s1 = {76 61 72 20 68 61 73 68 3d 44 45 43 28 52 65 71 75 65 73 74 2e 49 74 65 6d 5b 27}
		$s2 = {52 65 73 70 6f 6e 73 65 2e 57 72 69 74 65 28 45 4e 43 28 53 45 54 5f 41 53 53 5f 53 55 43 43 45 53 53 29 29 3b}
		$s3 = {68 61 73 68 74 61 62 6c 65 5b 68 61 73 68 5d 20 3d 20 61 73 73 43 6f 64 65 3b}
		$s4 = {52 65 73 70 6f 6e 73 65 2e 57 72 69 74 65 28 73 73 29 3b}
		$s5 = {76 61 72 20 68 61 73 68 74 61 62 6c 65 20 3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 5b 43 61 63 68 65 50 74 72 5d 3b}

	condition:
		uint16( 0 ) == 0x7566 and filesize < 2KB and 4 of them
}

rule HKTL_LazyCat_LogEraser : hardened
{
	meta:
		description = "Detetcs a tool used in the Australian Parliament House network compromise"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
		date = "2019-02-18"
		hash1 = "1c113dce265e4d744245a7c55dadc80199ae972a9e0ecbd0c5ced57067cf755b"
		hash2 = "510375f8142b3651df67d42c3eff8d2d880987c0e057fc75a5583f36de34bf0e"
		id = "a3d74657-a389-5482-ab26-966e790afd50"

	strings:
		$x1 = {((4c 61 7a 79 43 61 74 2e 64 6c 6c) | (4c 00 61 00 7a 00 79 00 43 00 61 00 74 00 2e 00 64 00 6c 00 6c 00))}
		$x2 = {((2e 6c 6f 63 61 6c 5f 70 72 69 76 69 6c 65 67 65 5f 65 73 63 61 6c 61 74 69 6f 6e 2e 72 6f 74 74 65 6e 5f 70 6f 74 61 74 6f) | (2e 00 6c 00 6f 00 63 00 61 00 6c 00 5f 00 70 00 72 00 69 00 76 00 69 00 6c 00 65 00 67 00 65 00 5f 00 65 00 73 00 63 00 61 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 72 00 6f 00 74 00 74 00 65 00 6e 00 5f 00 70 00 6f 00 74 00 61 00 74 00 6f 00))}
		$x3 = {((4c 61 7a 79 43 61 74 2e 45 78 74 65 6e 73 69 6f 6e) | (4c 00 61 00 7a 00 79 00 43 00 61 00 74 00 2e 00 45 00 78 00 74 00 65 00 6e 00 73 00 69 00 6f 00 6e 00))}
		$x4 = {((20 4d 45 4f 57 6f 66) | (20 00 4d 00 45 00 4f 00 57 00 6f 00 66 00))}
		$x5 = {56 00 69 00 72 00 74 00 75 00 61 00 6c 00 53 00 69 00 74 00 65 00 3a 00 20 00 7b 00 30 00 7d 00 2c 00 20 00 41 00 64 00 64 00 72 00 65 00 73 00 73 00 3a 00 20 00 7b 00 31 00 3a 00 58 00 31 00 36 00 7d 00 2c 00 20 00 4e 00 61 00 6d 00 65 00 3a 00 20 00 7b 00 32 00 7d 00 2c 00 20 00 48 00 61 00 6e 00 64 00 6c 00 65 00 3a 00 20 00 7b 00 33 00 3a 00 58 00 31 00 36 00 7d 00 2c 00 20 00 4c 00 6f 00 67 00 50 00 61 00 74 00 68 00 3a 00 20 00 7b 00 34 00 7d 00}
		$s1 = {((4c 61 7a 79 43 61 74) | (4c 00 61 00 7a 00 79 00 43 00 61 00 74 00))}
		$s2 = {24 65 33 66 66 33 37 66 32 2d 38 35 64 37 2d 34 62 32 34 2d 61 33 38 35 2d 37 65 65 62 31 66 35 61 39 35 36 32}
		$s3 = {6c 6f 63 61 6c 20 2d 3e 20 72 65 6d 6f 74 65 20 7b 30 7d 20 62 79 74 65 73}
		$s4 = {72 65 6d 6f 74 65 20 2d 3e 20 6c 6f 63 61 6c 20 7b 30 7d 20 62 79 74 65 73}

	condition:
		3 of them
}

rule HKTL_PowerKatz_Feb19_1 : hardened
{
	meta:
		description = "Detetcs a tool used in the Australian Parliament House network compromise"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
		date = "2019-02-18"
		id = "294d6f6c-dbc8-5431-87a0-64abe582c4ea"

	strings:
		$x1 = {((50 6f 77 65 72 6b 61 74 7a 33 32) | (50 00 6f 00 77 00 65 00 72 00 6b 00 61 00 74 00 7a 00 33 00 32 00))}
		$x2 = {((50 6f 77 65 72 6b 61 74 7a 36 34) | (50 00 6f 00 77 00 65 00 72 00 6b 00 61 00 74 00 7a 00 36 00 34 00))}
		$s1 = {((47 65 74 44 61 74 61 3a 20 6e 6f 74 20 66 6f 75 6e 64 20 74 61 73 6b 4e 61 6d 65) | (47 00 65 00 74 00 44 00 61 00 74 00 61 00 3a 00 20 00 6e 00 6f 00 74 00 20 00 66 00 6f 00 75 00 6e 00 64 00 20 00 74 00 61 00 73 00 6b 00 4e 00 61 00 6d 00 65 00))}
		$s2 = {((47 65 74 52 65 73 20 45 78 3a) | (47 00 65 00 74 00 52 00 65 00 73 00 20 00 45 00 78 00 3a 00))}

	condition:
		1 of ( $x* ) and 1 of ( $s* )
}

rule HKTL_Unknown_Feb19_1 : hardened
{
	meta:
		description = "Detetcs a tool used in the Australian Parliament House network compromise"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
		date = "2019-02-18"
		id = "bdcadc4b-8881-5dc7-b203-4e79cbc850ed"

	strings:
		$x1 = {((6e 6f 74 20 61 20 76 61 6c 69 64 20 74 69 6d 65 6f 75 74 20 66 6f 72 6d 61 74 21) | (6e 00 6f 00 74 00 20 00 61 00 20 00 76 00 61 00 6c 00 69 00 64 00 20 00 74 00 69 00 6d 00 65 00 6f 00 75 00 74 00 20 00 66 00 6f 00 72 00 6d 00 61 00 74 00 21 00))}
		$x2 = {((68 6f 73 74 20 63 61 6e 20 6e 6f 74 20 62 65 20 65 6d 70 74 79 21) | (68 00 6f 00 73 00 74 00 20 00 63 00 61 00 6e 00 20 00 6e 00 6f 00 74 00 20 00 62 00 65 00 20 00 65 00 6d 00 70 00 74 00 79 00 21 00))}
		$x3 = {((6e 6f 74 20 61 20 76 61 6c 69 64 20 70 6f 72 74 20 66 6f 72 6d 61 74 21) | (6e 00 6f 00 74 00 20 00 61 00 20 00 76 00 61 00 6c 00 69 00 64 00 20 00 70 00 6f 00 72 00 74 00 20 00 66 00 6f 00 72 00 6d 00 61 00 74 00 21 00))}
		$x4 = {((7b 30 7d 20 2d 20 7b 31 7d 20 54 54 4c 3d 7b 32 7d 20 74 69 6d 65 3d 7b 33 7d) | (7b 00 30 00 7d 00 20 00 2d 00 20 00 7b 00 31 00 7d 00 20 00 54 00 54 00 4c 00 3d 00 7b 00 32 00 7d 00 20 00 74 00 69 00 6d 00 65 00 3d 00 7b 00 33 00 7d 00))}
		$x5 = {((70 69 6e 67 20 63 6f 75 6e 74 20 69 73 20 6e 6f 74 20 61 20 63 6f 72 72 65 63 74 20 66 6f 72 6d 61 74 21) | (70 00 69 00 6e 00 67 00 20 00 63 00 6f 00 75 00 6e 00 74 00 20 00 69 00 73 00 20 00 6e 00 6f 00 74 00 20 00 61 00 20 00 63 00 6f 00 72 00 72 00 65 00 63 00 74 00 20 00 66 00 6f 00 72 00 6d 00 61 00 74 00 21 00))}
		$s1 = {((54 68 65 20 72 65 73 75 6c 74 20 69 73 20 74 6f 6f 20 6c 61 72 67 65 2c 70 72 6f 67 72 61 6d 20 73 74 6f 72 65 20 74 6f 20 27 7b 30 7d 27 2e 50 6c 65 61 73 65 20 64 6f 77 6e 6c 6f 61 64 20 69 74 20 6d 61 6e 75 6c 6c 79 2e) | (54 00 68 00 65 00 20 00 72 00 65 00 73 00 75 00 6c 00 74 00 20 00 69 00 73 00 20 00 74 00 6f 00 6f 00 20 00 6c 00 61 00 72 00 67 00 65 00 2c 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 73 00 74 00 6f 00 72 00 65 00 20 00 74 00 6f 00 20 00 27 00 7b 00 30 00 7d 00 27 00 2e 00 50 00 6c 00 65 00 61 00 73 00 65 00 20 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 20 00 69 00 74 00 20 00 6d 00 61 00 6e 00 75 00 6c 00 6c 00 79 00 2e 00))}
		$s2 = {((43 3a 5c 57 69 6e 64 6f 77 73 5c 74 65 6d 70 5c) | (43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 65 00 6d 00 70 00 5c 00))}

	condition:
		1 of ( $x* ) or 2 of them
}

