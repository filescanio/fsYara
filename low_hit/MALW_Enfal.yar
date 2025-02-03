rule EnfalCode : Enfal Family hardened
{
	meta:
		description = "Enfal code tricks"
		author = "Seth Hardy"
		last_modified = "2014-06-19"

	strings:
		$decrypt = { B0 20 2A C3 00 04 33 56 43 FF D7 3B D8 }

	condition:
		any of them
}

rule EnfalStrings : Enfal Family hardened
{
	meta:
		description = "Enfal Identifying Strings"
		author = "Seth Hardy"
		last_modified = "2014-06-19"

	strings:
		$ = {44 3a 5c 77 6f 72 6b 5c 5c 78 65 36 ba 90 e5 93 a5 e5 85 8d e6 9d 80 5c 74 6d 70 5c 52 65 6c 65 61 73 65 5c 53 65 72 76 69 63 65 44 6c 6c 2e 70 64 62}
		$ = {65 3a 5c 70 72 6f 67 72 61 6d 73 5c 4c 75 72 69 64 44 6f 77 6e 4c 6f 61 64 65 72}
		$ = {4c 75 72 69 64 44 6f 77 6e 6c 6f 61 64 65 72 20 66 6f 72 20 46 61 6c 63 6f 6e}
		$ = {44 6c 6c 53 65 72 76 69 63 65 54 72 6f 6a 61 6e}
		$ = {5c 6b 5c 5c 78 65 36 a1 8c e8 9d a2 5c}
		$ = {45 74 65 6e 46 61 6c 63 6f 6e ef bc 88 e4 bf ae e6 94 b9 ef bc 89}
		$ = {4d 61 64 6f 6e 6e 61 00 4a 65 73 75 73}
		$ = {2f 69 75 70 77 38 32 2f 6e 65 74 73 74 61 74 65}
		$ = {66 75 63 6b 4e 6f 64 41 67 61 69 6e}
		$ = {69 6c 6f 75 64 65 72 6d 61 6f}
		$ = {43 72 70 71 32 2e 63 67 69}
		$ = {43 6c 6e 70 70 35 2e 63 67 69}
		$ = {44 71 70 71 33 6c 6c 2e 63 67 69}
		$ = {64 69 65 6f 73 6e 38 33 2e 63 67 69}
		$ = {52 77 70 71 31 2e 63 67 69}
		$ = {2f 43 63 6d 77 68 69 74 65}
		$ = {2f 43 6d 77 68 69 74 65}
		$ = {2f 43 72 70 77 68 69 74 65}
		$ = {2f 44 66 77 68 69 74 65}
		$ = {2f 51 75 65 72 79 2e 74 78 74}
		$ = {2f 55 66 77 68 69 74 65}
		$ = {2f 63 67 6c 2d 62 69 6e 2f 43 6c 6e 70 70 35 2e 63 67 69}
		$ = {2f 63 67 6c 2d 62 69 6e 2f 43 72 70 71 32 2e 63 67 69}
		$ = {2f 63 67 6c 2d 62 69 6e 2f 44 77 70 71 33 6c 6c 2e 63 67 69}
		$ = {2f 63 67 6c 2d 62 69 6e 2f 4f 77 70 71 34 2e 63 67 69}
		$ = {2f 63 67 6c 2d 62 69 6e 2f 52 77 70 71 31 2e 63 67 69}
		$ = {2f 74 72 61 6e 64 6f 63 73 2f 6d 6d 2f}
		$ = {2f 74 72 61 6e 64 6f 63 73 2f 6e 65 74 73 74 61 74}
		$ = {4e 46 61 6c 2e 65 78 65}
		$ = {4c 49 4e 4c 49 4e 56 4d 41 4e}
		$ = {37 4e 46 50 34 52 39 57}

	condition:
		any of them
}

rule Enfal : Family hardened
{
	meta:
		description = "Enfal"
		author = "Seth Hardy"
		last_modified = "2014-06-19"

	condition:
		EnfalCode or EnfalStrings
}

rule Enfal_Malware : hardened
{
	meta:
		description = "Detects a certain type of Enfal Malware"
		author = "Florian Roth"
		reference = "not set"
		date = "2015/02/10"
		hash = "9639ec9aca4011b2724d8e7ddd13db19913e3e16"
		score = 60

	strings:
		$s0 = {50 4f 57 45 52 50 4e 54 2e 65 78 65}
		$s1 = {25 41 50 50 44 41 54 41 25 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c}
		$s2 = {25 48 4f 4d 45 50 41 54 48 25}
		$s3 = {53 65 72 76 65 72 32 30 30 38}
		$s4 = {53 65 72 76 65 72 32 30 30 33}
		$s5 = {53 65 72 76 65 72 32 30 30 33 52 32}
		$s6 = {53 65 72 76 65 72 32 30 30 38 52 32}
		$s9 = {25 48 4f 4d 45 44 52 49 56 45 25}
		$s13 = {25 43 6f 6d 53 70 65 63 25}

	condition:
		all of them
}

rule Enfal_Malware_Backdoor : hardened
{
	meta:
		description = "Generic Rule to detect the Enfal Malware"
		author = "Florian Roth"
		date = "2015/02/10"
		super_rule = 1
		hash0 = "6d484daba3927fc0744b1bbd7981a56ebef95790"
		hash1 = "d4071272cc1bf944e3867db299b3f5dce126f82b"
		hash2 = "6c7c8b804cc76e2c208c6e3b6453cb134d01fa41"
		score = 60

	strings:
		$mz = { 4d 5a }
		$x1 = {4d 00 69 00 63 00 6f 00 72 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 74 00 61 00 74 00 69 00 6f 00 6e 00}
		$x2 = {49 00 4d 00 20 00 4d 00 6f 00 6e 00 6e 00 69 00 74 00 6f 00 72 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00}
		$s1 = {69 00 6d 00 65 00 6d 00 6f 00 6e 00 73 00 76 00 63 00 2e 00 64 00 6c 00 6c 00}
		$s2 = {69 70 68 6c 70 73 76 63 2e 74 6d 70}
		$z1 = {75 72 6c 6d 6f 6e}
		$z2 = {52 00 65 00 67 00 69 00 73 00 74 00 65 00 72 00 65 00 64 00 20 00 74 00 72 00 61 00 64 00 65 00 6d 00 61 00 72 00 6b 00 73 00 20 00 61 00 6e 00 64 00 20 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 6d 00 61 00 72 00 6b 00 73 00 20 00 61 00 72 00 65 00 20 00 74 00 68 00 65 00 20 00 70 00 72 00 6f 00 70 00 65 00 72 00 74 00 79 00 20 00 6f 00 66 00 20 00 74 00 68 00 65 00 69 00 72 00 20 00 72 00 65 00 73 00 70 00 65 00 63 00}
		$z3 = {58 70 73 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72}
		$z4 = {58 70 73 52 65 67 69 73 74 65 72 53 65 72 76 65 72}
		$z5 = {7b 35 33 41 34 39 38 38 43 2d 46 39 31 46 2d 34 30 35 34 2d 39 30 37 36 2d 32 32 30 41 43 35 45 43 30 33 46 33 7d}

	condition:
		($mz at 0 ) and ( 1 of ( $x* ) or ( all of ( $s* ) and all of ( $z* ) ) )
}

rule ce_enfal_cmstar_debug_msg : hardened
{
	meta:
		Author = "rfalcone"
		Date = "2015.05.10"
		Description = "Detects the static debug strings within CMSTAR"
		Reference = "http://researchcenter.paloaltonetworks.com/2015/05/cmstar-downloader-lurid-and-enfals-new-cousin"

	strings:
		$d1 = {45 45 45 0d 0a}
		$d2 = {54 4b 45 0d 0a}
		$d3 = {56 50 45 0d 0a}
		$d4 = {56 50 53 0d 0a}
		$d5 = {57 46 53 45 0d 0a}
		$d6 = {57 46 53 53 0d 0a}
		$d7 = {43 4d 2a 2a 0d 0a}

	condition:
		uint16( 0 ) == 0x5a4d and all of ( $d* )
}

rule MAL_Enfal_Nov22 : hardened
{
	meta:
		old_rule_name = "Enfal_Malware"
		description = "Detects a certain type of Enfal Malware"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.enfal"
		date = "2015-02-10"
		modified = "2023-01-06"
		hash2 = "42fa6241ab94c73c7ab386d600fae70da505d752daab2e61819a0142b531078a"
		hash2 = "bf433f4264fa3f15f320b35e773e18ebfe94465d864d3f4b2a963c3e5efd39c2"
		score = 75
		id = "9dcba14e-2175-5da0-8629-5b952c213f6c"

	strings:
		$xop1 = { 00 00 83 c9 ff 33 c0 f2 ae f7 d1 49 b8 ff 8f 01 00 2b c1 }
		$s1 = {50 4f 57 45 52 50 4e 54 2e 65 78 65}
		$s2 = {25 41 50 50 44 41 54 41 25 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c}
		$s3 = {25 48 4f 4d 45 50 41 54 48 25}
		$s4 = {53 65 72 76 65 72 32 30 30 38}
		$s5 = {25 43 6f 6d 53 70 65 63 25}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 200KB and ( 1 of ( $x* ) or 3 of ( $s* ) )
}

