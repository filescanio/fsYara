rule NaikonCode : Naikon Family hardened
{
	meta:
		description = "Naikon code features"
		author = "Seth Hardy"
		last_modified = "2014-06-25"

	strings:
		$ = { 0F AF C1 C1 E0 1F }
		$ = { 35 5A 01 00 00}
		$ = { 81 C2 7F 14 06 00 }

	condition:
		all of them
}

rule NaikonStrings : Naikon Family hardened
{
	meta:
		description = "Naikon Identifying Strings"
		author = "Seth Hardy"
		last_modified = "2014-06-25"

	strings:
		$ = {4e 4f 4b 49 41 4e 39 35 2f 57 45 42}
		$ = {2f 74 61 67 3d 69 6e 66 6f 26 69 64 3d 31 35}
		$ = {73 6b 67 28 33 29 3d 26 33 2e 32 64 5f 75 31}
		$ = {5c 54 65 6d 70 5c 69 45 78 70 6c 6f 72 65 72 2e 65 78 65}
		$ = {5c 54 65 6d 70 5c 5c 22 54 53 47 22}

	condition:
		any of them
}

rule Naikon : Family hardened
{
	meta:
		description = "Naikon"
		author = "Seth Hardy"
		last_modified = "2014-06-25"

	condition:
		NaikonCode or NaikonStrings
}

rule Backdoor_Naikon_APT_Sample1 : hardened
{
	meta:
		description = "Detects backdoors related to the Naikon APT"
		author = "Florian Roth"
		reference = "https://goo.gl/7vHyvh"
		date = "2015-05-14"
		hash = "d5716c80cba8554eb79eecfb4aa3d99faf0435a1833ec5ef51f528146c758eba"
		hash = "f5ab8e49c0778fa208baad660fe4fa40fc8a114f5f71614afbd6dcc09625cb96"

	strings:
		$x0 = {47 45 54 20 68 74 74 70 3a 2f 2f 25 73 3a 25 64 2f 61 73 70 78 61 62 63 64 65 66 2e 61 73 70 3f 25 73 20 48 54 54 50 2f 31 2e 31}
		$x1 = {50 4f 53 54 20 68 74 74 70 3a 2f 2f 25 73 3a 25 64 2f 61 73 70 78 61 62 63 64 65 66 67 2e 61 73 70 3f 25 73 20 48 54 54 50 2f 31 2e 31}
		$x2 = {67 72 65 65 6e 73 6b 79 32 37 2e 76 69 63 70 2e 6e 65 74}
		$x3 = {5c 00 74 00 65 00 6d 00 70 00 76 00 78 00 64 00 2e 00 76 00 78 00 64 00 2e 00 64 00 6c 00 6c 00}
		$x4 = {6f 74 6e 61 2e 76 69 63 70 2e 6e 65 74}
		$x5 = {73 6d 69 74 68 6b 69 6e 67 31 39 2e 67 69 63 70 2e 6e 65 74}
		$s1 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 77 65 62 63 6c 69 65 6e 74}
		$s2 = {5c 55 73 65 72 2e 69 6e 69}
		$s3 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 6f 77 73 3b 20 55 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 31 3b 20 7a 68 2d 45 4e 3b 20 72 76 3a 31 2e 37 2e 31 32 29 20 47 65 63 6b 6f 2f 32 30 30}
		$s4 = {5c 00 55 00 73 00 65 00 72 00 50 00 72 00 6f 00 66 00 69 00 6c 00 65 00 2e 00 64 00 6c 00 6c 00}
		$s5 = {43 6f 6e 6e 65 63 74 69 6f 6e 3a 4b 65 65 70 2d 41 6c 69 76 65 3a 20 25 64}
		$s6 = {52 65 66 65 72 65 72 3a 20 68 74 74 70 3a 2f 2f 25 73 3a 25 64 2f}
		$s7 = {25 73 20 25 73 20 25 73 20 25 64 20 25 64 20 25 64 20}
		$s8 = {25 00 73 00 2d 00 2d 00 25 00 73 00}
		$s9 = {52 00 75 00 6e 00 20 00 46 00 69 00 6c 00 65 00 20 00 53 00 75 00 63 00 63 00 65 00 73 00 73 00 21 00}
		$s10 = {44 00 52 00 49 00 56 00 45 00 5f 00 52 00 45 00 4d 00 4f 00 54 00 45 00}
		$s11 = {50 00 72 00 6f 00 78 00 79 00 45 00 6e 00 61 00 62 00 6c 00 65 00}
		$s12 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1000KB and ( 1 of ( $x* ) or 7 of ( $s* ) )
}

