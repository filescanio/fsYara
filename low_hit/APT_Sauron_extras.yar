rule APT_Project_Sauron_Scripts : hardened
{
	meta:
		description = "Detects scripts (mostly LUA) from Project Sauron report by Kaspersky"
		author = "Florian Roth"
		reference = "https://goo.gl/eFoP4A"
		date = "2016-08-08"

	strings:
		$x1 = {6c 6f 63 61 6c 20 74 20 3d 20 77 2e 65 78 65 63 32 73 74 72 28 22 72 65 67 65 64 69 74 20}
		$x2 = {6c 6f 63 61 6c 20 72 20 3d 20 77 2e 65 78 65 63 32 73 74 72 28 22 63 61 74}
		$x3 = {61 70 2a 2e 74 78 74 20 6c 69 6e 6b 2a 2e 74 78 74 20 6e 6f 64 65 2a 2e 74 75 6e 20 56 69 72 74 75 61 6c 45 6e 63 72 79 70 74 65 64 4e 65 74 77 6f 72 6b 2e 6c 69 63 65 6e 63 65}
		$x4 = {6d 6f 76 65 20 4f 20 46 61 6b 65 56 69 72 74 75 61 6c 45 6e 63 72 79 70 74 65 64 4e 65 74 77 6f 72 6b 2e 64 6c 6c}
		$x5 = {73 69 6e 66 6f 20 7c 20 62 61 73 65 78 20 62 20 33 32 75 72 6c 20 7c 20 64 65 78 74 20 6c 20 33 30}
		$x6 = {77 2e 65 78 65 63 32 73 74 72 28 65 78 65 63 53 74 72 29}
		$x7 = {6e 65 74 6e 66 6f 20 69 72 63 20 7c 20 62 61 73 65 78 20 62 20 33 32 75 72 6c}
		$x8 = {77 2e 65 78 65 63 28 22 77 66 77 20 73 74 61 74 75 73 22 29}
		$x9 = {65 78 65 63 28 22 73 61 6d 64 75 6d 70 22 29}
		$x10 = {63 61 74 20 56 69 72 74 75 61 6c 45 6e 63 72 79 70 74 65 64 4e 65 74 77 6f 72 6b 2e 69 6e 69 7c 67 72 65 70}
		$x11 = {69 66 20 73 74 72 69 6e 67 2e 6c 6f 77 65 72 28 6b 29 20 3d 3d 20 22 73 65 63 75 72 69 74 79 70 72 6f 76 69 64 65 72 73 22 20 74 68 65 6e}
		$x12 = {65 78 65 63 32 73 74 72 28 22 70 6c 69 73 74 20 62 20 7c 20 67 72 65 70 20 6e 65 74 73 76 63 73 22 29}
		$x13 = {2e 2a 61 63 63 6f 75 6e 74 2e 2a 7c 2e 2a 61 63 63 74 2e 2a 7c 2e 2a 64 6f 6d 61 69 6e 2e 2a 7c 2e 2a 6c 6f 67 69 6e 2e 2a 7c 2e 2a 6d 65 6d 62 65 72 2e 2a}
		$x14 = {53 41 55 52 4f 4e 5f 4b 42 4c 4f 47 5f 4b 45 59 20 3d}

	condition:
		1 of them
}

rule APT_Project_Sauron_arping_module : hardened
{
	meta:
		description = "Detects strings from arping module - Project Sauron report by Kaspersky"
		author = "Florian Roth"
		reference = "https://goo.gl/eFoP4A"
		date = "2016-08-08"

	strings:
		$s1 = {52 65 73 6f 6c 76 65 20 68 6f 73 74 73 20 74 68 61 74 20 61 6e 73 77 65 72}
		$s2 = {50 72 69 6e 74 20 6f 6e 6c 79 20 72 65 70 6c 79 69 6e 67 20 49 70 73}
		$s3 = {44 6f 20 6e 6f 74 20 64 69 73 70 6c 61 79 20 4d 41 43 20 61 64 64 72 65 73 73 65 73}

	condition:
		all of them
}

rule APT_Project_Sauron_kblogi_module : hardened
{
	meta:
		description = "Detects strings from kblogi module - Project Sauron report by Kaspersky"
		author = "Florian Roth"
		reference = "https://goo.gl/eFoP4A"
		date = "2016-08-08"

	strings:
		$x1 = {49 6e 6a 65 63 74 20 75 73 69 6e 67 20 70 72 6f 63 65 73 73 20 6e 61 6d 65 20 6f 72 20 70 69 64 2e 20 44 65 66 61 75 6c 74}
		$s2 = {43 6f 6e 76 65 72 74 20 6d 6f 64 65 3a 20 52 65 61 64 20 6c 6f 67 20 66 72 6f 6d 20 66 69 6c 65 20 61 6e 64 20 63 6f 6e 76 65 72 74 20 74 6f 20 74 65 78 74}
		$s3 = {4d 61 78 69 6d 75 6d 20 72 75 6e 6e 69 6e 67 20 74 69 6d 65 20 69 6e 20 73 65 63 6f 6e 64 73}

	condition:
		$x1 or 2 of them
}

rule APT_Project_Sauron_basex_module : hardened
{
	meta:
		description = "Detects strings from basex module - Project Sauron report by Kaspersky"
		author = "Florian Roth"
		reference = "https://goo.gl/eFoP4A"
		date = "2016-08-08"

	strings:
		$x1 = {36 34 2c 20 36 34 75 72 6c 2c 20 33 32 2c 20 33 32 75 72 6c 20 6f 72 20 31 36 2e}
		$s2 = {46 6f 72 63 65 20 64 65 63 6f 64 69 6e 67 20 77 68 65 6e 20 69 6e 70 75 74 20 69 73 20 69 6e 76 61 6c 69 64 2f 63 6f 72 72 75 70 74}
		$s3 = {54 68 69 73 20 63 72 75 66 74}

	condition:
		$x1 or 2 of them
}

rule APT_Project_Sauron_dext_module : hardened
{
	meta:
		description = "Detects strings from dext module - Project Sauron report by Kaspersky"
		author = "Florian Roth"
		reference = "https://goo.gl/eFoP4A"
		date = "2016-08-08"

	strings:
		$x1 = {41 73 73 65 6d 62 6c 65 20 72 6f 77 73 20 6f 66 20 44 4e 53 20 6e 61 6d 65 73 20 62 61 63 6b 20 74 6f 20 61 20 73 69 6e 67 6c 65 20 73 74 72 69 6e 67 20 6f 66 20 64 61 74 61}
		$x2 = {72 65 6d 6f 76 65 73 20 63 68 65 63 6b 73 20 6f 66 20 44 4e 53 20 6e 61 6d 65 73 20 61 6e 64 20 6c 65 6e 67 74 68 73 20 28 64 75 72 69 6e 67 20 73 70 6c 69 74 29}
		$x3 = {52 61 6e 64 6f 6d 69 7a 65 20 64 61 74 61 20 6c 65 6e 67 74 68 73 20 28 6c 65 6e 67 74 68 2f 32 20 74 6f 20 6c 65 6e 67 74 68 29}
		$x4 = {54 68 69 73 20 63 72 75 66 74}

	condition:
		2 of them
}

rule Hacktool_This_Cruft : hardened limited
{
	meta:
		description = "Detects string 'This cruft' often used in hack tools like netcat or cryptcat and also mentioned in Project Sauron report"
		author = "Florian Roth"
		reference = "https://goo.gl/eFoP4A"
		date = "2016-08-08"
		score = 60

	strings:
		$x1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 54 68 69 73 20 63 72 75 66 74 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 200KB and $x1 )
}

rule APT_Project_Sauron_Custom_M1 : hardened limited
{
	meta:
		description = "Detects malware from Project Sauron APT"
		author = "FLorian Roth"
		reference = "https://goo.gl/eFoP4A"
		date = "2016-08-09"
		hash1 = "9572624b6026311a0e122835bcd7200eca396802000d0777dba118afaaf9f2a9"

	strings:
		$s1 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 6e 00 63 00 6e 00 66 00 6c 00 6f 00 63 00 2e 00 64 00 6c 00 6c 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s4 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 4e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 20 00 43 00 6f 00 6e 00 66 00 69 00 67 00 75 00 72 00 61 00 74 00 69 00 6f 00 6e 00 20 00 4c 00 6f 00 63 00 61 00 74 00 6f 00 72 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$op0 = { 80 75 6e 85 c0 79 6a 66 41 83 38 0a 75 63 0f b7 }
		$op1 = { 80 75 29 85 c9 79 25 b9 01 }
		$op2 = { 2b d8 48 89 7c 24 38 44 89 6c 24 40 83 c3 08 89 }

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 200KB and ( all of ( $s* ) ) and 1 of ( $op* ) ) or ( all of them )
}

rule APT_Project_Sauron_Custom_M2 : hardened limited
{
	meta:
		description = "Detects malware from Project Sauron APT"
		author = "FLorian Roth"
		reference = "https://goo.gl/eFoP4A"
		date = "2016-08-09"
		hash1 = "30a824155603c2e9d8bfd3adab8660e826d7e0681e28e46d102706a03e23e3a8"

	strings:
		$s2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 5c 2a 5c 33 76 70 6e (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$op0 = { 55 8b ec 83 ec 0c 53 56 33 f6 39 75 08 57 89 75 }
		$op1 = { 59 59 c3 8b 65 e8 ff 75 88 ff 15 50 20 40 00 ff }
		$op2 = { 8b 4f 06 85 c9 74 14 83 f9 12 0f 82 a7 }

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 400KB and ( all of ( $s* ) ) and all of ( $op* ) )
}

rule APT_Project_Sauron_Custom_M3 : hardened limited
{
	meta:
		description = "Detects malware from Project Sauron APT"
		author = "FLorian Roth"
		reference = "https://goo.gl/eFoP4A"
		date = "2016-08-09"
		hash1 = "a4736de88e9208eb81b52f29bab9e7f328b90a86512bd0baadf4c519e948e5ec"

	strings:
		$s1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 45 78 61 6d 70 6c 65 50 72 6f 6a 65 63 74 2e 64 6c 6c (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$op0 = { 8b 4f 06 85 c9 74 14 83 f9 13 0f 82 ba }
		$op1 = { ff 15 34 20 00 10 85 c0 59 a3 60 30 00 10 75 04 }
		$op2 = { 55 8b ec ff 4d 0c 75 09 ff 75 08 ff 15 00 20 00 }

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 1000KB and ( all of ( $s* ) ) and all of ( $op* ) )
}

rule APT_Project_Sauron_Custom_M4 : hardened limited
{
	meta:
		description = "Detects malware from Project Sauron APT"
		author = "FLorian Roth"
		reference = "https://goo.gl/eFoP4A"
		date = "2016-08-09"
		hash1 = "e12e66a6127cfd2cbb42e6f0d57c9dd019b02768d6f1fb44d91f12d90a611a57"

	strings:
		$s1 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 78 00 70 00 73 00 6d 00 6e 00 67 00 72 00 2e 00 64 00 6c 00 6c 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s2 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 58 00 50 00 53 00 20 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$op0 = { 89 4d e8 89 4d ec 89 4d f0 ff d2 3d 08 00 00 c6 }
		$op1 = { 55 8b ec ff 4d 0c 75 09 ff 75 08 ff 15 04 20 5b }
		$op2 = { 8b 4f 06 85 c9 74 14 83 f9 13 0f 82 b6 }

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 90KB and ( all of ( $s* ) ) and 1 of ( $op* ) ) or ( all of them )
}

rule APT_Project_Sauron_Custom_M6 : hardened limited
{
	meta:
		description = "Detects malware from Project Sauron APT"
		author = "FLorian Roth"
		reference = "https://goo.gl/eFoP4A"
		date = "2016-08-09"
		hash1 = "3782b63d7f6f688a5ccb1b72be89a6a98bb722218c9f22402709af97a41973c8"

	strings:
		$s1 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 72 00 73 00 65 00 63 00 65 00 6e 00 67 00 2e 00 64 00 6c 00 6c 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s2 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 52 00 65 00 6d 00 6f 00 74 00 65 00 20 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 20 00 45 00 6e 00 67 00 69 00 6e 00 65 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$op0 = { 8b 0d d5 1d 00 00 85 c9 0f 8e a2 }
		$op1 = { 80 75 6e 85 c0 79 6a 66 41 83 38 0a 75 63 0f b7 }
		$op2 = { 80 75 29 85 c9 79 25 b9 01 }

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 200KB and ( all of ( $s* ) ) and 1 of ( $op* ) ) or ( all of them )
}

rule APT_Project_Sauron_Custom_M7 : hardened limited
{
	meta:
		description = "Detects malware from Project Sauron APT"
		author = "FLorian Roth"
		reference = "https://goo.gl/eFoP4A"
		date = "2016-08-09"
		hash1 = "6c8c93069831a1b60279d2b316fd36bffa0d4c407068dbef81b8e2fe8fd8e8cd"
		hash2 = "7cc0bf547e78c8aaf408495ceef58fa706e6b5d44441fefdce09d9f06398c0ca"

	strings:
		$sx1 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 20 00 75 00 73 00 65 00 72 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$sx2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 48 69 6e 63 6f 72 72 65 63 74 20 68 65 61 64 65 72 20 63 68 65 63 6b (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$sa1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 4d 53 41 4f 53 53 50 43 2e 64 6c 6c (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$sa2 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 4d 00 53 00 41 00 4f 00 53 00 53 00 50 00 43 00 2e 00 44 00 4c 00 4c 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$sa3 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 4d 00 53 00 41 00 4f 00 53 00 53 00 50 00 43 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$sa4 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 41 00 4f 00 4c 00 20 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 20 00 50 00 61 00 63 00 6b 00 61 00 67 00 65 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$sa5 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 41 00 4f 00 4c 00 20 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 20 00 50 00 61 00 63 00 6b 00 61 00 67 00 65 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$sa6 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 41 00 4f 00 4c 00 20 00 43 00 6c 00 69 00 65 00 6e 00 74 00 20 00 66 00 6f 00 72 00 20 00 33 00 32 00 20 00 62 00 69 00 74 00 20 00 70 00 6c 00 61 00 74 00 66 00 6f 00 72 00 6d 00 73 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$op0 = { 8b ce 5b e9 4b ff ff ff 55 8b ec 51 53 8b 5d 08 }
		$op1 = { e8 0a fe ff ff 8b 4d 14 89 46 04 89 41 04 8b 45 }
		$op2 = { e9 29 ff ff ff 83 7d fc 00 0f 84 cf 0a 00 00 8b }
		$op3 = { 83 f8 0c 0f 85 3a 01 00 00 44 2b 41 6c 41 8b c9 }
		$op4 = { 44 39 57 0c 0f 84 d6 0c 00 00 44 89 6f 18 45 89 }
		$op5 = { c1 ed 02 83 c6 fe e9 68 fe ff ff 44 39 57 08 75 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 200KB and ( ( 3 of ( $s* ) and 3 of ( $op* ) ) or ( 1 of ( $sx* ) and 1 of ( $sa* ) ) )
}

