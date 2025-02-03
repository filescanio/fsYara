rule apt_equation_exploitlib_mutexes : hardened
{
	meta:
		copyright = "Kaspersky Lab"
		description = "Rule to detect Equation group's Exploitation library http://goo.gl/ivt8EW"
		version = "1.0"
		date = "2016-02-15"
		modified = "2023-01-27"
		reference = "http://securelist.com/blog/research/68750/equation-the-death-star-of-malware-galaxy/"
		id = "d060bfd7-fb16-55d3-8a39-1197fdd8e759"

	strings:
		$a1 = {70 00 72 00 6b 00 4d 00 74 00 78 00}
		$a2 = {63 00 6e 00 46 00 6f 00 72 00 6d 00 53 00 79 00 6e 00 63 00 45 00 78 00 46 00 42 00 43 00}
		$a3 = {63 00 6e 00 46 00 6f 00 72 00 6d 00 56 00 6f 00 69 00 64 00 46 00 42 00 43 00}
		$a4 = {63 6e 46 6f 72 6d 53 79 6e 63 45 78 46 42 43}
		$a5 = {63 6e 46 6f 72 6d 56 6f 69 64 46 42 43}

	condition:
		uint16( 0 ) == 0x5A4D and any of ( $a* )
}

rule apt_equation_cryptotable : hardened
{
	meta:
		copyright = "Kaspersky Lab"
		description = "Rule to detect the crypto library used in Equation group malware"
		version = "1.0"
		last_modified = "2015-02-16"
		reference = "https://securelist.com/blog/"
		id = "e7f313a3-8ef8-5363-898a-836a96aaa2ff"

	strings:
		$a = {37 DF E8 B6 C7 9C 0B AE 91 EF F0 3B 90 C6 80 85 5D 19 4B 45 44 12 3C E2 0D 5C 1C 7B C4 FF D6 05 17 14 4F 03 74 1E 41 DA 8F 7D DE 7E 99 F1 35 AC B8 46 93 CE 23 82 07 EB 2B D4 72 71 40 F3 B0 F7 78 D7 4C D1 55 1A 39 83 18 FA E1 9A 56 B1 96 AB A6 30 C5 5F BE 0C 50 C1}

	condition:
		$a
}

rule Equation_Kaspersky_TripleFantasy_1 : hardened
{
	meta:
		description = "Equation Group Malware - TripleFantasy http://goo.gl/ivt8EW"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "b2b2cd9ca6f5864ef2ac6382b7b6374a9fb2cbe9"
		id = "8d2adb3c-70e0-5768-bcfa-be64220064d9"

	strings:
		$s0 = {25 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 25 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 68 00 6e 00 65 00 74 00 63 00 66 00 67 00 2e 00 64 00 6c 00 6c 00}
		$s1 = {25 00 57 00 49 00 4e 00 44 00 49 00 52 00 25 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 61 00 68 00 6c 00 68 00 63 00 69 00 62 00 2e 00 64 00 6c 00 6c 00}
		$s2 = {25 00 57 00 49 00 4e 00 44 00 49 00 52 00 25 00 5c 00 73 00 6a 00 79 00 6e 00 74 00 6d 00 76 00 2e 00 64 00 61 00 74 00}
		$s3 = {47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 7b 00 38 00 63 00 33 00 38 00 65 00 34 00 66 00 33 00 2d 00 35 00 39 00 31 00 66 00 2d 00 39 00 31 00 63 00 66 00 2d 00 30 00 36 00 61 00 36 00 2d 00 36 00 37 00 62 00 38 00 34 00 64 00 38 00 61 00 30 00 31 00 30 00 32 00 7d 00}
		$s4 = {25 00 57 00 49 00 4e 00 44 00 49 00 52 00 25 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 6f 00 77 00 72 00 77 00 62 00 73 00 64 00 69 00}
		$s5 = {43 00 68 00 72 00 6f 00 6d 00 65 00}
		$s6 = {53 74 72 69 6e 67 49 6e 64 65 78}
		$x1 = {69 00 74 00 65 00 6d 00 61 00 67 00 69 00 63 00 2e 00 6e 00 65 00 74 00 40 00 34 00 34 00 33 00}
		$x2 = {74 00 65 00 61 00 6d 00 34 00 68 00 65 00 61 00 74 00 2e 00 6e 00 65 00 74 00 40 00 34 00 34 00 33 00}
		$x5 = {36 00 32 00 2e 00 32 00 31 00 36 00 2e 00 31 00 35 00 32 00 2e 00 36 00 39 00 40 00 34 00 34 00 33 00}
		$x6 = {38 00 34 00 2e 00 32 00 33 00 33 00 2e 00 32 00 30 00 35 00 2e 00 33 00 37 00 40 00 34 00 34 00 33 00}
		$z1 = {77 00 77 00 77 00 2e 00 6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 63 00 6f 00 6d 00 40 00 38 00 30 00}
		$z2 = {77 00 77 00 77 00 2e 00 67 00 6f 00 6f 00 67 00 6c 00 65 00 2e 00 63 00 6f 00 6d 00 40 00 38 00 30 00}
		$z3 = {31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 3a 00 33 00 31 00 32 00 38 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 300000 and ( ( all of ( $s* ) and all of ( $z* ) ) or ( all of ( $s* ) and 1 of ( $x* ) ) )
}

rule Equation_Kaspersky_DoubleFantasy_1 : hardened
{
	meta:
		description = "Equation Group Malware - DoubleFantasy"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "d09b4b6d3244ac382049736ca98d7de0c6787fa2"
		id = "f3c87adf-86c3-5d7c-9532-75341841869a"

	strings:
		$z1 = {6d 73 76 63 70 35 25 64 2e 64 6c 6c}
		$s0 = {61 63 74 78 70 72 78 79 2e 47 65 74 50 72 6f 78 79 44 6c 6c 49 6e 66 6f}
		$s3 = {61 63 74 78 70 72 78 79 2e 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74}
		$s5 = {61 63 74 78 70 72 78 79 2e 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72}
		$s6 = {61 63 74 78 70 72 78 79 2e 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72}
		$x2 = {31 39 31 48 31 61 31}
		$x3 = {4e 6f 76 65 6d 62 65 72 20}
		$x4 = {61 62 61 62 61 62 61 62 61 62 61 62}
		$x5 = {4a 61 6e 75 61 72 79 20}
		$x6 = {4f 63 74 6f 62 65 72 20}
		$x7 = {53 65 70 74 65 6d 62 65 72 20}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 350000 and ( ( $z1 ) or ( all of ( $s* ) and 6 of ( $x* ) ) )
}

rule Equation_Kaspersky_GROK_Keylogger : hardened
{
	meta:
		description = "Equation Group Malware - GROK keylogger"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "50b8f125ed33233a545a1aac3c9d4bb6aa34b48f"
		id = "1bae3e86-54e5-55e9-8bbd-aa9ec2a0fa2b"

	strings:
		$s0 = {63 3a 5c 75 73 65 72 73 5c 72 6d 67 72 65 65 35 5c}
		$s1 = {6d 00 73 00 72 00 74 00 64 00 76 00 2e 00 73 00 79 00 73 00}
		$x1 = {73 76 72 67 2e 70 64 62}
		$x2 = {57 33 32 70 53 65 72 76 69 63 65 54 61 62 6c 65}
		$x3 = {49 6e 20 66 6f 72 6d 61}
		$x4 = {52 65 6c 65 61 73 65 46}
		$x5 = {63 72 69 70 74 6f 72}
		$x6 = {61 73 74 4d 75 74 65 78}
		$x7 = {41 52 41 53 41 54 41 55}
		$x8 = {52 30 6f 6d 70 34 61 72}
		$z1 = {48 2e 74 65 78 74}
		$z2 = {5c 00 72 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 5c 00 6d 00 61 00 63 00 68 00 69 00 6e 00 65 00 5c 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00}
		$z4 = {5c 00 72 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 5c 00 6d 00 61 00 63 00 68 00 69 00 6e 00 65 00 5c 00 53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 30 00 30 00 31 00 5c 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5c 00 53 00 65 00 73 00 73 00 69 00 6f 00 6e 00 20 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 5c 00 45 00 6e 00 76 00 69 00 72 00 6f 00 6e 00 6d 00 65 00 6e 00 74 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 250000 and ( $s0 or ( $s1 and 6 of ( $x* ) ) or ( 6 of ( $x* ) and all of ( $z* ) ) )
}

rule Equation_Kaspersky_GreyFishInstaller : hardened
{
	meta:
		description = "Equation Group Malware - Grey Fish"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "58d15d1581f32f36542f3e9fb4b1fc84d2a6ba35"
		id = "ea16b51c-755e-5f08-a209-d21a1ed30fcf"

	strings:
		$s0 = {44 00 4f 00 47 00 52 00 4f 00 55 00 4e 00 44 00 2e 00 65 00 78 00 65 00}
		$s1 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 43 00 6f 00 6e 00 66 00 69 00 67 00 75 00 72 00 61 00 74 00 69 00 6f 00 6e 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00}
		$s2 = {47 65 74 4d 61 70 70 65 64 46 69 6c 65 6e 61 6d 65 57}

	condition:
		all of them
}

rule Equation_Kaspersky_EquationDrugInstaller : hardened
{
	meta:
		description = "Equation Group Malware - EquationDrug installer LUTEUSOBSTOS"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "61fab1b8451275c7fd580895d9c68e152ff46417"
		id = "fa549e6e-f0d8-55ea-9ec9-c8ec53b55dec"
		score = 75

	strings:
		$s0 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 77 00 69 00 6e 00 33 00 32 00 6b 00 2e 00 73 00 79 00 73 00}
		$s1 = {41 4c 4c 5f 46 49 52 45 57 41 4c 4c 53}
		$x1 = {40 00 70 00 72 00 6b 00 4d 00 74 00 78 00}
		$x2 = {53 00 54 00 41 00 54 00 49 00 43 00}
		$x3 = {77 00 69 00 6e 00 64 00 69 00 72 00}
		$x4 = {63 00 6e 00 46 00 6f 00 72 00 6d 00 56 00 6f 00 69 00 64 00 46 00 42 00 43 00}
		$x5 = {43 00 63 00 6e 00 46 00 6f 00 72 00 6d 00 53 00 79 00 6e 00 63 00 45 00 78 00 46 00 42 00 43 00}
		$x6 = {57 00 69 00 6e 00 53 00 74 00 61 00 4f 00 62 00 6a 00}
		$x7 = {42 00 49 00 4e 00 52 00 45 00 53 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 500000 and all of ( $s* ) and 5 of ( $x* )
}

rule Equation_Kaspersky_EquationLaserInstaller : hardened
{
	meta:
		description = "Equation Group Malware - EquationLaser Installer"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "5e1f56c1e57fbff96d4999db1fd6dd0f7d8221df"
		score = 80
		id = "15fd5668-36f2-556c-8150-225d3cbd4121"

	strings:
		$s0 = {46 61 69 6c 65 64 20 74 6f 20 67 65 74 20 57 69 6e 64 6f 77 73 20 76 65 72 73 69 6f 6e}
		$s1 = {6c 00 73 00 61 00 73 00 72 00 76 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 20 00 61 00 6e 00 64 00 20 00 6c 00 73 00 61 00 73 00 73 00 2e 00 65 00 78 00 65 00}
		$s2 = {5c 5c 25 73 5c 6d 61 69 6c 73 6c 6f 74 5c 25 73}
		$s3 = {25 64 2d 25 64 2d 25 64 20 25 64 3a 25 64 3a 25 64 20 5a}
		$s4 = {6c 73 61 73 72 76 33 32 2e 64 6c 6c}
		$s6 = {25 73 20 25 30 32 78 20 25 73}
		$s7 = {56 49 45 57 45 52 53}
		$s8 = {35 00 2e 00 32 00 2e 00 33 00 37 00 39 00 30 00 2e 00 32 00 32 00 30 00 20 00 28 00 73 00 72 00 76 00 30 00 33 00 5f 00 67 00 64 00 72 00 2e 00 30 00 34 00 30 00 39 00 31 00 38 00 2d 00 31 00 35 00 35 00 32 00 29 00}

	condition:
		( uint16( 0 ) == 0x5a4d ) and filesize < 250000 and 6 of ( $s* )
}

rule Equation_Kaspersky_FannyWorm : hardened
{
	meta:
		description = "Equation Group Malware - Fanny Worm"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/ivt8EW"
		date = "2015-02-16"
		modified = "2023-01-06"
		hash = "1f0ae54ac3f10d533013f74f48849de4e65817a7"
		score = 80
		id = "1b8d1ce6-8926-5aa3-8fba-6a8451d66a7d"

	strings:
		$s1 = {78 3a 5c 66 61 6e 6e 79 2e 62 6d 70}
		$s2 = {33 32 2e 65 78 65}
		$s3 = {64 3a 5c 66 61 6e 6e 79 2e 62 6d 70}
		$x1 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c}
		$x2 = {53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 55 53 42 53 54 4f 52 5c 45 6e 75 6d}
		$x3 = {53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 50 61 72 74 4d 67 72 5c 45 6e 75 6d}
		$x4 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 77 00 69 00 6e 00 33 00 32 00 6b 00 2e 00 73 00 79 00 73 00}
		$x5 = {5c 41 47 45 4e 54 43 50 44 2e 44 4c 4c}
		$x6 = {61 67 65 6e 74 63 70 64 2e 64 6c 6c}
		$x7 = {50 41 44 75 70 64 61 74 65 2e 65 78 65}
		$x8 = {64 6c 6c 5f 69 6e 73 74 61 6c 6c 65 72 2e 64 6c 6c}
		$x9 = {5c 72 65 73 74 6f 72 65 5c}
		$x10 = {51 3a 5c 5f 5f 3f 5f 5f 2e 6c 6e 6b}
		$x11 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 4d 53 4e 65 74 4d 6e 67}
		$x12 = {5c 73 68 65 6c 6c 64 6f 63 2e 64 6c 6c}
		$x13 = {66 69 6c 65 20 73 69 7a 65 20 3d 20 25 64 20 62 79 74 65 73}
		$x14 = {5c 4d 53 41 67 65 6e 74}
		$x15 = {47 6c 6f 62 61 6c 5c 52 50 43 4d 75 74 65 78}
		$x16 = {47 6c 6f 62 61 6c 5c 44 69 72 65 63 74 4d 61 72 6b 65 74 69 6e 67}

	condition:
		( uint16( 0 ) == 0x5a4d ) and filesize < 300000 and ( ( 2 of ( $s* ) ) or ( 1 of ( $s* ) and 6 of ( $x* ) ) or ( 14 of ( $x* ) ) )
}

rule Equation_Kaspersky_HDD_reprogramming_module : hardened
{
	meta:
		description = "Equation Group Malware - HDD reprogramming module"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "ff2b50f371eb26f22eb8a2118e9ab0e015081500"
		id = "09ffe270-39e7-5225-b4a9-1c8d312a09c1"

	strings:
		$s0 = {6e 6c 73 5f 39 33 33 77 2e 64 6c 6c}
		$s1 = {42 00 49 00 4e 00 41 00 52 00 59 00}
		$s2 = {4b 66 41 63 71 75 69 72 65 53 70 69 6e 4c 6f 63 6b}
		$s3 = {48 41 4c 2e 64 6c 6c}
		$s4 = {52 45 41 44 5f 52 45 47 49 53 54 45 52 5f 55 43 48 41 52}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 300000 and all of ( $s* )
}

rule Equation_Kaspersky_EOP_Package : hardened
{
	meta:
		description = "Equation Group Malware - EoP package and malware launcher"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "2bd1b1f5b4384ce802d5d32d8c8fd3d1dc04b962"
		id = "2eb97873-a415-57be-a8fb-70ef86a99c9b"

	strings:
		$s0 = {61 62 61 62 61 62 61 62 61 62 61 62}
		$s1 = {61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71}
		$s2 = {40 00 53 00 54 00 41 00 54 00 49 00 43 00}
		$s3 = {24 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61}
		$s4 = {40 00 70 00 72 00 6b 00 4d 00 74 00 78 00}
		$s5 = {70 00 72 00 6b 00 4d 00 74 00 78 00}
		$s6 = {63 00 6e 00 46 00 6f 00 72 00 6d 00 56 00 6f 00 69 00 64 00 46 00 42 00 43 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 100000 and all of ( $s* )
}

rule Equation_Kaspersky_TripleFantasy_Loader : hardened
{
	meta:
		description = "Equation Group Malware - TripleFantasy Loader"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "4ce6e77a11b443cc7cbe439b71bf39a39d3d7fa3"
		id = "562e7855-f011-5985-91c0-622b2fec32f8"

	strings:
		$x1 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 20 00 49 00 6e 00 6e 00 6f 00 76 00 61 00 74 00 69 00 6f 00 6e 00 73 00 2c 00 20 00 4c 00 4c 00 43 00}
		$x2 = {4d 00 6f 00 6e 00 69 00 74 00 65 00 72 00 20 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 20 00 50 00 72 00 6f 00 74 00 6f 00 63 00 6f 00 6c 00}
		$x3 = {61 00 68 00 6c 00 68 00 63 00 69 00 62 00 2e 00 64 00 6c 00 6c 00}
		$s0 = {68 6e 65 74 63 66 67 2e 48 4e 65 74 47 65 74 53 68 61 72 69 6e 67 53 65 72 76 69 63 65 73 50 61 67 65}
		$s1 = {68 6e 65 74 63 66 67 2e 49 63 66 47 65 74 4f 70 65 72 61 74 69 6f 6e 61 6c 4d 6f 64 65}
		$s2 = {68 6e 65 74 63 66 67 2e 49 63 66 47 65 74 44 79 6e 61 6d 69 63 46 77 50 6f 72 74 73}
		$s3 = {68 6e 65 74 63 66 67 2e 48 4e 65 74 46 72 65 65 46 69 72 65 77 61 6c 6c 4c 6f 67 67 69 6e 67 53 65 74 74 69 6e 67 73}
		$s4 = {68 6e 65 74 63 66 67 2e 48 4e 65 74 47 65 74 53 68 61 72 65 41 6e 64 42 72 69 64 67 65 53 65 74 74 69 6e 67 73}
		$s5 = {68 6e 65 74 63 66 67 2e 48 4e 65 74 47 65 74 46 69 72 65 77 61 6c 6c 53 65 74 74 69 6e 67 73 50 61 67 65}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 50000 and ( all of ( $x* ) and all of ( $s* ) )
}

rule Equation_Kaspersky_SuspiciousString : hardened
{
	meta:
		description = "Equation Group Malware - suspicious string found in sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/17"
		score = 60
		id = "a5f203a7-0c50-5658-89f4-44533ed4eef0"

	strings:
		$s1 = {69 33 38 36 5c 44 65 73 65 72 74 57 69 6e 74 65 72 44 72 69 76 65 72 2e 70 64 62}
		$s2 = {50 65 72 66 6f 72 6d 69 6e 67 20 55 52 2d 73 70 65 63 69 66 69 63 20 70 6f 73 74 2d 69 6e 73 74 61 6c 6c 2e 2e 2e}
		$s3 = {54 69 6d 65 6f 75 74 20 77 61 69 74 69 6e 67 20 66 6f 72 20 74 68 65 20 22 63 61 6e 49 6e 73 74 61 6c 6c 4e 6f 77 22 20 65 76 65 6e 74 20 66 72 6f 6d 20 74 68 65 20 69 6d 70 6c 61 6e 74 2d 73 70 65 63 69 66 69 63 20 45 58 45 21}
		$s4 = {53 54 52 41 49 54 53 48 4f 4f 54 45 52 33 30 2e 65 78 65}
		$s5 = {73 74 61 6e 64 61 6c 6f 6e 65 67 72 6f 6b 5f 32 2e 31 2e 31 2e 31}
		$s6 = {63 3a 5c 75 73 65 72 73 5c 72 6d 67 72 65 65 35 5c}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 500000 and all of ( $s* )
}

rule EquationDrug_NetworkSniffer1 : hardened
{
	meta:
		description = "EquationDrug - Backdoor driven by network sniffer - mstcp32.sys, fat32.sys"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
		date = "2015/03/11"
		modified = "2023-01-06"
		hash = "26e787997a338d8111d96c9a4c103cf8ff0201ce"
		id = "21a500e7-3011-50e6-b685-f4f65d6dee17"

	strings:
		$s0 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 28 00 52 00 29 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 28 00 54 00 4d 00 29 00 20 00 4f 00 70 00 65 00 72 00 61 00 74 00 69 00 6e 00 67 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00}
		$s1 = {5c 00 52 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 5c 00 55 00 73 00 65 00 72 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 55 00 73 00 65 00 72 00 5c 00}
		$s3 = {73 79 73 5c 6d 73 74 63 70 33 32 2e 64 62 67}
		$s7 = {6d 00 73 00 74 00 63 00 70 00 33 00 32 00 2e 00 73 00 79 00 73 00}
		$s8 = {70 33 32 2e 73 79 73}
		$s9 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 25 00 77 00 73 00 5f 00 25 00 77 00 73 00}
		$s10 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 25 00 77 00 73 00}
		$s11 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 25 00 77 00 73 00}

	condition:
		all of them
}

rule EquationDrug_CompatLayer_UnilayDLL : hardened
{
	meta:
		description = "EquationDrug - Unilay.DLL"
		author = "Florian Roth (Nextron Systems) @4nc4p"
		reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
		date = "2015/03/11"
		hash = "a3a31937956f161beba8acac35b96cb74241cd0f"
		id = "32fd31c7-cc44-50e1-8888-b9da59ce587b"

	strings:
		$s0 = {75 6e 69 6c 61 79 2e 64 6c 6c}

	condition:
		uint16( 0 ) == 0x5a4d and $s0
}

rule EquationDrug_HDDSSD_Op : hardened
{
	meta:
		description = "EquationDrug - HDD/SSD firmware operation - nls_933w.dll"
		author = "Florian Roth (Nextron Systems) @4nc4p"
		reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
		date = "2015/03/11"
		hash = "ff2b50f371eb26f22eb8a2118e9ab0e015081500"
		id = "e2698f10-49e8-55da-bddc-e5c887f11bc7"

	strings:
		$s0 = {6e 6c 73 5f 39 33 33 77 2e 64 6c 6c}

	condition:
		all of them
}

rule EquationDrug_NetworkSniffer2 : hardened
{
	meta:
		description = "EquationDrug - Network Sniffer - tdip.sys"
		author = "Florian Roth (Nextron Systems) @4nc4p"
		reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
		date = "2015/03/11"
		hash = "7e3cd36875c0e5ccb076eb74855d627ae8d4627f"
		id = "afc5ae23-4965-5796-af3b-9e2705aea455"

	strings:
		$s0 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 28 00 52 00 29 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 28 00 54 00 4d 00 29 00 20 00 4f 00 70 00 65 00 72 00 61 00 74 00 69 00 6e 00 67 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00}
		$s1 = {49 00 50 00 20 00 54 00 72 00 61 00 6e 00 73 00 70 00 6f 00 72 00 74 00 20 00 44 00 72 00 69 00 76 00 65 00 72 00}
		$s2 = {74 00 64 00 69 00 70 00 2e 00 73 00 79 00 73 00}
		$s3 = {73 79 73 5c 74 64 69 70 2e 64 62 67}
		$s4 = {64 69 70 2e 73 79 73}
		$s5 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 25 00 77 00 73 00 5f 00 25 00 77 00 73 00}
		$s6 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 25 00 77 00 73 00}
		$s7 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 25 00 77 00 73 00}

	condition:
		all of them
}

rule EquationDrug_NetworkSniffer3 : hardened
{
	meta:
		description = "EquationDrug - Network Sniffer - tdip.sys"
		author = "Florian Roth (Nextron Systems) @4nc4p"
		reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
		date = "2015/03/11"
		hash = "14599516381a9646cd978cf962c4f92386371040"
		id = "c6b1658b-cbc6-535a-a3a2-15ce3cf6e4f6"

	strings:
		$s0 = {43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 20 00 41 00 6c 00 6c 00 20 00 72 00 69 00 67 00 68 00 74 00 73 00 20 00 72 00 65 00 73 00 65 00 72 00 76 00 65 00 64 00 2e 00}
		$s1 = {49 00 50 00 20 00 54 00 72 00 61 00 6e 00 73 00 70 00 6f 00 72 00 74 00 20 00 44 00 72 00 69 00 76 00 65 00 72 00}
		$s2 = {74 00 64 00 69 00 70 00 2e 00 73 00 79 00 73 00}
		$s3 = {74 64 69 70 2e 70 64 62}

	condition:
		all of them
}

rule EquationDrug_VolRec_Driver : hardened
{
	meta:
		description = "EquationDrug - Collector plugin for Volrec - msrstd.sys"
		author = "Florian Roth (Nextron Systems) @4nc4p"
		reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
		date = "2015/03/11"
		hash = "ee2b504ad502dc3fed62d6483d93d9b1221cdd6c"
		id = "db4f3f65-bdc4-565d-ad59-25a16ec7c9d2"

	strings:
		$s0 = {6d 00 73 00 72 00 73 00 74 00 64 00 2e 00 73 00 79 00 73 00}
		$s1 = {6d 73 72 73 74 64 2e 70 64 62}
		$s2 = {6d 00 73 00 72 00 73 00 74 00 64 00 20 00 64 00 72 00 69 00 76 00 65 00 72 00}

	condition:
		all of them
}

rule EquationDrug_KernelRootkit : hardened
{
	meta:
		description = "EquationDrug - Kernel mode stage 0 and rootkit (Windows 2000 and above) - msndsrv.sys"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
		date = "2015/03/11"
		modified = "2023-01-06"
		hash = "597715224249e9fb77dc733b2e4d507f0cc41af6"
		id = "92491e30-4041-5c8b-8e4e-7bc2b1d3234b"

	strings:
		$s0 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 28 00 52 00 29 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 28 00 54 00 4d 00 29 00 20 00 4f 00 70 00 65 00 72 00 61 00 74 00 69 00 6e 00 67 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00}
		$s1 = {50 61 72 6d 73 6e 64 73 72 76 2e 64 62 67}
		$s2 = {5c 00 52 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 5c 00 55 00 73 00 65 00 72 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 55 00 73 00 65 00 72 00 5c 00}
		$s3 = {6d 00 73 00 6e 00 64 00 73 00 72 00 76 00 2e 00 73 00 79 00 73 00}
		$s5 = {5c 00 52 00 45 00 47 00 49 00 53 00 54 00 52 00 59 00 5c 00 4d 00 41 00 43 00 48 00 49 00 4e 00 45 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00}
		$s6 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 25 00 77 00 73 00 5f 00 25 00 77 00 73 00}
		$s7 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 25 00 77 00 73 00}
		$s9 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 25 00 77 00 73 00}

	condition:
		all of them
}

rule EquationDrug_Keylogger : hardened
{
	meta:
		description = "EquationDrug - Key/clipboard logger driver - msrtvd.sys"
		author = "Florian Roth (Nextron Systems) @4nc4p"
		reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
		date = "2015/03/11"
		hash = "b93aa17b19575a6e4962d224c5801fb78e9a7bb5"
		id = "57b6af34-577b-58ec-9a9e-91911c32270b"

	strings:
		$s0 = {5c 00 72 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 5c 00 6d 00 61 00 63 00 68 00 69 00 6e 00 65 00 5c 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00}
		$s2 = {5c 00 72 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 5c 00 6d 00 61 00 63 00 68 00 69 00 6e 00 65 00 5c 00 53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 30 00 30 00 31 00 5c 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5c 00 53 00 65 00 73 00 73 00 69 00 6f 00 6e 00 20 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 5c 00 45 00 6e 00}
		$s3 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 47 00 6b 00}
		$s5 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 47 00 6b 00 30 00}

	condition:
		all of them
}

rule EquationDrug_NetworkSniffer4 : hardened
{
	meta:
		description = "EquationDrug - Network-sniffer/patcher - atmdkdrv.sys"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
		date = "2015/03/11"
		modified = "2023-01-06"
		hash = "cace40965f8600a24a2457f7792efba3bd84d9ba"
		id = "12bb1eb3-a14e-5616-bc7c-249c83f97035"

	strings:
		$s0 = {43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 31 00 39 00 39 00 39 00 20 00 52 00 41 00 56 00 49 00 53 00 45 00 4e 00 54 00 20 00 54 00 65 00 63 00 68 00 6e 00 6f 00 6c 00 6f 00 67 00 69 00 65 00 73 00 20 00 49 00 6e 00 63 00 2e 00}
		$s1 = {5c 73 79 73 74 65 6d 72 6f 6f 74 5c}
		$s2 = {52 00 41 00 56 00 49 00 53 00 45 00 4e 00 54 00 20 00 54 00 65 00 63 00 68 00 6e 00 6f 00 6c 00 6f 00 67 00 69 00 65 00 73 00 20 00 49 00 6e 00 63 00 2e 00}
		$s3 = {43 00 72 00 65 00 61 00 74 00 65 00 64 00 20 00 62 00 79 00 20 00 56 00 49 00 4f 00 4e 00 41 00 20 00 44 00 65 00 76 00 65 00 6c 00 6f 00 70 00 6d 00 65 00 6e 00 74 00}
		$s4 = {5c 00 52 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 5c 00 55 00 73 00 65 00 72 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 55 00 73 00 65 00 72 00 5c 00}
		$s5 = {5c 00 64 00 65 00 76 00 69 00 63 00 65 00 5c 00 68 00 61 00 72 00 64 00 64 00 69 00 73 00 6b 00 76 00 6f 00 6c 00 75 00 6d 00 65 00}
		$s7 = {41 00 54 00 4d 00 44 00 4b 00 44 00 52 00 56 00 2e 00 53 00 59 00 53 00}
		$s8 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 25 00 77 00 73 00 5f 00 25 00 77 00 73 00}
		$s9 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 25 00 77 00 73 00}
		$s10 = {43 00 69 00 6e 00 65 00 4d 00 61 00 73 00 74 00 65 00 72 00 20 00 43 00 20 00 31 00 2e 00 31 00 20 00 57 00 44 00 4d 00 20 00 4d 00 61 00 69 00 6e 00 20 00 44 00 72 00 69 00 76 00 65 00 72 00}
		$s11 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 25 00 77 00 73 00}
		$s13 = {43 00 69 00 6e 00 65 00 4d 00 61 00 73 00 74 00 65 00 72 00 20 00 43 00 20 00 31 00 2e 00 31 00 20 00 57 00 44 00 4d 00}

	condition:
		all of them
}

rule EquationDrug_PlatformOrchestrator : hardened
{
	meta:
		description = "EquationDrug - Platform orchestrator - mscfg32.dll, svchost32.dll"
		author = "Florian Roth (Nextron Systems) @4nc4p"
		reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
		date = "2015/03/11"
		hash = "febc4f30786db7804008dc9bc1cebdc26993e240"
		id = "ce19ed3c-9dd9-5cb0-99fe-c04fde057293"

	strings:
		$s0 = {53 00 45 00 52 00 56 00 49 00 43 00 45 00 53 00 2e 00 45 00 58 00 45 00}
		$s1 = {5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 2e 00 63 00 6f 00 6d 00}
		$s2 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 28 00 52 00 29 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 28 00 54 00 4d 00 29 00 20 00 4f 00 70 00 65 00 72 00 61 00 74 00 69 00 6e 00 67 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00}
		$s3 = {4c 00 53 00 41 00 53 00 53 00 2e 00 45 00 58 00 45 00}
		$s4 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 43 00 6f 00 6e 00 66 00 69 00 67 00 75 00 72 00 61 00 74 00 69 00 6f 00 6e 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00}
		$s8 = {75 6e 69 6c 61 79 2e 64 6c 6c}

	condition:
		all of them
}

rule EquationDrug_NetworkSniffer5 : hardened
{
	meta:
		description = "EquationDrug - Network-sniffer/patcher - atmdkdrv.sys"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
		date = "2015/03/11"
		modified = "2023-01-06"
		hash = "09399b9bd600d4516db37307a457bc55eedcbd17"
		id = "9eac2c51-3ad7-5346-a985-39733bc204c2"

	strings:
		$s0 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 28 00 52 00 29 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 28 00 54 00 4d 00 29 00 20 00 4f 00 70 00 65 00 72 00 61 00 74 00 69 00 6e 00 67 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00}
		$s1 = {5c 00 52 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 5c 00 55 00 73 00 65 00 72 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 55 00 73 00 65 00 72 00 5c 00}
		$s2 = {61 00 74 00 6d 00 64 00 6b 00 64 00 72 00 76 00 2e 00 73 00 79 00 73 00}
		$s4 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 25 00 77 00 73 00 5f 00 25 00 77 00 73 00}
		$s5 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 25 00 77 00 73 00}
		$s6 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 25 00 77 00 73 00}

	condition:
		all of them
}

rule EquationDrug_FileSystem_Filter : hardened
{
	meta:
		description = "EquationDrug - Filesystem filter driver - volrec.sys, scsi2mgr.sys"
		author = "Florian Roth (Nextron Systems) @4nc4p"
		reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
		date = "2015/03/11"
		hash = "57fa4a1abbf39f4899ea76543ebd3688dcc11e13"
		id = "7077daf6-3d51-5ff2-bc74-95cb169a7cd2"

	strings:
		$s0 = {76 00 6f 00 6c 00 72 00 65 00 63 00 2e 00 73 00 79 00 73 00}
		$s1 = {76 6f 6c 72 65 63 2e 70 64 62}
		$s2 = {56 00 6f 00 6c 00 75 00 6d 00 65 00 20 00 72 00 65 00 63 00 6f 00 67 00 6e 00 69 00 7a 00 65 00 72 00 20 00 64 00 72 00 69 00 76 00 65 00 72 00}

	condition:
		all of them
}

rule apt_equation_keyword : hardened
{
	meta:
		description = "Rule to detect Equation group's keyword in executable file"
		last_modified = "2015-09-26"
		reference = "http://securelist.com/blog/research/68750/equation-the-death-star-of-malware-galaxy/"
		id = "a7d4eda5-f390-5099-9c46-bf74a878b4f0"

	strings:
		$a1 = {42 00 61 00 63 00 6b 00 73 00 6e 00 61 00 72 00 66 00 5f 00 41 00 42 00 32 00 35 00}
		$a2 = {42 61 63 6b 73 6e 61 72 66 5f 41 42 32 35}

	condition:
		uint16( 0 ) == 0x5a4d and 1 of ( $a* )
}

