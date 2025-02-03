rule sakula_v1_0 : RAT hardened
{
	meta:
		description = "Sakula v1.0"
		date = "2015-10-13"
		author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"

	strings:
		$m1 = {25 64 5f 6f 66 5f 25 64 5f 66 6f 72 5f 25 73 5f 6f 6e 5f 25 73}
		$m2 = {2f 63 20 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 26 20 64 65 6c 20 2f 71 20 22 25 73 22}
		$m3 = {3d 25 73 26 74 79 70 65 3d 25 64}
		$m4 = {3f 70 68 6f 74 6f 69 64 3d}
		$m5 = {69 65 78 70 6c 6f 72 65 72}
		$m6 = {6e 65 74 20 73 74 61 72 74 20 22 25 73 22}
		$v1_1 = {4d 69 63 72 6f 50 6c 61 79 65 72 55 70 64 61 74 65 2e 65 78 65}
		$MZ = {4d 5a}

	condition:
		$MZ at 0 and all of ( $m* ) and not $v1_1
}

rule sakula_v1_1 : RAT hardened
{
	meta:
		description = "Sakula v1.1"
		date = "2015-10-13"
		author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"

	strings:
		$m1 = {25 64 5f 6f 66 5f 25 64 5f 66 6f 72 5f 25 73 5f 6f 6e 5f 25 73}
		$m2 = {2f 63 20 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 26 20 64 65 6c 20 2f 71 20 22 25 73 22}
		$m3 = {3d 25 73 26 74 79 70 65 3d 25 64}
		$m4 = {3f 70 68 6f 74 6f 69 64 3d}
		$m5 = {69 65 78 70 6c 6f 72 65 72}
		$m6 = {6e 65 74 20 73 74 61 72 74 20 22 25 73 22}
		$v1_1 = {4d 69 63 72 6f 50 6c 61 79 65 72 55 70 64 61 74 65 2e 65 78 65}
		$MZ = {4d 5a}

	condition:
		$MZ at 0 and all of them
}

rule sakula_v1_2 : RAT hardened
{
	meta:
		description = "Sakula v1.2"
		date = "2015-10-13"
		author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"

	strings:
		$m1 = {25 64 5f 6f 66 5f 25 64 5f 66 6f 72 5f 25 73 5f 6f 6e 5f 25 73}
		$m2 = {2f 63 20 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 26 20 64 65 6c 20 2f 71 20 22 25 73 22}
		$m3 = {63 6d 64 2e 65 78 65 20 2f 63 20 72 75 6e 64 6c 6c 33 32 20 22 25 73 22}
		$v1_1 = {4d 69 63 72 6f 50 6c 61 79 65 72 55 70 64 61 74 65 2e 65 78 65}
		$v1_2 = {43 43 50 55 70 64 61 74 65}
		$MZ = {4d 5a}

	condition:
		$MZ at 0 and $m1 and $m2 and $m3 and $v1_2 and not $v1_1
}

rule sakula_v1_3 : RAT hardened
{
	meta:
		description = "Sakula v1.3"
		date = "2015-10-13"
		score = 70
		author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"

	strings:
		$m1 = {25 64 5f 6f 66 5f 25 64 5f 66 6f 72 5f 25 73 5f 6f 6e 5f 25 73}
		$m2 = {2f 63 20 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 26 20 64 65 6c 20 2f 71 20 22 25 73 22}
		$m3 = {63 6d 64 2e 65 78 65 20 2f 63 20 72 75 6e 64 6c 6c 33 32 20 22 25 73 22}
		$v1_3 = { 81 3E 78 03 00 00 75 57  8D 54 24 14 52 68 0C 05 41 00 68 01 00 00 80 FF  15 00 F0 40 00 85 C0 74 10 8B 44 24 14 68 2C 31  41 00 50 FF 15 10 F0 40 00 8B 4C 24 14 51 FF 15  24 F0 40 00 E8 0F 09 00 }
		$MZ = {4d 5a}

	condition:
		$MZ at 0 and all of them
}

rule sakula_v1_4 : RAT hardened
{
	meta:
		description = "Sakula v1.4"
		date = "2015-10-13"
		author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"

	strings:
		$m1 = {25 64 5f 6f 66 5f 25 64 5f 66 6f 72 5f 25 73 5f 6f 6e 5f 25 73}
		$m2 = {2f 63 20 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 26 20 64 65 6c 20 2f 71 20 22 25 73 22}
		$m3 = {63 6d 64 2e 65 78 65 20 2f 63 20 72 75 6e 64 6c 6c 33 32 20 22 25 73 22}
		$v1_4 = { 50 E8 CD FC FF FF 83 C4  04 68 E8 03 00 00 FF D7 56 E8 54 12 00 00 E9 AE  FE FF FF E8 13 F5 FF FF }
		$MZ = {4d 5a}

	condition:
		$MZ at 0 and all of them
}

