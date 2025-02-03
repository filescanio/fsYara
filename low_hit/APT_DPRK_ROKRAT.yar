rule ROKRAT_loader : TAU DPRK APT hardened
{
	meta:
		author = "CarbonBlack Threat Research"
		date = "2018-Jan-11"
		description = "Designed to catch loader observed used with ROKRAT malware"
		reference = "https://www.carbonblack.com/2018/02/27/threat-analysis-rokrat-malware/"
		rule_version = 1
		yara_version = "3.7.0"
		TLP = "White"
		exemplar_hashes = "e1546323dc746ed2f7a5c973dcecc79b014b68bdd8a6230239283b4f775f4bbd"

	strings:
		$n1 = {77 73 63 72 69 70 74 2e 65 78 65}
		$n2 = {63 6d 64 2e 65 78 65}
		$s1 = {43 72 65 61 74 65 50 72 6f 63 65 73 73}
		$s2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63}
		$s3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79}
		$s4 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64}
		$s5 = {4c 6f 61 64 52 65 73 6f 75 72 63 65}
		$s6 = {46 69 6e 64 52 65 73 6f 75 72 63 65}
		$b1 = {33 C9 33 C0 E8 00 00 00 00 5E}
		$b2 = /\xB9.{3}\x00\x81\xE9?.{3}\x00/
		$b3 = {03 F1 83 C6 02}
		$b4 = {3E 8A 06 34 90 46}
		$b5 = {3E 30 06 46 49 83 F9 00 75 F6}
		$hpt_1 = {68 EC 97 03 0C}
		$hpt_2 = {68 54 CA AF 91}
		$hpt_3 = {68 8E 4E 0E EC}
		$hpt_4 = {68 AA FC 0D 7C}
		$hpt_5 = {68 1B C6 46 79}
		$hpt_6 = {68 F6 22 B9 7C}
		$henc_1 = {7B FF 84 10 1F}
		$henc_2 = {7B 47 D9 BC 82}
		$henc_3 = {7B 9D 5D 1D EC}
		$henc_4 = {7B B9 EF 1E 6F}
		$henc_5 = {7B 08 D5 55 6A}
		$henc_6 = {7B E5 31 AA 6F}

	condition:
		(1 of ( $n* ) and 4 of ( $s* ) and 4 of ( $b* ) ) or all of ( $hpt* ) or all of ( $henc* )
}

rule ROKRAT_payload : TAU DPRK APT hardened
{
	meta:
		author = "CarbonBlack Threat Research"
		date = "2018-Jan-11"
		description = "Designed to catch loader observed used with ROKRAT malware"
		reference = "https://www.carbonblack.com/2018/02/27/threat-analysis-rokrat-malware/"
		rule_version = 1
		yara_version = "3.7.0"
		TLP = "White"
		exemplar_hashes = "e200517ab9482e787a59e60accc8552bd0c844687cd0cf8ec4238ed2fc2fa573"

	strings:
		$s1 = {61 00 70 00 69 00 2e 00 62 00 6f 00 78 00 2e 00 63 00 6f 00 6d 00 2f 00 6f 00 61 00 75 00 74 00 68 00 32 00 2f 00 74 00 6f 00 6b 00 65 00 6e 00}
		$s2 = {75 00 70 00 6c 00 6f 00 61 00 64 00 2e 00 62 00 6f 00 78 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 70 00 69 00 2f 00 32 00 2e 00 30 00 2f 00 66 00 69 00 6c 00 65 00 73 00 2f 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00}
		$s3 = {61 00 70 00 69 00 2e 00 70 00 63 00 6c 00 6f 00 75 00 64 00 2e 00 63 00 6f 00 6d 00 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 66 00 69 00 6c 00 65 00 3f 00 70 00 61 00 74 00 68 00 3d 00 25 00 73 00 26 00 66 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 3d 00 25 00 73 00 26 00 6e 00 6f 00 70 00 61 00 72 00 74 00 69 00 61 00 6c 00 3d 00 31 00}
		$s4 = {63 00 6c 00 6f 00 75 00 64 00 2d 00 61 00 70 00 69 00 2e 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 6e 00 65 00 74 00 2f 00 76 00 31 00 2f 00 64 00 69 00 73 00 6b 00 2f 00 72 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 3f 00 70 00 61 00 74 00 68 00 3d 00 25 00 73 00}
		$s5 = {53 62 69 65 44 6c 6c 2e 64 6c 6c}
		$s6 = {64 62 67 68 65 6c 70 2e 64 6c 6c}
		$s7 = {61 70 69 5f 6c 6f 67 2e 64 6c 6c}
		$s8 = {64 69 72 5f 77 61 74 63 68 2e 64 6c 6c}
		$s9 = {64 00 65 00 66 00 5f 00 25 00 73 00 2e 00 6a 00 70 00 67 00}
		$s10 = {70 00 68 00 6f 00 5f 00 25 00 73 00 5f 00 25 00 64 00 2e 00 6a 00 70 00 67 00}
		$s11 = {6c 00 6f 00 67 00 69 00 6e 00 3d 00 25 00 73 00 26 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 3d 00 25 00 73 00 26 00 6c 00 6f 00 67 00 69 00 6e 00 5f 00 73 00 75 00 62 00 6d 00 69 00 74 00 3d 00 41 00 75 00 74 00 68 00 6f 00 72 00 69 00 7a 00 69 00 6e 00 67 00}
		$s12 = {67 64 69 70 6c 75 73 2e 64 6c 6c}
		$s13 = {53 00 65 00 74 00 2d 00 43 00 6f 00 6f 00 6b 00 69 00 65 00 3a 00 5c 00 62 00 2a 00 7b 00 2e 00 2b 00 3f 00 7d 00 5c 00 6e 00}
		$s14 = {63 00 68 00 61 00 72 00 73 00 65 00 74 00 3d 00 7b 00 5b 00 41 00 2d 00 5a 00 61 00 2d 00 7a 00 30 00 2d 00 39 00 5c 00 2d 00 5f 00 5d 00 2b 00 7d 00}

	condition:
		12 of ( $s* )
}

