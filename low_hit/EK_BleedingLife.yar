rule bleedinglife2_adobe_2010_1297_exploit : EK PDF hardened
{
	meta:
		author = "Josh Berry"
		date = "2016-06-26"
		description = "BleedingLife2 Exploit Kit Detection"
		hash0 = "8179a7f91965731daa16722bd95f0fcf"
		sample_filetype = "unknown"
		yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"

	strings:
		$string0 = {67 65 74 53 68 61 72 65 64 53 74 79 6c 65}
		$string1 = {63 75 72 72 65 6e 74 43 6f 75 6e 74}
		$string2 = {53 74 72 69 6e 67}
		$string3 = {73 65 74 53 65 6c 65 63 74 69 6f 6e}
		$string4 = {42 4f 54 54 4f 4d}
		$string5 = {63 6c 61 73 73 54 6f 49 6e 73 74 61 6e 63 65 73 44 69 63 74}
		$string6 = {62 75 74 74 6f 6e 44 6f 77 6e}
		$string7 = {66 6f 63 75 73 52 65 63 74}
		$string8 = {70 69 6c 6c 31 31}
		$string9 = {54 45 58 54 5f 49 4e 50 55 54}
		$string10 = {72 65 73 74 72 69 63 74}
		$string11 = {64 65 66 61 75 6c 74 42 75 74 74 6f 6e 45 6e 61 62 6c 65 64}
		$string12 = {63 6f 70 79 53 74 79 6c 65 73 54 6f 43 68 69 6c 64}
		$string13 = {20 78 6d 6c 6e 73 3a 78 6d 70 4d 4d}
		$string14 = {5f 65 64 69 74 61 62 6c 65}
		$string15 = {63 6c 61 73 73 54 6f 44 65 66 61 75 6c 74 53 74 79 6c 65 73 44 69 63 74}
		$string16 = {49 4d 45 43 6f 6e 76 65 72 73 69 6f 6e 4d 6f 64 65}
		$string17 = {53 63 65 6e 65 20 31}

	condition:
		17 of them
}

rule bleedinglife2_adobe_2010_2884_exploit : EK hardened
{
	meta:
		author = "Josh Berry"
		date = "2016-06-26"
		description = "BleedingLife2 Exploit Kit Detection"
		hash0 = "b22ac6bea520181947e7855cd317c9ac"
		sample_filetype = "unknown"
		yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"

	strings:
		$string0 = {5f 61 75 74 6f 52 65 70 65 61 74}
		$string1 = {65 6d 62 65 64 46 6f 6e 74 73}
		$string2 = {4b 65 79 62 6f 61 72 64 45 76 65 6e 74}
		$string3 = {69 6e 73 74 61 6e 63 65 53 74 79 6c 65 73}
		$string4 = {49 6e 76 61 6c 69 64 61 74 69 6f 6e 54 79 70 65}
		$string5 = {61 75 74 6f 52 65 70 65 61 74}
		$string6 = {67 65 74 53 63 61 6c 65 58}
		$string7 = {52 61 64 69 6f 42 75 74 74 6f 6e 5f 73 65 6c 65 63 74 65 64 44 6f 77 6e 49 63 6f 6e}
		$string8 = {63 6f 6e 66 69 67 55 49}
		$string9 = {64 65 61 63 74 69 76 61 74 65}
		$string10 = {66 6c 2e 63 6f 6e 74 72 6f 6c 73 3a 42 75 74 74 6f 6e}
		$string11 = {5f 6d 6f 75 73 65 53 74 61 74 65 4c 6f 63 6b 65 64}
		$string12 = {66 6c 2e 63 6f 72 65 2e 43 6f 6d 70 6f 6e 65 6e 74 53 68 69 6d}
		$string13 = {74 6f 53 74 72 69 6e 67}
		$string14 = {5f 67 72 6f 75 70}
		$string15 = {61 64 64 52 61 64 69 6f 42 75 74 74 6f 6e}
		$string16 = {69 6e 43 61 6c 6c 4c 61 74 65 72 50 68 61 73 65}
		$string17 = {6f 6c 64 4d 6f 75 73 65 53 74 61 74 65}

	condition:
		17 of them
}

rule bleedinglife2_jar2 : EK hardened
{
	meta:
		author = "Josh Berry"
		date = "2016-06-26"
		description = "BleedingLife2 Exploit Kit Detection"
		hash0 = "2bc0619f9a0c483f3fd6bce88148a7ab"
		sample_filetype = "unknown"
		yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"

	strings:
		$string0 = {4d 45 54 41 2d 49 4e 46 2f 4d 41 4e 49 46 45 53 54 2e 4d 46 50 4b}
		$string1 = {52 65 71 75 69 72 65 64 4a 61 76 61 43 6f 6d 70 6f 6e 65 6e 74 2e 63 6c 61 73 73 50 4b}
		$string2 = {4d 45 54 41 2d 49 4e 46 2f 4a 41 56 41 2e 53 46 6d}
		$string3 = {52 65 71 75 69 72 65 64 4a 61 76 61 43 6f 6d 70 6f 6e 65 6e 74 2e 63 6c 61 73 73}
		$string4 = {4d 45 54 41 2d 49 4e 46 2f 4d 41 4e 49 46 45 53 54 2e 4d 46}
		$string5 = {4d 45 54 41 2d 49 4e 46 2f 4a 41 56 41 2e 44 53 41 50 4b}
		$string6 = {4d 45 54 41 2d 49 4e 46 2f 4a 41 56 41 2e 53 46 50 4b}
		$string7 = {35 45 56 54 77 6b 78}
		$string8 = {4d 45 54 41 2d 49 4e 46 2f 4a 41 56 41 2e 44 53 41 33 68 62}
		$string9 = {79 5c 44 77 20 2d}

	condition:
		9 of them
}

rule bleedinglife2_java_2010_0842_exploit : EK hardened
{
	meta:
		author = "Josh Berry"
		date = "2016-06-26"
		description = "BleedingLife2 Exploit Kit Detection"
		hash0 = "b14ee91a3da82f5acc78abd10078752e"
		sample_filetype = "unknown"
		yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"

	strings:
		$string0 = {4d 45 54 41 2d 49 4e 46 2f 4d 41 4e 49 46 45 53 54 2e 4d 46 4d 61 6e 69 66 65 73 74 2d 56 65 72 73 69 6f 6e 3a 20 31 2e 30}
		$string1 = {54 6f 6f 6c 73 44 65 6d 6f 2e 63 6c 61 73 73 50 4b}
		$string2 = {4d 45 54 41 2d 49 4e 46 2f 73 65 72 76 69 63 65 73 2f 6a 61 76 61 78 2e 73 6f 75 6e 64 2e 6d 69 64 69 2e 73 70 69 2e 4d 69 64 69 44 65 76 69 63 65 50 72 6f 76 69 64 65 72 35}
		$string3 = {43 72 65 61 74 65 64 2d 42 79 3a 20 31 2e 36 2e 30 5f 32 32 20 28 53 75 6e 20 4d 69 63 72 6f 73 79 73 74 65 6d 73 20 49 6e 63 2e 29}
		$string4 = {4d 45 54 41 2d 49 4e 46 2f 50 4b}
		$string5 = {54 6f 6f 6c 73 44 65 6d 6f 2e 63 6c 61 73 73}
		$string6 = {4d 45 54 41 2d 49 4e 46 2f 73 65 72 76 69 63 65 73 2f 50 4b}
		$string7 = {54 6f 6f 6c 73 44 65 6d 6f 53 75 62 43 6c 61 73 73 2e 63 6c 61 73 73 50 4b}
		$string8 = {4d 45 54 41 2d 49 4e 46 2f 4d 41 4e 49 46 45 53 54 2e 4d 46 50 4b}
		$string9 = {54 6f 6f 6c 73 44 65 6d 6f 53 75 62 43 6c 61 73 73 2e 63 6c 61 73 73 65 4e}

	condition:
		9 of them
}

