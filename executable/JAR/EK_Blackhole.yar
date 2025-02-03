rule blackhole2_jar : EK hardened
{
	meta:
		author = "Josh Berry"
		date = "2016-06-27"
		description = "BlackHole2 Exploit Kit Detection"
		hash0 = "86946ec2d2031f2b456e804cac4ade6d"
		sample_filetype = "unknown"
		yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"

	strings:
		$string0 = {6b 30 2f 33 3b 4e}
		$string1 = {67 3a 57 6c 59 30}
		$string2 = {28 77 77 36 4f 75}
		$string3 = {53 4f 55 47 58 5b}
		$string4 = {37 58 32 41 4e 62}
		$string5 = {72 38 4c 3c 3b 7a 59 48 29}
		$string6 = {66 62 65 61 74 62 65 61 2f 66 62 65 61 74 62 65 65 2e 63 6c 61 73 73 50 4b}
		$string7 = {66 62 65 61 74 62 65 61 2f 66 62 65 61 74 62 65 63 2e 63 6c 61 73 73}
		$string8 = {66 62 65 61 74 62 65 61 2f 66 62 65 61 74 62 65 66 2e 63 6c 61 73 73}
		$string9 = {66 62 65 61 74 62 65 61 2f 66 62 65 61 74 62 65 66 2e 63 6c 61 73 73 50 4b}
		$string10 = {66 62 65 61 74 62 65 61 2f 66 62 65 61 74 62 65 61 2e 63 6c 61 73 73}
		$string11 = {66 62 65 61 74 62 65 61 2f 66 62 65 61 74 62 65 62 2e 63 6c 61 73 73 50 4b}
		$string12 = {6e 4f 4a 68 2d 32}
		$string13 = {5b 61 66 3a 46 72}

	condition:
		13 of them
}

rule blackhole2_jar2 : EK hardened
{
	meta:
		author = "Josh Berry"
		date = "2016-06-27"
		description = "BlackHole2 Exploit Kit Detection"
		hash0 = "add1d01ba06d08818ff6880de2ee74e8"
		sample_filetype = "unknown"
		yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"

	strings:
		$string0 = {36 5f 4f 36 64 30 39}
		$string1 = {6a 75 71 69 72 76 73 2e 63 6c 61 73 73 50 4b}
		$string2 = {68 77 2e 63 6c 61 73 73 50 4b}
		$string3 = {61 2e 63 6c 61 73 73 50 4b}
		$string4 = {77 2e 63 6c 61 73 73 75 53 5d 77}
		$string5 = {77 2e 63 6c 61 73 73 50 4b}
		$string6 = {59 45 7d 30 76 43 5a}
		$string7 = {76 29 51 2c 46 66}
		$string8 = {25 38 48 25 74 28}
		$string9 = {68 77 2e 63 6c 61 73 73}
		$string10 = {61 2e 63 6c 61 73 73 6d 56}
		$string11 = {32 43 6e 69 59 46 55}
		$string12 = {6a 75 71 69 72 76 73 2e 63 6c 61 73 73}

	condition:
		12 of them
}

rule blackhole2_jar3 : EK hardened
{
	meta:
		author = "Josh Berry"
		date = "2016-06-27"
		description = "BlackHole2 Exploit Kit Detection"
		hash0 = "c7abd2142f121bd64e55f145d4b860fa"
		sample_filetype = "unknown"
		yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"

	strings:
		$string0 = {36 39 2f 73 6a 5d 5d 6f}
		$string1 = {47 4a 6b 35 4e 64}
		$string2 = {76 63 73 2e 63 6c 61 73 73 75}
		$string3 = {54 3c 45 73 73 42}
		$string4 = {31 76 6d 51 6d 51}
		$string5 = {4b 66 31 45 77 72}
		$string6 = {63 24 57 75 75 75 4b 4b 75 35}
		$string7 = {6d 2e 63 6c 61 73 73 50 4b}
		$string8 = {63 68 63 79 69 68 2e 63 6c 61 73 73 50 4b}
		$string9 = {68 77 2e 63 6c 61 73 73}
		$string10 = {66 27 3b 3b 3b 3b 7b}
		$string11 = {76 63 73 2e 63 6c 61 73 73 50 4b}
		$string12 = {56 62 68 66 5f 36}

	condition:
		12 of them
}

rule blackhole1_jar : hardened
{
	meta:
		author = "Josh Berry"
		date = "2016-06-26"
		description = "BlackHole1 Exploit Kit Detection"
		hash0 = "724acccdcf01cf2323aa095e6ce59cae"
		sample_filetype = "unknown"
		yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"

	strings:
		$string0 = {43 72 65 61 74 65 64 2d 42 79 3a 20 31 2e 36 2e 30 5f 31 38 20 28 53 75 6e 20 4d 69 63 72 6f 73 79 73 74 65 6d 73 20 49 6e 63 2e 29}
		$string1 = {77 6f 72 6b 70 61 63 6b 2f 64 65 63 6f 64 65 72 2e 63 6c 61 73 73 6d 51 5d 53}
		$string2 = {77 6f 72 6b 70 61 63 6b 2f 64 65 63 6f 64 65 72 2e 63 6c 61 73 73 50 4b}
		$string3 = {77 6f 72 6b 70 61 63 6b 2f 65 64 69 74 6f 72 2e 63 6c 61 73 73 50 4b}
		$string4 = {78 6d 6c 65 64 69 74 6f 72 2f 47 55 49 2e 63 6c 61 73 73 6d 4f}
		$string5 = {78 6d 6c 65 64 69 74 6f 72 2f 47 55 49 2e 63 6c 61 73 73 50 4b}
		$string6 = {78 6d 6c 65 64 69 74 6f 72 2f 70 65 65 72 73 2e 63 6c 61 73 73 50 4b}
		$string7 = {76 28 53 69 53 5d 54}
		$string8 = {2c 52 33 54 69 56}
		$string9 = {4d 45 54 41 2d 49 4e 46 2f 4d 41 4e 49 46 45 53 54 2e 4d 46 50 4b}
		$string10 = {78 6d 6c 65 64 69 74 6f 72 2f 50 4b}
		$string11 = {5a 5b 4f 67 38 6f}
		$string12 = {77 6f 72 6b 70 61 63 6b 2f 50 4b}

	condition:
		12 of them
}

