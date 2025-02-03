rule xRAT20 : RAT hardened
{
	meta:
		author = "Rottweiler"
		date = "2015-08-20"
		description = "Identifies xRAT 2.0 samples"
		maltype = "Remote Access Trojan"
		hash0 = "cda610f9cba6b6242ebce9f31faf5d9c"
		hash1 = "60d7b0d2dfe937ac6478807aa7043525"
		hash2 = "d1b577fbfd25cc5b873b202cfe61b5b8"
		hash3 = "1820fa722906569e3f209d1dab3d1360"
		hash4 = "8993b85f5c138b0afacc3ff04a2d7871"
		hash5 = "0c231ed8a800b0f17f897241f1d5f4e3"
		hash1 = "60d7b0d2dfe937ac6478807aa7043525"
		hash8 = "2c198e3e0e299a51e5d955bb83c62a5e"
		sample_filetype = "exe"
		yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"

	strings:
		$string0 = {47 00 65 00 74 00 44 00 69 00 72 00 65 00 63 00 74 00 6f 00 72 00 79 00 3a 00 20 00 46 00 69 00 6c 00 65 00 20 00 6e 00 6f 00 74 00 20 00 66 00 6f 00 75 00 6e 00 64 00}
		$string1 = {3c 3e 6d 5f 5f 46 69 6e 61 6c 6c 79 38}
		$string2 = {53 65 63 75 72 65}
		$string3 = {52 65 76 65 72 73 65 50 72 6f 78 79 43 6c 69 65 6e 74}
		$string4 = {44 72 69 76 65 44 69 73 70 6c 61 79 4e 61 6d 65}
		$string5 = {3c 49 73 45 72 72 6f 72 3e 6b 5f 5f 42 61 63 6b 69 6e 67 46 69 65 6c 64}
		$string6 = {73 65 74 5f 49 6e 73 74 61 6c 6c 50 61 74 68}
		$string7 = {6d 65 6d 63 6d 70}
		$string8 = {75 72 6c 48 69 73 74 6f 72 79}
		$string9 = {73 65 74 5f 41 6c 6c 6f 77 41 75 74 6f 52 65 64 69 72 65 63 74}
		$string10 = {6c 70 49 6e 69 74 44 61 74 61}
		$string11 = {72 65 61 64 65 72}
		$string12 = {3c 46 72 6f 6d 52 61 77 44 61 74 61 47 6c 6f 62 61 6c 3e 64 5f 5f 66}
		$string13 = {6d 00 71 00 2e 00 70 00 6e 00 67 00}
		$string14 = {72 65 6d 6f 76 65 5f 4b 65 79 44 6f 77 6e}
		$string15 = {50 72 6f 74 65 63 74 65 64 44 61 74 61}
		$string16 = {6d 5f 68 6f 74 6b 65 79 73}
		$string17 = {67 65 74 5f 48 6f 75 72}
		$string18 = {5c 00 6d 00 6f 00 7a 00 67 00 6c 00 75 00 65 00 2e 00 64 00 6c 00 6c 00}

	condition:
		18 of them
}

