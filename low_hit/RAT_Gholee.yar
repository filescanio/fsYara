rule MW_gholee_v1 : v1 hardened
{
	meta:
		Author = "@GelosSnake"
		description = "http://securityaffairs.co/wordpress/28170/cyber-crime/gholee-malware.html"
		date = "2014-08"
		maltype = "Remote Access Trojan"
		sample_filetype = "dll"
		hash0 = "48573a150562c57742230583456b4c02"

	strings:
		$a = {73 61 6e 64 62 6f 78 5f 61 76 67 31 30 5f 76 63 39 5f 53 50 31 5f 32 30 31 31}
		$b = {67 68 6f 6c 65 65}

	condition:
		all of them
}

rule MW_gholee_v2 : v2 hardened
{
	meta:
		author = "@GelosSnake"
		date = "2015-02-12"
		description = "http://securityaffairs.co/wordpress/28170/cyber-crime/gholee-malware.html"
		hash0 = "05523761ca296ec09afdf79477e5f18d"
		hash1 = "08e424ac42e6efa361eccefdf3c13b21"
		hash2 = "5730f925145f1a1cd8380197e01d9e06"
		hash3 = "73461c8578dd9ab86d42984f30c04610"
		sample_filetype = "dll"

	strings:
		$string0 = {52 69 63 68 48 61}
		$string1 = {20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 28 00 28 00 28 00 28 00 28 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 48 00}
		$string2 = {31 24 31 2c 31 34 31 3c 31 44 31 4c 31 54 31 5c 31 64 31 6c 31 74 31}
		$string3 = {3c 38 3b 24 4f 27 20}
		$string4 = {40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a 5b 5c 5d}
		$string5 = {6a 59 50 51 54 56 54 53 6b 6c 6c 5a 54 54 58 52 54 55 69 48 63 65 57 64 61 2f}
		$string6 = {75 72 6e 3a 73 63 68 65 6d 61 73 2d 6d 69 63 72 6f 73 6f 66 74 2d 63 6f 6d 3a 61 73 6d 2e 76 31}
		$string7 = {38 2e 38 34 38 48 38 4f 38 69 38 73 38 79 38}
		$string8 = {77 00 72 00 61 00 70 00 70 00 65 00 72 00 33 00}
		$string9 = {70 77 77 77 77 77 77 77 77}
		$string10 = {53 75 6e 64 61 79}
		$string11 = {59 59 75 54 56 57 68}
		$string12 = {44 44 49 4e 47 50 41 44 44 49 4e 47 58 58 50 41 44 44 49 4e 47 50 41 44 44 49 4e 47 58 58 50 41 44 44 49 4e 47 50 41 44 44 49 4e 47 58 58 50 41 44 44 49 4e 47 50 41 44 44 49 4e 47 58 58 50 41 44 44 49 4e 47 50 41 44 44 49 4e 47 58 58 50 41 44 44 49 4e 47 50 41 44 44 49 4e 47 58 58 50 41 44 44 49 4e}
		$string13 = {79 74 4d 4d 4d 4d 4d 4d 55 62 62 72 72 72 72 72 78 78 78 78 78 78 78 78 72 72 69 55 4d 4d 4d 4d 4d 4d 4d 4d 4d 55 75 7a 74}
		$string15 = {77 00 72 00 61 00 70 00 70 00 65 00 72 00 33 00 20 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 20 00 31 00 2e 00 30 00}
		$string16 = {37 37 41 37 37 39}
		$string17 = {3c 43 3c 47 3c 4d 3c 52 3c 58 3c}
		$string18 = {39 20 39 2d 39 4e 39 58 39 73 39}

	condition:
		18 of them
}

