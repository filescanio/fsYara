rule CryptoLocker_set1 : hardened
{
	meta:
		author = "Christiaan Beek, Christiaan_Beek@McAfee.com"
		date = "2014-04-13"
		description = "Detection of Cryptolocker Samples"

	strings:
		$string0 = {73 74 61 74 69 63}
		$string1 = {20 6b 73 63 64 53}
		$string2 = {52 6f 6d 61 6e 74 69 63}
		$string3 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00}
		$string4 = {50 00 72 00 6f 00 64 00 75 00 63 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00}
		$string5 = {39 25 39 52 39 66 39 71 39}
		$string6 = {49 00 44 00 52 00 5f 00 56 00 45 00 52 00 53 00 49 00 4f 00 4e 00 31 00}
		$string7 = {20 20 3c 2f 74 72 75 73 74 49 6e 66 6f 3e}
		$string8 = {4c 00 6f 00 6f 00 6b 00 46 00 6f 00 72 00}
		$string9 = {3a 6e 3b 74 3b 79 3b}
		$string10 = {20 20 20 20 20 20 20 20 3c 72 65 71 75 65 73 74 65 64 45 78 65 63 75 74 69 6f 6e 4c 65 76 65 6c 20 6c 65 76 65 6c}
		$string11 = {56 00 53 00 5f 00 56 00 45 00 52 00 53 00 49 00 4f 00 4e 00 5f 00 49 00 4e 00 46 00 4f 00}
		$string12 = {32 00 2e 00 30 00 2e 00 31 00 2e 00 30 00}
		$string13 = {3c 61 73 73 65 6d 62 6c 79 20 78 6d 6c 6e 73}
		$string14 = {20 20 3c 74 72 75 73 74 49 6e 66 6f 20 78 6d 6c 6e 73}
		$string15 = {73 72 74 57 64 40 40}
		$string16 = {35 31 35 5d 35 7a 35}
		$string17 = {43 00 3a 00 5c 00 6c 00 5a 00 62 00 76 00 6e 00 6f 00 56 00 65 00 2e 00 65 00 78 00 65 00}

	condition:
		12 of ( $string* )
}

rule CryptoLocker_rule2 : hardened
{
	meta:
		author = "Christiaan Beek, Christiaan_Beek@McAfee.com"
		date = "2014-04-14"
		score = 70
		description = "Detection of CryptoLocker Variants"

	strings:
		$string0 = {32 00 2e 00 30 00 2e 00 31 00 2e 00 37 00}
		$string1 = {20 20 20 20 3c 73 65 63 75 72 69 74 79 3e}
		$string2 = {52 6f 6d 61 6e 74 69 63}
		$string3 = {50 00 72 00 6f 00 64 00 75 00 63 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00}
		$string4 = {39 25 39 52 39 66 39 71 39}
		$string5 = {49 00 44 00 52 00 5f 00 56 00 45 00 52 00 53 00 49 00 4f 00 4e 00 31 00}
		$string6 = {62 75 74 74 6f 6e}
		$string7 = {20 20 20 20 3c 2f 73 65 63 75 72 69 74 79 3e}
		$string8 = {56 00 46 00 69 00 6c 00 65 00 49 00 6e 00 66 00 6f 00}
		$string9 = {4c 00 6f 00 6f 00 6b 00 46 00 6f 00 72 00}
		$string10 = {20 20 20 20 20 20 3c 2f 72 65 71 75 65 73 74 65 64 50 72 69 76 69 6c 65 67 65 73 3e}
		$string11 = {20 75 69 41 63 63 65 73 73}
		$string12 = {20 20 3c 74 72 75 73 74 49 6e 66 6f 20 78 6d 6c 6e 73}
		$string13 = {6c 61 73 74 2e 69 6e 66}
		$string14 = {20 6d 61 6e 69 66 65 73 74 56 65 72 73 69 6f 6e}
		$string15 = {46 00 46 00 46 00 46 00 30 00 34 00 45 00 33 00}
		$string16 = {33 2c 33 31 33 36 33 48 33 50 33 6d 33 75 33 7a 33}

	condition:
		12 of ( $string* )
}

rule SVG_LoadURL : hardened limited
{
	meta:
		description = "Detects a tiny SVG file that loads an URL (as seen in CryptoWall malware infections)"
		author = "Florian Roth"
		reference = "http://goo.gl/psjCCc"
		date = "2015-05-24"
		hash1 = "ac8ef9df208f624be9c7e7804de55318"
		hash2 = "3b9e67a38569ebe8202ac90ad60c52e0"
		hash3 = "7e2be5cc785ef7711282cea8980b9fee"
		hash4 = "4e2c6f6b3907ec882596024e55c2b58b"
		score = 50

	strings:
		$s1 = {3c 2f 73 76 67 3e}
		$s2 = {3c 73 63 72 69 70 74 3e}
		$s3 = {6c 6f 63 61 74 69 6f 6e 2e 68 72 65 66 3d 27 68 74 74 70}

	condition:
		all of ( $s* ) and filesize < 600
}

rule BackdoorFCKG : CTB_Locker_Ransomware hardened
{
	meta:
		author = "ISG"
		date = "2015-01-20"
		reference = "https://blogs.mcafee.com/mcafee-labs/rise-backdoor-fckq-ctb-locker"
		description = "CTB_Locker"

	strings:
		$string0 = {41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41}
		$stringl = {52 4e 44 42 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41}
		$string2 = {6b 65 6d 65 31 33 32 2e 44 4c 4c}
		$string3 = {6b 6c 6f 73 70 61 64 2e 70 64 62}

	condition:
		3 of them
}

