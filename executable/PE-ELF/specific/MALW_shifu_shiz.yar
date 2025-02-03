rule shifu_shiz : hardened
{
	meta:
		description = "Memory string yara for Shifu/Shiz"
		author = "J from THL <j@techhelplist.com>"
		reference1 = "https://researchcenter.paloaltonetworks.com/2017/01/unit42-2016-updates-shifu-banking-trojan/"
		reference2 = "https://beta.virusbay.io/sample/browse/24a6dfaa98012a839658c143475a1e46"
		reference3 = "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/crime_shifu_trojan.yar"
		date = "2018-03-16"
		maltype1 = "Banker"
		maltype2 = "Keylogger"
		maltype3 = "Stealer"
		filetype = "memory"
		score = 75

	strings:
		$aa = {61 75 74 68 5f 6c 6f 67 69 6e 42 79 50 61 73 73 77 6f 72 64}
		$ab = {62 61 63 6b 5f 63 6f 6d 6d 61 6e 64}
		$ac = {62 61 63 6b 5f 63 75 73 74 6f 6d 31}
		$ad = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61}
		$ae = {69 65 78 70 6c 6f 72 65 2e 65 78 65 7c 6f 70 65 72 61 2e 65 78 65 7c 6a 61 76 61 2e 65 78 65 7c 6a 61 76 61 77 2e 65 78 65 7c 65 78 70 6c 6f 72 65 72 2e 65 78 65 7c 69 73 63 6c 69 65 6e 74 2e 65 78 65 7c 69 6e 74 70 72 6f 2e 65 78 65 7c 69 70 63 5f 66 75 6c 6c 2e 65 78 65}
		$af = {6d 6e 70 2e 65 78 65 7c 63 62 73 6d 61 69 6e 2e 64 6c 6c 7c 66 69 72 65 66 6f 78 2e 65 78 65 7c 63 6c 6d 61 69 6e 2e 65 78 65 7c 63 6f 72 65 2e 65 78 65 7c 6d 61 78 74 68 6f 6e 2e 65 78 65 7c 61 76 61 6e 74 2e 65 78 65 7c 73 61 66 61 72 69 2e 65 78 65}
		$ag = {73 76 63 68 6f 73 74 2e 65 78 65 7c 63 68 72 6f 6d 65 2e 65 78 65 7c 6e 6f 74 65 70 61 64 2e 65 78 65 7c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 7c 6e 65 74 73 63 61 70 65 2e 65 78 65 7c 74 62 62 2d 66 69 72 65 66 6f 78 2e 65 78 65 7c 66 72 64 2e 65 78 65}
		$ah = {21 69 6e 6a 65 63 74}
		$ai = {21 64 65 61 63 74 69 76 65 62 63}
		$aj = {21 6b 69 6c 6c 5f 6f 73}
		$ak = {21 6c 6f 61 64}
		$al = {21 6e 65 77 5f 63 6f 6e 66 69 67}
		$am = {21 61 63 74 69 76 65 62 63}
		$an = {6b 65 79 6c 6f 67 2e 74 78 74}
		$ao = {6b 65 79 73 5f 70 61 74 68 2e 74 78 74}
		$ap = {70 61 73 73 2e 6c 6f 67}
		$aq = {70 61 73 73 77 6f 72 64 73 2e 74 78 74}
		$ar = {43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65 3d 22 66 69 6c 65 22 3b 20 66 69 6c 65 6e 61 6d 65 3d 22 72 65 70 6f 72 74 22}
		$as = {43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65 3d 22 70 63 6e 61 6d 65 22}
		$at = {62 6f 74 69 64 3d 25 73 26 76 65 72 3d}
		$au = {61 63 74 69 6f 6e 3d 61 75 74 68 26 6e 70 3d 26 6c 6f 67 69 6e 3d}
		$av = {26 63 74 6c 30 30 25 32 34 4d 61 69 6e 4d 65 6e 75 25 32 34 4c 6f 67 69 6e 31 25 32 34 55 73 65 72 4e 61 6d 65 3d}
		$aw = {26 63 76 76 3d}
		$ax = {26 63 76 76 32 3d}
		$ay = {26 64 6f 6d 61 69 6e 3d}
		$az = {4c 4f 47 49 4e 5f 41 55 54 48 4f 52 49 5a 41 54 49 4f 4e 5f 43 4f 44 45 3d}
		$ba = {6e 61 6d 65 3d 25 73 26 70 6f 72 74 3d 25 75}
		$bb = {50 65 65 6b 4e 61 6d 65 64 50 69 70 65}
		$bc = {5b 70 73 74 5d}
		$bd = {5b 72 65 74 5d}
		$be = {5b 74 61 62 5d}
		$bf = {5b 62 6b 73 5d}
		$bg = {5b 64 65 6c 5d}
		$bh = {5b 69 6e 73 5d}
		$bi = {26 75 70 3d 25 75 26 6f 73 3d 25 30 33 75 26 72 69 67 68 74 73 3d 25 73 26 6c 74 69 6d 65 3d 25 73 25 64 26 74 6f 6b 65 6e 3d 25 64 26 63 6e 3d}

	condition:
		18 of them
}

