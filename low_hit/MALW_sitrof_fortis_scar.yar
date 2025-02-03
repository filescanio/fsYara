rule sitrof_fortis_scar : hardened
{
	meta:
		author = "J from THL <j@techhelplist.com>"
		date = "2018/23"
		reference1 = "https://www.virustotal.com/#/file/59ab6cb69712d82f3e13973ecc7e7d2060914cea6238d338203a69bac95fd96c/community"
		reference2 = "ETPRO rule 2806032, ETPRO TROJAN Win32.Scar.hhrw POST"
		version = 2
		maltype = "Stealer"
		filetype = "memory"

	strings:
		$a = {3f 67 65 74 26 76 65 72 73 69 6f 6e}
		$b = {3f 72 65 67 26 76 65 72 3d}
		$c = {3f 67 65 74 26 65 78 65}
		$d = {3f 67 65 74 26 64 6f 77 6e 6c 6f 61 64}
		$e = {3f 67 65 74 26 6d 6f 64 75 6c 65}
		$f = {26 76 65 72 3d}
		$g = {26 63 6f 6d 70 3d}
		$h = {26 61 64 64 69 6e 66 6f 3d}
		$i = {25 73 40 25 73 3b 20 25 73 20 25 73 20 22 25 73 22 20 70 72 6f 63 65 73 73 6f 72 28 73 29}
		$j = {55 73 65 72 2d 41 67 65 6e 74 3a 20 66 6f 72 74 69 73}

	condition:
		6 of them
}

