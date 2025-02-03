rule TerminatorRat : RAT hardened
{
	meta:
		description = "Terminator RAT"
		author = "Jean-Philippe Teissier / @Jipe_"
		date = "2013-10-24"
		filetype = "memory"
		version = "1.0"
		ref1 = "http://www.fireeye.com/blog/technical/malware-research/2013/10/evasive-tactics-terminator-rat.html"

	strings:
		$a = {41 63 63 65 6c 6f 72 61 74 6f 72}
		$b = {3c 68 74 6d 6c 3e 3c 74 69 74 6c 65 3e 31 32 33 35 36 3c 2f 74 69 74 6c 65 3e 3c 62 6f 64 79 3e}

	condition:
		all of them
}

rule TROJAN_Notepad_shell_crew : Trojan hardened
{
	meta:
		author = "RSA_IR"
		Date = "4Jun13"
		File = "notepad.exe v 1.1"
		MD5 = "106E63DBDA3A76BEEB53A8BBD8F98927"

	strings:
		$s1 = {37 35 42 41 41 37 37 43 38 34 32 42 45 31 36 38 42 30 46 36 36 43 34 32 43 37 38 38 35 39 39 37}
		$s2 = {42 35 32 33 46 36 33 35 36 36 46 34 30 37 46 33 38 33 34 42 43 43 35 34 41 41 41 33 32 35 32 34}

	condition:
		$s1 or $s2
}

