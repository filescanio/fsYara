rule DDosTf : hardened
{
	meta:
		author = "benkow_ - MalwareMustDie"
		reference = "http://blog.malwaremustdie.org/2016/01/mmd-0048-2016-ddostf-new-elf-windows.html"
		description = "Rule to detect ELF.DDosTf infection"
		score = 75

	strings:
		$st0 = {64 64 6f 73 2e 74 66}
		$st1 = {E8 AE BE E7 BD AE 54 43  50 5F 4B 45 45 50 49 4E 54 56 4C E9 94 99 E8 AF AF EF BC 9A 00}
		$st2 = {E8 AE BE E7 BD AE 54 43  50 5F 4B 45 45 50 43 4E 54 E9 94 99 E8 AF AF EF BC 9A 00}
		$st3 = {41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 20 7a 68}
		$st4 = {25 64 20 4b 62 2f 62 70 73 7c 25 64 25 25}

	condition:
		all of them
}

