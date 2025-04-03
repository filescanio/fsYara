private rule is__elf : hardened
{
	meta:
		author = "@mmorenog,@yararules"

	strings:
		$header = { 7F 45 4C 46 }

	condition:
		$header at 0
}

rule is__Mirai_gen7 : hardened loosened limited
{
	meta:
		description = "Generic detection for MiraiX version 7"
		reference = "http://blog.malwaremustdie.org/2016/08/mmd-0056-2016-linuxmirai-just.html"
		author = "unixfreaxjp"
		org = "MalwareMustDie"
		date = "2018-01-05"
		score = 70

	strings:
		$st01 = {((2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 72 6d) | (2f 00 62 00 69 00 6e 00 2f 00 62 00 75 00 73 00 79 00 62 00 6f 00 78 00 20 00 72 00 6d 00))}
		$st02 = {((2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 65 63 68 6f) | (2f 00 62 00 69 00 6e 00 2f 00 62 00 75 00 73 00 79 00 62 00 6f 00 78 00 20 00 65 00 63 00 68 00 6f 00))}
		$st03 = {((2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 77 67 65 74) | (2f 00 62 00 69 00 6e 00 2f 00 62 00 75 00 73 00 79 00 62 00 6f 00 78 00 20 00 77 00 67 00 65 00 74 00))}
		$st04 = {((2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 74 66 74 70) | (2f 00 62 00 69 00 6e 00 2f 00 62 00 75 00 73 00 79 00 62 00 6f 00 78 00 20 00 74 00 66 00 74 00 70 00))}
		$st05 = {((2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 63 70) | (2f 00 62 00 69 00 6e 00 2f 00 62 00 75 00 73 00 79 00 62 00 6f 00 78 00 20 00 63 00 70 00))}
		$st06 = {((2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 63 68 6d 6f 64) | (2f 00 62 00 69 00 6e 00 2f 00 62 00 75 00 73 00 79 00 62 00 6f 00 78 00 20 00 63 00 68 00 6d 00 6f 00 64 00))}
		$st07 = {((2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 63 61 74) | (2f 00 62 00 69 00 6e 00 2f 00 62 00 75 00 73 00 79 00 62 00 6f 00 78 00 20 00 63 00 61 00 74 00))}

	condition:
		5 of them
}

