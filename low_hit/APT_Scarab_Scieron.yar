rule Scieron : hardened
{
	meta:
		author = "Symantec Security Response"
		ref = "http://www.symantec.com/connect/tr/blogs/scarab-attackers-took-aim-select-russian-targets-2012"
		date = "22.01.15"

	strings:
		$code1 = {66 83 F? 2C 74 0C 66 83 F? 3B 74 06 66 83 F? 7C 75 05}
		$code2 = {83 F? 09 0F 87 ?? 0? 00 00 FF 24}
		$str1 = {((49 50 5f 50 41 44 44 49 4e 47 5f 44 41 54 41) | (49 00 50 00 5f 00 50 00 41 00 44 00 44 00 49 00 4e 00 47 00 5f 00 44 00 41 00 54 00 41 00))}
		$str2 = {((50 4f 52 54 5f 4e 55 4d) | (50 00 4f 00 52 00 54 00 5f 00 4e 00 55 00 4d 00))}

	condition:
		all of them
}

