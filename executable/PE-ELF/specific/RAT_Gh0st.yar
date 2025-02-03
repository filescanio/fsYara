rule APT_WIN_Gh0st_ver : RAT hardened
{
	meta:
		author = "@BryanNolen"
		date = "2012-12"
		type = "APT"
		version = "1.1"
		ref = "Detection of Gh0st RAT server DLL component"
		ref1 = "http://www.mcafee.com/au/resources/white-papers/foundstone/wp-know-your-digital-enemy.pdf"

	strings:
		$library = {64 65 66 6c 61 74 65 20 31 2e 31 2e 34 20 43 6f 70 79 72 69 67 68 74 20 31 39 39 35 2d 32 30 30 32 20 4a 65 61 6e 2d 6c 6f 75 70 20 47 61 69 6c 6c 79}
		$capability = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61}
		$capability1 = {63 61 70 43 72 65 61 74 65 43 61 70 74 75 72 65 57 69 6e 64 6f 77 41}
		$capability2 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64}
		$capability3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79}
		$capability4 = {4c 73 61 52 65 74 72 69 65 76 65 50 72 69 76 61 74 65 44 61 74 61}
		$capability5 = {41 64 6a 75 73 74 54 6f 6b 65 6e 50 72 69 76 69 6c 65 67 65 73}
		$function = {52 65 73 65 74 53 53 44 54}
		$window = {57 69 6e 53 74 61 30 5c 44 65 66 61 75 6c 74}
		$magic = {47 6C 6F 62 61 6C 5C [5-9] 20 25 64}

	condition:
		all of them
}

rule Gh0st : RAT hardened
{
	meta:
		description = "Gh0st"
		author = "botherder https://github.com/botherder"

	strings:
		$ = /(G)host/
		$ = /(i)nflate 1\.1\.4 Copyright 1995-2002 Mark Adler/
		$ = /(d)eflate 1\.1\.4 Copyright 1995-2002 Jean-loup Gailly/
		$ = /(%)s\\shell\\open\\command/
		$ = /(G)etClipboardData/
		$ = /(W)riteProcessMemory/
		$ = /(A)djustTokenPrivileges/
		$ = /(W)inSta0\\Default/
		$ = /(#)32770/
		$ = /(#)32771/
		$ = /(#)32772/
		$ = /(#)32774/

	condition:
		all of them
}

rule gh0st : hardened
{
	meta:
		author = "https://github.com/jackcr/"

	strings:
		$a = { 47 68 30 73 74 ?? ?? ?? ?? ?? ?? ?? ?? 78 9C }
		$b = {47 68 30 73 74 20 55 70 64 61 74 65}

	condition:
		any of them
}

