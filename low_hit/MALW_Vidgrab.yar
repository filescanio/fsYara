rule VidgrabCode : Vidgrab Family hardened
{
	meta:
		description = "Vidgrab code tricks"
		author = "Seth Hardy"
		last_modified = "2014-06-20"

	strings:
		$divbyzero = { B8 02 00 00 00 48 48 BA 02 00 00 00 83 F2 02 F7 F0 }
		$xorloop = { 03 C1 80 30 (66 | 58) 41 }
		$junk = { 8B 4? ?? 8B 4? ?? 03 45 08 52 5A }

	condition:
		all of them
}

rule VidgrabStrings : Vidgrab Family hardened
{
	meta:
		description = "Vidgrab Identifying Strings"
		author = "Seth Hardy"
		last_modified = "2014-06-20"

	strings:
		$ = {((49 44 49 5f 49 43 4f 4e 35) | (49 00 44 00 49 00 5f 00 49 00 43 00 4f 00 4e 00 35 00))}
		$ = {73 74 61 72 74 65 72 2e 65 78 65}
		$ = {77 6d 69 66 77 2e 65 78 65}
		$ = {53 6f 66 74 77 61 72 65 5c 72 61 72}
		$ = {74 6d 70 30 39 32 2e 74 6d 70}
		$ = {74 65 6d 70 31 2e 65 78 65}

	condition:
		3 of them
}

rule Vidgrab : Family hardened
{
	meta:
		description = "Vidgrab"
		author = "Seth Hardy"
		last_modified = "2014-06-20"

	condition:
		VidgrabCode or VidgrabStrings
}

