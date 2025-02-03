rule MacControlCode : MacControl Family hardened
{
	meta:
		description = "MacControl code tricks"
		author = "Seth Hardy"
		last_modified = "2014-06-17"

	strings:
		$L4_Accept = { C7 ?? 41 63 63 65 C7 ?? 04 70 74 3A 20 }
		$L4_AcceptLang = { C7 ?? 41 63 63 65 C7 ?? 04 70 74 2D 4C }
		$L4_Pragma = { C7 ?? 50 72 61 67 C7 ?? 04 6D 61 3A 20 }
		$L4_Connection = { C7 ?? 43 6F 6E 6E C7 ?? 04 65 63 74 69 }
		$GEThgif = { C7 ?? 47 45 54 20 C7 ?? 04 2F 68 2E 67 }

	condition:
		all of ( $L4* ) or $GEThgif
}

rule MacControlStrings : MacControl Family hardened
{
	meta:
		description = "MacControl Identifying Strings"
		author = "Seth Hardy"
		last_modified = "2014-06-17"

	strings:
		$ = {48 54 54 50 48 65 61 64 47 65 74}
		$ = {2f 4c 69 62 72 61 72 79 2f 6c 61 75 6e 63 68 65 64}
		$ = {4d 79 20 63 6f 6e 6e 65 63 74 20 65 72 72 6f 72 20 77 69 74 68 20 6e 6f 20 69 70 21}
		$ = {53 65 6e 64 20 46 69 6c 65 20 69 73 20 46 61 69 6c 65 64}
		$ = {2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 59 6f 75 20 48 61 76 65 20 67 6f 74 20 69 74 21 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a}

	condition:
		any of them
}

rule MacControl : Family hardened
{
	meta:
		description = "MacControl"
		author = "Seth Hardy"
		last_modified = "2014-06-16"

	condition:
		MacControlCode or MacControlStrings
}

