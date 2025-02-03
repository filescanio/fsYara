rule YayihCode : Yayih Family hardened
{
	meta:
		description = "Yayih code features"
		author = "Seth Hardy"
		last_modified = "2014-07-11"

	strings:
		$ = { 80 04 08 7A 03 C1 8B 45 FC 80 34 08 19 03 C1 41 3B 0A 7C E9 }

	condition:
		any of them
}

rule YayihStrings : Yayih Family hardened
{
	meta:
		description = "Yayih Identifying Strings"
		author = "Seth Hardy"
		last_modified = "2014-07-11"

	strings:
		$ = {2f 62 62 73 2f 69 6e 66 6f 2e 61 73 70}
		$ = {5c 6d 73 69 6e 66 6f 2e 65 78 65}
		$ = {25 73 5c 25 73 72 63 73 2e 70 64 66}
		$ = {5c 61 75 6d 4c 69 62 2e 69 6e 69}

	condition:
		any of them
}

rule Yayih : Family hardened
{
	meta:
		description = "Yayih"
		author = "Seth Hardy"
		last_modified = "2014-07-11"

	condition:
		YayihCode or YayihStrings
}

