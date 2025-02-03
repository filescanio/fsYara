rule nAspyUpdateCode : nAspyUpdate Family hardened
{
	meta:
		description = "nAspyUpdate code features"
		author = "Seth Hardy"
		last_modified = "2014-07-14"

	strings:
		$ = { 8A 54 24 14 8A 01 32 C2 02 C2 88 01 41 4E 75 F4 }

	condition:
		any of them
}

rule nAspyUpdateStrings : nAspyUpdate Family hardened
{
	meta:
		description = "nAspyUpdate Identifying Strings"
		author = "Seth Hardy"
		last_modified = "2014-07-14"

	strings:
		$ = {5c 68 74 74 70 63 6c 69 65 6e 74 2e 74 78 74}
		$ = {70 61 73 73 77 6f 72 64 20 3c 3d 31 34}
		$ = {2f 25 6c 64 6e 2e 74 78 74}
		$ = {4b 69 6c 6c 20 59 6f 75 00}

	condition:
		any of them
}

rule nAspyUpdate : Family hardened
{
	meta:
		description = "nAspyUpdate"
		author = "Seth Hardy"
		last_modified = "2014-07-14"

	condition:
		nAspyUpdateCode or nAspyUpdateStrings
}

