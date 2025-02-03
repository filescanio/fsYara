rule OlyxCode : Olyx Family hardened
{
	meta:
		description = "Olyx code tricks"
		author = "Seth Hardy"
		last_modified = "2014-06-19"

	strings:
		$six = { C7 40 04 36 36 36 36 C7 40 08 36 36 36 36 }
		$slash = { C7 40 04 5C 5C 5C 5C C7 40 08 5C 5C 5C 5C }

	condition:
		any of them
}

rule OlyxStrings : Olyx Family hardened
{
	meta:
		description = "Olyx Identifying Strings"
		author = "Seth Hardy"
		last_modified = "2014-06-19"

	strings:
		$ = {2f 41 70 70 6c 69 63 61 74 69 6f 6e 73 2f 41 75 74 6f 6d 61 74 6f 72 2e 61 70 70 2f 43 6f 6e 74 65 6e 74 73 2f 4d 61 63 4f 53 2f 44 6f 63 6b 4c 69 67 68 74}

	condition:
		any of them
}

rule Olyx : Family hardened
{
	meta:
		description = "Olyx"
		author = "Seth Hardy"
		last_modified = "2014-06-19"

	condition:
		OlyxCode or OlyxStrings
}

