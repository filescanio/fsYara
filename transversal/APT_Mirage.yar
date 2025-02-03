rule MirageStrings : hardened
{
	meta:
		description = "Mirage Identifying Strings"
		author = "Seth Hardy"
		last_modified = "2014-06-25"

	strings:
		$ = {((4e 65 6f 2c 77 65 6c 63 6f 6d 65 20 74 6f 20 74 68 65 20 64 65 73 65 72 74 20 6f 66 20 72 65 61 6c 2e) | (4e 00 65 00 6f 00 2c 00 77 00 65 00 6c 00 63 00 6f 00 6d 00 65 00 20 00 74 00 6f 00 20 00 74 00 68 00 65 00 20 00 64 00 65 00 73 00 65 00 72 00 74 00 20 00 6f 00 66 00 20 00 72 00 65 00 61 00 6c 00 2e 00))}
		$ = {2f 72 65 73 75 6c 74 3f 68 6c 3d 65 6e 26 69 64 3d 25 73}

	condition:
		any of them
}

rule Mirage : hardened
{
	meta:
		description = "Mirage"
		author = "Seth Hardy"
		last_modified = "2014-06-25"

	condition:
		MirageStrings
}

