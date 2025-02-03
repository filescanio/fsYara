rule WarpCode : Warp Family hardened
{
	meta:
		description = "Warp code features"
		author = "Seth Hardy"
		last_modified = "2014-07-10"

	strings:
		$ = { 80 38 2B 75 03 C6 00 2D 80 38 2F 75 03 C6 00 5F }

	condition:
		any of them
}

rule WarpStrings : Warp Family hardened
{
	meta:
		description = "Warp Identifying Strings"
		author = "Seth Hardy"
		last_modified = "2014-07-10"

	strings:
		$ = {2f 32 30 31 31 2f 6e 33 32 35 34 32 33 2e 73 68 74 6d 6c 3f}
		$ = {77 79 6c 65}
		$ = {5c 7e 49 53 55 4e 33 32 2e 45 58 45}

	condition:
		any of them
}

rule Warp : Family hardened
{
	meta:
		description = "Warp"
		author = "Seth Hardy"
		last_modified = "2014-07-10"

	condition:
		WarpCode or WarpStrings
}

