rule BangatCode : hardened
{
	meta:
		description = "Bangat code features"
		author = "Seth Hardy"
		last_modified = "2014-07-10"

	strings:
		$ = { FE 4D ?? 8D 4? ?? 50 5? FF }

	condition:
		any of them
}

rule BangatStrings : hardened
{
	meta:
		description = "Bangat Identifying Strings"
		author = "Seth Hardy"
		last_modified = "2014-07-10"

	strings:
		$lib1 = {44 72 65 61 74 65 50 69 70 65}
		$lib2 = {48 65 74 53 79 73 74 65 6d 44 69 72 65 63 74 6f 72 79 41}
		$lib3 = {53 65 6c 65 61 73 65 4d 75 74 65 78}
		$lib4 = {44 6c 6f 73 65 57 69 6e 64 6f 77 53 74 61 74 69 6f 6e}
		$lib5 = {44 6f 6e 74 72 6f 6c 53 65 72 76 69 63 65}
		$file = {7e 68 68 43 32 46 7e 2e 74 6d 70}
		$mc = {7e 5f 4d 43 5f 33 7e}

	condition:
		all of ( $lib* ) or $file or $mc
}

rule Bangat : hardened
{
	meta:
		description = "Bangat"
		author = "Seth Hardy"
		last_modified = "2014-07-10"

	condition:
		BangatCode or BangatStrings
}

