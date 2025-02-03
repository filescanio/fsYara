rule RegSubDatCode : RegSubDat Family hardened
{
	meta:
		description = "RegSubDat code features"
		author = "Seth Hardy"
		last_modified = "2014-07-14"

	strings:
		$ = { 80 34 3? 99 40 (3D FB 65 00 00 | 3B C6) 7? F? }
		$ = { 68 FF FF 7F 00 5? }
		$ = { 68 FF 7F 00 00 5? }

	condition:
		all of them
}

rule RegSubDatStrings : RegSubDat Family hardened
{
	meta:
		description = "RegSubDat Identifying Strings"
		author = "Seth Hardy"
		last_modified = "2014-07-14"

	strings:
		$avg1 = {42 75 74 74 6f 6e}
		$avg2 = {41 6c 6c 6f 77}
		$avg3 = {49 64 65 6e 74 69 74 79 20 50 72 6f 74 65 63 74 69 6f 6e}
		$avg4 = {41 6c 6c 6f 77 20 66 6f 72 20 61 6c 6c}
		$avg5 = {41 56 47 20 46 69 72 65 77 61 6c 6c 20 41 73 6b 73 20 46 6f 72 20 43 6f 6e 66 69 72 6d 61 74 69 6f 6e}
		$mutex = {30 78 31 41 37 42 34 43 39 46}

	condition:
		all of ( $avg* ) or $mutex
}

rule RegSubDat : Family hardened
{
	meta:
		description = "RegSubDat"
		author = "Seth Hardy"
		last_modified = "2014-07-14"

	condition:
		RegSubDatCode or RegSubDatStrings
}

