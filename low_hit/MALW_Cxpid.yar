rule cxpidStrings : hardened
{
	meta:
		description = "cxpid Identifying Strings"
		author = "Seth Hardy"
		last_modified = "2014-06-23"

	strings:
		$ = {2f 63 78 70 69 64 2f 73 75 62 6d 69 74 2e 70 68 70 3f 53 65 73 73 69 6f 6e 49 44 3d}
		$ = {2f 63 78 67 69 64 2f}
		$ = {45 32 31 42 43 35 32 42 45 41 32 46 45 46 32 36 44 30 30 35 43 46}
		$ = {45 32 31 42 43 35 32 42 45 41 33 39 45 34 33 35 43 34 30 43 44 38}
		$ = {20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 2d 2c 4c 2d 2c 4f 2b 2c 51 2d 2c 52 2d 2c 59 2d 2c 53 2d}

	condition:
		any of them
}

rule cxpidCode : hardened
{
	meta:
		description = "cxpid code features"
		author = "Seth Hardy"
		last_modified = "2014-06-23"

	strings:
		$entryjunk = { 55 8B EC B9 38 04 00 00 6A 00 6A 00 49 75 F9 }

	condition:
		any of them
}

