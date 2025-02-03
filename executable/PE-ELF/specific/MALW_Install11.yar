rule Insta11Strings : Insta11 Family hardened
{
	meta:
		description = "Insta11 Identifying Strings"
		author = "Seth Hardy"
		last_modified = "2014-06-23"

	strings:
		$ = {58 54 41 4c 4b 45 52 37}
		$ = {((49 6e 73 74 61 31 31 20 4d 69 63 72 6f 73 6f 66 74) | (49 00 6e 00 73 00 74 00 61 00 31 00 31 00 20 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00))}
		$ = {77 75 64 4d 65 73 73 61 67 65}
		$ = {45 43 44 34 46 43 34 44 2d 35 32 31 43 2d 31 31 44 30 2d 42 37 39 32 2d 30 30 41 30 43 39 30 33 31 32 45 31}
		$ = {42 31 32 41 45 38 39 38 2d 44 30 35 36 2d 34 33 37 38 2d 41 38 34 34 2d 36 44 33 39 33 46 45 33 37 39 35 36}

	condition:
		3 of them
}

