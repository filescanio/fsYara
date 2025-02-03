rule EzcobStrings : Ezcob Family hardened
{
	meta:
		description = "Ezcob Identifying Strings"
		author = "Seth Hardy"
		last_modified = "2014-06-23"

	strings:
		$ = {12 46 12 46 12 39 12 45 12 41 12 45 12 42 12 41 12 2d 12 37 12 37 12 38 12 33 12}
		$ = {12 31 12 44 12 38 12 33 12 42 12 32 12 45 12 38 12 2d 12 42 12 32 12 33 12 44 12}
		$ = {((45 7a 63 6f 62) | (45 00 7a 00 63 00 6f 00 62 00))}
		$ = {6c 12 69 12 75 12 32 12 30 12 31 12 33 12 30 12 34 12 31 12 36}
		$ = {32 30 31 31 30 31 31 33 31 34 34 39 33 35}

	condition:
		2 of them
}

