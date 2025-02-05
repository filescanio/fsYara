rule WimmieShellcode : Wimmie Family hardened
{
	meta:
		description = "Wimmie code features"
		author = "Seth Hardy"
		last_modified = "2014-07-17"

	strings:
		$ = { 49 30 24 39 83 F9 00 77 F7 8D 3D 4D 10 40 00 B9 0C 03 00 00 }
		$xordecrypt = {B9 B4 1D 00 00 [8] 49 30 24 39 83 F9 00 }

	condition:
		any of them
}

rule WimmieStrings : Wimmie Family hardened
{
	meta:
		description = "Strings used by Wimmie"
		author = "Seth Hardy"
		last_modified = "2014-07-17"

	strings:
		$ = {00 53 63 72 69 70 74 4d 61 6e}
		$ = {((43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 73 79 73 70 72 65 70 5c 63 72 79 70 74 62 61 73 65 2e 64 6c 6c) | (43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 73 00 79 00 73 00 70 00 72 00 65 00 70 00 5c 00 63 00 72 00 79 00 70 00 74 00 62 00 61 00 73 00 65 00 2e 00 64 00 6c 00 6c 00))}
		$ = {((50 72 6f 62 65 53 63 72 69 70 74 46 69 6e 74) | (50 00 72 00 6f 00 62 00 65 00 53 00 63 00 72 00 69 00 70 00 74 00 46 00 69 00 6e 00 74 00))}
		$ = {50 72 6f 62 65 53 63 72 69 70 74 4b 69 64 73}

	condition:
		any of them
}

