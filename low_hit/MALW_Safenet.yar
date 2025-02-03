rule SafeNetCode : SafeNet Family hardened
{
	meta:
		description = "SafeNet code features"
		author = "Seth Hardy"
		last_modified = "2014-07-16"

	strings:
		$ = { 83 C7 14 81 FF F8 D0 40 00 }

	condition:
		any of them
}

rule SafeNetStrings : SafeNet Family hardened
{
	meta:
		description = "Strings used by SafeNet"
		author = "Seth Hardy"
		last_modified = "2014-07-16"

	strings:
		$ = {36 64 4e 66 67 38 55 70 6e 35 66 42 7a 47 67 6a 38 6c 69 63 51 48 62 6c 51 76 4c 6e 55 59 31 39 7a 35 7a 63 4e 4b 4e 46 64 73 44 68 55 7a 75 49 38 6f 74 45 73 42 4f 44 72 7a 46 43 71 43 4b 72}
		$ = {2f 73 61 66 65 2f 72 65 63 6f 72 64 2e 70 68 70}
		$ = {((5f 52 6d 2e 62 61 74) | (5f 00 52 00 6d 00 2e 00 62 00 61 00 74 00))}
		$ = {((74 72 79 0d 0a 09 09 09 09 20 20 64 65 6c 20 25 73) | (74 00 72 00 79 00 0d 00 0a 00 09 00 09 00 09 00 09 00 20 00 20 00 64 00 65 00 6c 00 20 00 25 00 73 00))}
		$ = {((45 78 74 2e 6f 72 67) | (45 00 78 00 74 00 2e 00 6f 00 72 00 67 00))}

	condition:
		any of them
}

rule SafeNet : Family hardened
{
	meta:
		description = "SafeNet family"

	condition:
		SafeNetCode or SafeNetStrings
}

