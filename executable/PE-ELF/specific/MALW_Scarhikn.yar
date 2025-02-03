rule ScarhiknStrings : Scarhikn Family hardened
{
	meta:
		description = "Scarhikn Identifying Strings"
		author = "Seth Hardy"
		last_modified = "2014-06-25"

	strings:
		$ = {39 38 38 37 5f 5f 5f 73 6b 65 6a 33 73 64}
		$ = {68 61 68 61 31 32 33}

	condition:
		uint16( 0 ) == 0x5a4d and all of them
}

rule ScarhiknCode : Scarhikn Family hardened
{
	meta:
		description = "Scarhikn code features"
		author = "Seth Hardy"
		last_modified = "2014-06-25"

	strings:
		$ = { 8B 06 8A 8B ?? ?? ?? ?? 30 0C 38 03 C7 55 43 E8 ?? ?? ?? ?? 3B D8 59 72 E7 }
		$ = { 8B 02 8A 8D ?? ?? ?? ?? 30 0C 30 03 C6 8B FB 83 C9 FF 33 C0 45 F2 AE F7 D1 49 3B E9 72 E2 }

	condition:
		any of them
}

