rule iexpl0reCode : iexpl0ree Family hardened
{
	meta:
		description = "iexpl0re code features"
		author = "Seth Hardy"
		last_modified = "2014-07-21"

	strings:
		$ = { 47 83 FF 64 0F 8C 6D FF FF FF 33 C0 5F 5E 5B C9 C3 }
		$ = { 80 74 0D A4 44 41 3B C8 7C F6 68 04 01 00 00 }
		$ = { 8A C1 B2 07 F6 EA 30 04 31 41 3B 4D 10 7C F1 }
		$ = { 47 83 FF 64 0F 8C 79 FF FF FF 33 C0 5F 5E 5B C9 C3 }
		$ = { 68 88 00 00 00 68 90 06 00 00 68 ?? ?? ?? ?? 89 3? E8 }
		$ = { BB 88 00 00 00 53 68 90 06 00 00 68 ?? ?? ?? ?? 89 3? E8 }

	condition:
		any of them
}

rule iexpl0reStrings : iexpl0re Family hardened
{
	meta:
		description = "Strings used by iexpl0re"
		author = "Seth Hardy"
		last_modified = "2014-07-21"

	strings:
		$ = {25 55 53 45 52 50 52 4f 46 49 4c 45 25 5c 49 45 58 50 4c 30 52 45 2e 45 58 45}
		$ = {22 3c 37 37 30 6a 20 28 28}
		$ = {5c 55 73 65 72 73 5c 25 73 5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 49 45 58 50 4c 30 52 45 2e 4c 4e 4b}
		$ = {5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 25 73 5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 49 45 58 50 4c 30 52 45 2e 45 58 45}
		$ = {4c 6f 61 64 65 72 56 35 2e 64 6c 6c}
		$ = {50 4f 53 54 20 2f 69 6e 64 65 78 25 30 2e 39 64 2e 61 73 70 20 48 54 54 50 2f 31 2e 31}
		$ = {47 45 54 20 2f 73 65 61 72 63 68 3f 6e 3d 25 30 2e 39 64 26}
		$ = {44 55 44 45 5f 41 4d 5f 49 5f 53 48 41 52 50 2d 33 2e 31 34 31 35 39 32 36 35 33 35 38 39 37 39 78 36 2e 36 32 36 31 37 36}
		$ = {57 48 4f 5f 41 5f 52 5f 45 5f 59 4f 55 3f 32 2e 39 39 37 39 32 34 35 38 78 31 2e 32 35 36 36 33 37 30 36 31 34 33 35 39 32}
		$ = {42 41 53 54 41 52 44 5f 26 26 5f 42 49 54 43 48 45 53 5f 25 30 2e 38 78}
		$ = {63 3a 5c 62 62 62 5c 65 65 65 2e 74 78 74}

	condition:
		any of them
}

rule iexpl0re : Family hardened
{
	meta:
		description = "iexpl0re family"
		author = "Seth Hardy"
		last_modified = "2014-07-21"

	condition:
		iexpl0reCode or iexpl0reStrings
}

