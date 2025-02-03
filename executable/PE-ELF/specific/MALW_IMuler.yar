rule IMulerCode : IMuler Family hardened
{
	meta:
		description = "IMuler code tricks"
		author = "Seth Hardy"
		last_modified = "2014-06-16"

	strings:
		$L4_tmpSpotlight = { C7 ?? 2F 74 6D 70 C7 ?? 04 2F 53 70 6F }
		$L4_TMPAAABBB = { C7 ?? ?? ?? ?? ?? 54 4D 50 41 C7 ?? ?? ?? ?? ?? 41 41 42 42 }
		$L4_FILEAGENTVer = { C7 ?? 46 49 4C 45 C7 ?? 04 41 47 45 4E }
		$L4_TMP0M34JDF8 = { C7 ?? ?? ?? ?? ?? 54 4D 50 30 C7 ?? ?? ?? ?? ?? 4D 33 34 4A }
		$L4_tmpmdworker = { C7 ?? 2F 74 6D 70 C7 ?? 04 2F 2E 6D 64 }

	condition:
		any of ( $L4* )
}

rule IMulerStrings : IMuler Family hardened
{
	meta:
		description = "IMuler Identifying Strings"
		author = "Seth Hardy"
		last_modified = "2014-06-16"

	strings:
		$ = {2f 63 67 69 2d 6d 61 63 2f}
		$ = {78 6e 6f 63 7a 31}
		$ = {63 68 65 63 6b 76 69 72 2e 70 6c 69 73 74}
		$ = {2f 55 73 65 72 73 2f 61 70 70 6c 65 2f 44 6f 63 75 6d 65 6e 74 73 2f 6d 61 63 20 62 61 63 6b}
		$ = {69 4d 75 6c 65 72 32}
		$ = {2f 55 73 65 72 73 2f 69 6d 61 63 2f 44 65 73 6b 74 6f 70 2f 6d 61 63 62 61 63 6b 2f}
		$ = {78 6e 74 61 73 6b 7a 2e 67 7a}
		$ = {32 77 6d 73 65 74 73 74 61 74 75 73 2e 63 67 69}
		$ = {6c 61 75 6e 63 68 2d 30 72 70 2e 64 61 74}
		$ = {32 77 6d 75 70 6c 6f 61 64 2e 63 67 69}
		$ = {78 6e 74 6d 70 7a}
		$ = {32 77 6d 72 65 63 76 64 61 74 61 2e 63 67 69}
		$ = {78 6e 6f 72 7a 36}
		$ = {32 77 6d 64 65 6c 66 69 6c 65 2e 63 67 69}
		$ = {2f 4c 61 6e 63 68 41 67 65 6e 74 73 2f 63 68 65 63 6b 76 69 72}
		$ = {30 50 45 52 41 3a 25 73}
		$ = {2f 74 6d 70 2f 53 70 6f 74 6c 69 67 68 74}
		$ = {2f 74 6d 70 2f 6c 61 75 6e 63 68 2d 49 43 53 30 30 30}

	condition:
		3 of them
}

