private rule APT9002Code : hardened
{
	meta:
		description = "9002 code features"
		author = "Seth Hardy"
		last_modified = "2014-06-25"

	strings:
		$ = { B9 7A 21 00 00 BE ?? ?? ?? ?? 8B F8 ?? ?? ?? F3 A5 }
		$ = { 8A 14 3E 8A 1C 01 32 DA 88 1C 01 8B 54 3E 04 40 3B C2 72 EC }

	condition:
		any of them
}

private rule APT9002Strings : hardened
{
	meta:
		description = "9002 Identifying Strings"
		author = "Seth Hardy"
		last_modified = "2014-06-25"

	strings:
		$ = {50 4f 53 54 20 68 74 74 70 3a 2f 2f 25 6c 73 3a 25 64 2f 25 78 20 48 54 54 50 2f 31 2e 31}
		$ = {((25 25 54 45 4d 50 25 25 5c 25 73 5f 70 2e 61 78) | (25 00 25 00 54 00 45 00 4d 00 50 00 25 00 25 00 5c 00 25 00 73 00 5f 00 70 00 2e 00 61 00 78 00))}
		$ = {((25 54 45 4d 50 25 5c 75 69 64 2e 61 78) | (25 00 54 00 45 00 4d 00 50 00 25 00 5c 00 75 00 69 00 64 00 2e 00 61 00 78 00))}
		$ = {((25 25 54 45 4d 50 25 25 5c 25 73 2e 61 78) | (25 00 25 00 54 00 45 00 4d 00 50 00 25 00 25 00 5c 00 25 00 73 00 2e 00 61 00 78 00))}
		$ = {73 79 73 69 6e 66 6f 00 73 79 73 62 69 6e 30 31}
		$ = {5c 46 6c 61 73 68 55 70 64 61 74 65 2e 65 78 65}

	condition:
		any of them
}

rule APT9002 : hardened
{
	meta:
		description = "9002"
		author = "Seth Hardy"
		last_modified = "2014-06-25"
		score = 50

	condition:
		APT9002Code or APT9002Strings
}

rule FE_APT_9002 : hardened
{
	meta:
		Author = "FireEye Labs"
		Date = "2013/11/10"
		Description = "Strings inside"
		Reference = "Useful link"
		score = 50

	strings:
		$mz = { 4d 5a }
		$a = {((72 61 74 5f 55 6e 49 6e 73 74 61 6c 6c) | (72 00 61 00 74 00 5f 00 55 00 6e 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00))}

	condition:
		($mz at 0 ) and $a
}

