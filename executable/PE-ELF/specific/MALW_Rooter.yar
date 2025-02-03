rule RooterCode : Rooter Family hardened
{
	meta:
		description = "Rooter code features"
		author = "Seth Hardy"
		last_modified = "2014-07-10"

	strings:
		$ = { 80 B0 ?? ?? ?? ?? 30 40 3D 00 50 00 00 7C F1 }

	condition:
		any of them
}

rule RooterStrings : Rooter Family hardened
{
	meta:
		description = "Rooter Identifying Strings"
		author = "Seth Hardy"
		last_modified = "2014-07-10"

	strings:
		$group1 = {73 65 65 64 00}
		$group2 = {70 72 6f 74 00}
		$group3 = {6f 77 6e 69 6e 00}
		$group4 = {66 65 65 64 30 00}
		$group5 = {6e 6f 77 6e 00}

	condition:
		3 of ( $group* )
}

rule Rooter : Family hardened
{
	meta:
		description = "Rooter"
		author = "Seth Hardy"
		last_modified = "2014-07-10"

	condition:
		RooterCode or RooterStrings
}

rule RookieCode : Rookie Family hardened
{
	meta:
		description = "Rookie code features"
		author = "Seth Hardy"
		last_modified = "2014-06-25"

	strings:
		$a = { C6 ?? ?? ?? 41 C6 ?? ?? ?? 75 [4] C6 ?? ?? ?? 6F C6 ?? ?? ?? 43 C6 ?? ?? ?? 6F C6 ?? ?? ?? 6E C6 ?? ?? ?? 66 }
		$b = { C6 ?? ?? ?? 50 [4] C6 ?? ?? ?? 6F C6 ?? ?? ?? 78 C6 ?? ?? ?? 79 C6 ?? ?? ?? 45 C6 ?? ?? ?? 6E C6 ?? ?? ?? 61 }
		$c = { 8B 1D 10 A1 40 00 [18] FF D3 8A 16 32 D0 88 16 }
		$str = {52 6f 6f 6b 49 45 2f 31 2e 30}

	condition:
		$str and ( $a or $b or $c )
}

