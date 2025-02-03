rule wiper_unique_strings : hardened
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		company = "novetta"

	strings:
		$a = {43 21 40 49 23 25 56 4a 53 49 45 4f 54 51 57 50 56 7a 30 33 34 76 75 41}
		$b = {42 41 49 53 45 4f 25 24 32 66 61 73 39 76 51 73 66 76 78 25 24}
		$c = {31 2e 32 2e 37 2e 66 2d 68 61 6e 62 61 2d 77 69 6e 36 34 2d 76 31}
		$d = {6d 64 20 25 73 26 63 6f 70 79 20 25 73 5c 2a 2e 2a 20 25 73}
		$e = {25 73 64 2e 65 25 73 63 20 6e 25 73 73 68 25 73 72 65 77 61 25 73 20 61 64 25 73 20 70 6f 25 73 6f 70 25 73 69 6e 67 20 54 25 73 20 25 64 20 22 25 73 22}
		$f = {47 65 2e 74 56 6f 6c 2e 20 2e 75 6d 65 49 6e 2e 2e 66 6f 72 20 20 6d 61 74 69 2e 6f 6e 57}

	condition:
		$a or $b or $c or $d or $e or $f
}

rule wiper_encoded_strings : hardened
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		company = "novetta"

	strings:
		$scr = {89 D4 C4 D5 00 00 00}
		$explorer = {E2 DF D7 CB C8 D5 C2 D5 89 C2 DF C2 00 00 00 }
		$kernel32 = {CC C2 D5 C9 C2 CB 94 95  89 C3 CB CB 00 00 }

	condition:
		$scr or $explorer or $kernel32
}

rule createP2P : hardened
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		$ = {43 00 72 00 65 00 61 00 74 00 50 00 32 00 50 00 20 00 54 00 68 00 72 00 65 00 61 00 64 00}

	condition:
		any of them
}

rule firewallOpener : hardened
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		$ = {25 73 64 2e 65 25 73 63 20 6e 25 73 73 68 25 73 72 65 77 61 25 73 20 61 64 25 73 20 70 6f 25 73 6f 70 25 73 69 6e 67 20 54 25 73 20 25 64 20 22 25 73 22}

	condition:
		any of them
}

