rule poisonivy_1 : rat hardened
{
	meta:
		description = "Poison Ivy"
		author = "Jean-Philippe Teissier / @Jipe_"
		date = "2013-02-01"
		filetype = "memory"
		version = "1.0"
		ref1 = "https://code.google.com/p/volatility/source/browse/trunk/contrib/plugins/malware/poisonivy.py"

	strings:
		$a = { 53 74 75 62 50 61 74 68 ?? 53 4F 46 54 57 41 52 45 5C 43 6C 61 73 73 65 73 5C 68 74 74 70 5C 73 68 65 6C 6C 5C 6F 70 65 6E 5C 63 6F 6D 6D 61 6E 64 [22] 53 6F 66 74 77 61 72 65 5C 4D 69 63 72 6F 73 6F 66 74 5C 41 63 74 69 76 65 20 53 65 74 75 70 5C 49 6E 73 74 61 6C 6C 65 64 20 43 6F 6D 70 6F 6E 65 6E 74 73 5C }

	condition:
		$a
}

rule PoisonIvy_Generic_3 : hardened
{
	meta:
		description = "PoisonIvy RAT Generic Rule"
		author = "Florian Roth"
		date = "2015-05-14"
		hash = "e1cbdf740785f97c93a0a7a01ef2614be792afcd"

	strings:
		$k1 = {54 69 67 65 72 33 32 34 7b}
		$s2 = {57 49 4e 49 4e 45 54 2e 64 6c 6c}
		$s3 = {6d 00 73 00 63 00 6f 00 72 00 65 00 65 00 2e 00 64 00 6c 00 6c 00}
		$s4 = {57 53 32 5f 33 32 2e 64 6c 6c}
		$s5 = {45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00}
		$s6 = {55 53 45 52 33 32 2e 44 4c 4c}
		$s7 = {43 4f 4e 4f 55 54 24}
		$s8 = {6c 6f 67 69 6e 2e 61 73 70}
		$h1 = {48 54 54 50 2f 31 2e 30}
		$h2 = {50 4f 53 54}
		$h3 = {6c 6f 67 69 6e 2e 61 73 70}
		$h4 = {63 68 65 63 6b 2e 61 73 70}
		$h5 = {72 65 73 75 6c 74 2e 61 73 70}
		$h6 = {75 70 6c 6f 61 64 2e 61 73 70}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 500KB and ( $k1 or all of ( $s* ) or all of ( $h* ) )
}

rule PoisonIvy_2 : hardened
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/PoisonIvy"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$stub = {04 08 00 53 74 75 62 50 61 74 68 18 04}
		$string1 = {43 4f 4e 4e 45 43 54 20 25 73 3a 25 69 20 48 54 54 50 2f 31 2e 30}
		$string2 = {77 73 32 5f 33 32}
		$string3 = {63 6b 73 3d 75}
		$string4 = {74 68 6a 40 68}
		$string5 = {61 64 76 70 61 63 6b}

	condition:
		$stub at 0x1620 and all of ( $string* ) or ( all of them )
}

