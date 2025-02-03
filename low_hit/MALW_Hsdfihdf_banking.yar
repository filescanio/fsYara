rule Hsdfihdf : banking malware hardened
{
	meta:
		author = "Adam Ziaja <adam@adamziaja.com> http://adamziaja.com"
		date = "2014-04-06"
		description = "Polish banking malware"
		hash0 = "db1675c74a444fd35383d9a45631cada"
		hash1 = "f48ba39df38056449a3e9a1a7289f657"
		filetype = "exe"

	strings:
		$s0 = {41 4e 53 49 5f 43 48 41 52 53 45 54}
		$s1 = {5d 5b 56 65 65 5f 64 5f 5b}
		$s2 = {71 66 63 44 3a 36 3c}
		$s3 = {25 2d 25 2f 25 31 25 33 25 35 25 37 25 39 25 3b 25}
		$s4 = {69 6d 68 7a 78 73 63 5c 57 57 4b 44 3c 2e 29 77}
		$s5 = {56 7a 6c 61 72 66 5c 5d 56 4f 5a 56 4d 73 6b 66}
		$s6 = {4a 4b 57 46 41 70 5c 5a}
		$s7 = {3c 61 4c 4c 77 68 67}
		$s8 = {62 64 4c 65 66 74 54 6f 52 69 67 68 74}
		$s9 = {46 2f 2e 70 54 43 37}
		$s10 = {4f 3e 3c 38 2c 29 2d 24 20}
		$s11 = {6d 6a 65 55 42 3e 44 2e 27 38 29 35 5c 5c 76 68 65 5b}
		$s12 = {4a 47 69 56 52 6b 5b 57 5d 50 4c 28}
		$s13 = {7a 77 57 4e 4e 47 3a 38}
		$s14 = {7a 76 37 2c 27 24}
		$a0 = {23 68 73 64 66 69 68 64 66}
		$a1 = {70 6f 6c 73 6b 61 2e 69 72 63 2e 70 6c}
		$b0 = {66 69 72 65 68 69 6d 40 6f 32 2e 70 6c}
		$b1 = {66 69 72 65 68 69 6d 40 67 6f 32 2e 70 6c}
		$b2 = {66 69 72 65 68 69 6d 40 74 6c 65 6e 2e 70 6c}
		$c0 = {63 79 62 65 72 70 75 6e 6b 73 2e 70 6c}
		$c1 = {6b 61 70 65 72 2e 70 68 72 61 63 6b 2e 70 6c}
		$c2 = {73 65 72 77 65 72 2e 75 6b 2e 74 6f}
		$c3 = {6e 73 31 2e 69 70 76 34 2e 68 75}
		$c4 = {73 63 6f 72 65 62 6f 74 2e 6b 6f 74 68 2e 68 75}
		$c5 = {65 73 6f 70 6f 6c 61 6e 64 2e 70 6c}

	condition:
		14 of ( $s* ) or all of ( $a* ) or 1 of ( $b* ) or 2 of ( $c* )
}

