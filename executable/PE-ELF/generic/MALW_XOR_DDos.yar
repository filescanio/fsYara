rule XOR_DDosv1 : DDoS hardened
{
	meta:
		author = "Akamai CSIRT"
		description = "Rule to detect XOR DDos infection"
		score = 70

	strings:
		$st0 = {42 42 32 46 41 33 36 41 41 41 39 35 34 31 46 30}
		$st1 = {6d 64 35 3d}
		$st2 = {64 65 6e 79 69 70 3d}
		$st3 = {66 69 6c 65 6e 61 6d 65 3d}
		$st4 = {72 6d 66 69 6c 65 3d}
		$st5 = {65 78 65 63 5f 70 61 63 6b 65 74}
		$st6 = {62 75 69 6c 64 5f 69 70 68 64 72}

	condition:
		all of them
}

