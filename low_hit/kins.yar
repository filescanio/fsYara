rule KINS_dropper : hardened
{
	meta:
		author = "AlienVault Labs aortega@alienvault.com"
		description = "Match protocol, process injects and windows exploit present in KINS dropper"

	strings:
		$n1 = {74 69 64 3d 25 64 26 74 61 3d 25 73 2d 25 78}
		$n2 = {66 69 64 3d 25 64}
		$n3 = {25 5b 5e 2e 5d 2e 25 5b 5e 28 5d 28 25 5b 5e 29 5d 29}
		$i0 = {25 73 20 5b 25 73 20 25 64 5d 20 37 37 20 25 73}
		$i01 = {47 6c 6f 62 61 6c 5c 25 73 25 78}
		$i1 = {49 6e 6a 65 63 74 3a 3a 49 6e 6a 65 63 74 50 72 6f 63 65 73 73 42 79 4e 61 6d 65 28 29}
		$i2 = {49 6e 6a 65 63 74 3a 3a 43 6f 70 79 49 6d 61 67 65 54 6f 50 72 6f 63 65 73 73 28 29}
		$i3 = {49 6e 6a 65 63 74 3a 3a 49 6e 6a 65 63 74 50 72 6f 63 65 73 73 28 29}
		$i4 = {49 6e 6a 65 63 74 3a 3a 49 6e 6a 65 63 74 49 6d 61 67 65 54 6f 50 72 6f 63 65 73 73 28 29}
		$i5 = {44 72 6f 70 3a 3a 49 6e 6a 65 63 74 53 74 61 72 74 54 68 72 65 61 64 28 29}
		$uac1 = {45 78 70 6c 6f 69 74 4d 53 31 30 5f 30 39 32}
		$uac2 = {((5c 67 6c 6f 62 61 6c 72 6f 6f 74 5c 73 79 73 74 65 6d 72 6f 6f 74 5c 73 79 73 74 65 6d 33 32 5c 74 61 73 6b 73 5c) | (5c 00 67 00 6c 00 6f 00 62 00 61 00 6c 00 72 00 6f 00 6f 00 74 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 72 00 6f 00 6f 00 74 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 74 00 61 00 73 00 6b 00 73 00 5c 00))}
		$uac3 = {((3c 52 75 6e 4c 65 76 65 6c 3e 48 69 67 68 65 73 74 41 76 61 69 6c 61 62 6c 65 3c 2f 52 75 6e 4c 65 76 65 6c 3e) | (3c 00 52 00 75 00 6e 00 4c 00 65 00 76 00 65 00 6c 00 3e 00 48 00 69 00 67 00 68 00 65 00 73 00 74 00 41 00 76 00 61 00 69 00 6c 00 61 00 62 00 6c 00 65 00 3c 00 2f 00 52 00 75 00 6e 00 4c 00 65 00 76 00 65 00 6c 00 3e 00))}

	condition:
		2 of ( $n* ) and 2 of ( $i* ) and 2 of ( $uac* )
}

rule KINS_DLL_zeus : hardened
{
	meta:
		author = "AlienVault Labs aortega@alienvault.com"
		description = "Match default bot in KINS leaked dropper, Zeus"

	strings:
		$n1 = {25 42 4f 54 49 44 25}
		$n2 = {25 6f 70 65 6e 73 6f 63 6b 73 25}
		$n3 = {25 6f 70 65 6e 76 6e 63 25}
		$n4 = /Global\\(s|v)_ev/ fullword
		$s1 = {72 6e 6d 2c 36 7d 76 77}
		$s2 = {18 04 0f 12 16 0a 1e 08 5b 11 0f 13}
		$s3 = {39 1f 01 07 15 19 1a 33 19 0d 1f}
		$s4 = {62 6f 71 78 63 61 7f 69 2d 67 79 65}
		$s5 = {6f 69 7f 6b 61 53 6a 7c 73 6f 71}

	condition:
		all of ( $n* ) and 1 of ( $s* )
}

