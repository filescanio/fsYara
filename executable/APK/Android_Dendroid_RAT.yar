rule Dendroid : android hardened
{
	meta:
		author = "https://twitter.com/jsmesa"
		reference = "https://koodous.com/"
		description = "Dendroid RAT"
		score = 50

	strings:
		$s1 = {2f 75 70 6c 6f 61 64 2d 70 69 63 74 75 72 65 73 2e 70 68 70 3f}
		$s2 = {4f 70 65 6e 65 64 20 44 69 61 6c 6f 67 3a}
		$s3 = {63 6f 6d 2f 63 6f 6e 6e 65 63 74 2f 4d 79 53 65 72 76 69 63 65}
		$s4 = {61 6e 64 72 6f 69 64 2f 6f 73 2f 42 69 6e 64 65 72}
		$s5 = {61 6e 64 72 6f 69 64 2f 61 70 70 2f 53 65 72 76 69 63 65}

	condition:
		all of them
}

