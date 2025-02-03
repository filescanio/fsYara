rule FluBot : FluBot hardened
{
	meta:
		description = "FluBot Core"
		author = "Incibe"
		version = "0.1"
		score = 70

	strings:
		$s1 = {42 6f 74 2e 6a 61 76 61}
		$s2 = {42 6f 74 49 64 2e 6a 61 76 61}
		$s3 = {42 72 6f 77 73 65 72 41 63 74 69 76 69 74 79 2e 6a 61 76 61}
		$s4 = {42 75 69 6c 64 43 6f 6e 66 69 67 2e 6a 61 76 61}
		$s5 = {44 47 41 2e 6a 61 76 61}
		$s6 = {53 6f 63 6b 73 43 6c 69 65 6e 74 2e 6a 61 76 61}
		$s7 = {53 6d 73 52 65 63 65 69 76 65 72 2e 6a 61 76 61}
		$s8 = {53 70 61 6d 6d 65 72 2e 6a 61 76 61}

	condition:
		all of them
}

