rule GEN_PowerShell : hardened limited
{
	meta:
		description = "Generic PowerShell Malware Rule"
		author = "https://github.com/interleaved"
		score = 50

	strings:
		$s1 = {70 6f 77 65 72 73 68 65 6c 6c}
		$s2 = {2d 65 70 20 62 79 70 61 73 73}
		$s3 = {2d 6e 6f 70}
		$s10 = {2d 65 78 65 63 75 74 69 6f 6e 70 6f 6c 69 63 79 20 62 79 70 61 73 73}
		$s4 = {2d 77 69 6e 20 68 69 64 64 65 6e}
		$s5 = {2d 77 69 6e 64 6f 77 73 74 79 6c 65 20 68 69 64 64 65 6e}
		$s11 = {2d 77 20 68 69 64 64 65 6e}
		$s8 = {2d 65 6e 63}
		$s9 = {2d 65 6e 63 6f 64 65 64 63 6f 6d 6d 61 6e 64}

	condition:
		$s1 and ( ( $s2 or $s3 or $s10 ) and ( $s4 or $s5 or $s11 ) and ( $s8 or $s9 ) )
}

