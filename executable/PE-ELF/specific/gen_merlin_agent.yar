rule merlinAgent : hardened
{
	meta:
		description = "Detects Merlin agent"
		filetype = "pe, elf, mach"
		author = "Hilko Bengen"
		reference = "https://github.com/Ne0nd0g/merlin"
		date = "2017-12-26"
		id = "92346a3f-dce4-58db-893b-b7797fa20029"

	strings:
		$x1 = {43 6f 6d 6d 61 6e 64 20 6f 75 74 70 75 74 3a 0d 0a 0d 0a 25 73}
		$x2 = {5b 2d 5d 43 6f 6e 6e 65 63 74 69 6e 67 20 74 6f 20 77 65 62 20 73 65 72 76 65 72 20 61 74 20 25 73 20 74 6f 20 75 70 64 61 74 65 20 61 67 65 6e 74 20 63 6f 6e 66 69 67 75 72 61 74 69 6f 6e 20 69 6e 66 6f 72 6d 61 74 69 6f 6e 2e}
		$x3 = {5b 2d 5d 25 64 20 6f 75 74 20 6f 66 20 25 64 20 74 6f 74 61 6c 20 66 61 69 6c 65 64 20 63 68 65 63 6b 69 6e 73}
		$x4 = {5b 21 7d 55 6e 6b 6e 6f 77 6e 20 41 67 65 6e 74 43 6f 6e 74 72 6f 6c 20 6d 65 73 73 61 67 65 20 74 79 70 65 20 72 65 63 65 69 76 65 64 20 25 73}
		$x5 = {5b 2d 5d 52 65 63 65 69 76 65 64 20 41 67 65 6e 74 20 4b 69 6c 6c 20 4d 65 73 73 61 67 65}
		$x6 = {5b 2d 5d 52 65 63 65 69 76 65 64 20 53 65 72 76 65 72 20 4f 4b 2c 20 64 6f 69 6e 67 20 6e 6f 74 68 69 6e 67}
		$x7 = {5b 21 5d 54 68 65 72 65 20 77 61 73 20 61 6e 20 65 72 72 6f 72 20 77 69 74 68 20 74 68 65 20 48 54 54 50 20 63 6c 69 65 6e 74 20 77 68 69 6c 65 20 70 65 72 66 6f 72 6d 69 6e 67 20 61 20 50 4f 53 54 3a}
		$x8 = {5b 2d 5d 53 6c 65 65 70 69 6e 67 20 66 6f 72 20 25 73 20 61 74 20 25 73}
		$s1 = {45 78 65 63 75 74 69 6e 67 20 63 6f 6d 6d 61 6e 64 20 25 73 20 25 73 20 25 73}
		$s2 = {5b 2b 5d 48 6f 73 74 20 49 6e 66 6f 72 6d 61 74 69 6f 6e 3a}
		$s3 = {09 48 6f 73 74 6e 61 6d 65 3a 20 25 73}
		$s4 = {09 50 6c 61 74 66 6f 72 6d 3a 20 25 73}
		$s5 = {09 55 73 65 72 20 47 55 49 44 3a 20 25 73}

	condition:
		1 of ( $x* ) or 4 of them
}

