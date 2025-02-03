rule WEBSHELL_APT_PHP_DEWMODE_UNC2546_Feb21_1 : hardened
{
	meta:
		description = "Detects DEWMODE webshells"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2021/02/accellion-fta-exploited-for-data-theft-and-extortion.html"
		date = "2021-02-22"
		hash1 = "2e0df09fa37eabcae645302d9865913b818ee0993199a6d904728f3093ff48c7"
		hash2 = "5fa2b9546770241da7305356d6427847598288290866837626f621d794692c1b"
		id = "ea883f25-0e9b-5617-b05e-191a4a5c5a52"

	strings:
		$x1 = {3c 66 6f 6e 74 20 73 69 7a 65 3d 34 3e 43 6c 65 61 6e 75 70 20 53 68 65 6c 6c 3c 2f 66 6f 6e 74 3e 3c 2f 61 3e 27 3b}
		$x2 = {24 28 73 68 20 2f 74 6d 70 2f 2e 73 63 72 29}
		$x3 = {40 73 79 73 74 65 6d 28 27 73 75 64 6f 20 2f 75 73 72 2f 6c 6f 63 61 6c 2f 62 69 6e 2f 61 64 6d 69 6e 2e 70 6c 20 2d 2d 6d 6f 75 6e 74 5f 63 69 66 73 3d}
		$s1 = {74 61 72 67 65 74 3d 5c 5c 22 5f 62 6c 61 6e 6b 5c 5c 22 3e 44 6f 77 6e 6c 6f 61 64 3c 2f 61 3e 3c 2f 74 64 3e 22 3b}
		$s2 = {2c 50 41 53 53 57 4f 52 44 20 31 3e 2f 64 65 76 2f 6e 75 6c 6c 20 32 3e 2f 64 65 76 2f 6e 75 6c 6c 27 29 3b}
		$s3 = {2c 62 61 73 65 36 34 5f 64 65 63 6f 64 65 28 27}
		$s4 = {69 6e 63 6c 75 64 65 20 22 72 65 6d 6f 74 65 2e 69 6e 63 22 3b}
		$s5 = {40 73 79 73 74 65 6d 28 27 73 75 64 6f 20 2f 75 73 72 2f 6c 6f 63 61 6c}

	condition:
		uint16( 0 ) == 0x3f3c and filesize < 9KB and ( 1 of ( $x* ) or 2 of them ) or 3 of them
}

