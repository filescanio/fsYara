rule MAL_EnvyScout_May_2021_1 : hardened
{
	meta:
		description = "Detect EnvyScout downloader"
		author = "Arkbird_SOLG"
		reference = "Internal Research"
		date = "2021-05-28"
		hash1 = "279d5ef8f80aba530aaac8afd049fa171704fc703d9cfe337b56639732e8ce11"
		hash2 = "9059c5b46dce8595fcc46e63e4ffbceeed883b7b1c9a2313f7208a7f26a0c186"
		tlp = "White"
		adversary = "NOBELIUM"

	strings:
		$s1 = {3d 3d 74 79 70 65 6f 66 20 77 69 6e 64 6f 77 26 26 77 69 6e 64 6f 77 2e 77 69 6e 64 6f 77 3d 3d 3d 77 69 6e 64 6f 77 3f 77 69 6e 64 6f 77 3a}
		$s2 = {3d 3d 74 79 70 65 6f 66 20 73 65 6c 66 26 26 73 65 6c 66 2e 73 65 6c 66 3d 3d 3d 73 65 6c 66 3f 73 65 6c 66 3a}
		$s3 = {30 3d 3d 3d 74 3f 74 3d 7b 61 75 74 6f 42 6f 6d 3a 21 31 7d 3a}
		$s4 = {5f 67 6c 6f 62 61 6c 2e 73 61 76 65 41 73 3d 73 61 76 65 41 73 2e 73 61 76 65 41 73 3d 73 61 76 65 41 73}
		$s5 = {6e 61 76 69 67 61 74 6f 72 2e 75 73 65 72 41 67 65 6e 74}
		$s6 = { 6e 65 77 20 42 6c 6f 62 28 5b [1-12] 5d 2c 20 7b 74 79 70 65 3a 20 22 61 70 70 6c 69 63 61 74 69 6f 6e 2f 6f 63 74 65 74 2d 73 74 72 65 61 6d 22 7d 29 3b 73 61 76 65 41 73 28 }

	condition:
		filesize > 100KB and 5 of ( $s* )
}

