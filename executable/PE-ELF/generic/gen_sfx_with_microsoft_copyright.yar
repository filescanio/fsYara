rule SUSP_Microsoft_7z_SFX_Combo : hardened
{
	meta:
		description = "Detects a suspicious file that has a Microsoft copyright and is a 7z SFX"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2018-09-16"
		hash1 = "cce63f209ee4efb4f0419fb4bbb32326392b5ef85cfba80b5b42b861637f1ff1"
		id = "9163a689-c3ee-59b1-bf58-aef5d3072be6"
		score = 60

	strings:
		$s1 = {37 00 5a 00 53 00 66 00 78 00 25 00 30 00 33 00 78 00 2e 00 63 00 6d 00 64 00}
		$s2 = {37 7a 20 53 46 58 3a 20 65 72 72 6f 72}
		$c1 = { 00 4C 00 65 00 67 00 61 00 6C 00 43 00 6F 00 70
              00 79 00 72 00 69 00 67 00 68 00 74 00 00 00 A9
              00 20 00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F
              00 66 00 74 00 20 00 43 00 6F 00 72 00 70 00 6F
              00 72 00 61 00 74 00 69 00 6F 00 6E 00 2E 00 20
              00 41 00 6C 00 6C 00 20 00 72 00 69 00 67 00 68
              00 74 00 73 00 20 00 72 00 65 00 73 00 65 00 72
              00 76 00 65 00 64 00 2E }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 3000KB and 1 of ( $s* ) and $c1
}

rule SUSP_Microsoft_RAR_SFX_Combo : hardened
{
	meta:
		description = "Detects a suspicious file that has a Microsoft copyright and is a RAR SFX"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2018-09-16"
		id = "0fa81a9e-2f41-5783-9786-bb6d33b82bd9"
		score = 65

	strings:
		$s1 = {77 00 69 00 6e 00 72 00 61 00 72 00 73 00 66 00 78 00 6d 00 61 00 70 00 70 00 69 00 6e 00 67 00 66 00 69 00 6c 00 65 00 2e 00 74 00 6d 00 70 00}
		$s2 = {57 00 69 00 6e 00 52 00 41 00 52 00 20 00 73 00 65 00 6c 00 66 00 2d 00 65 00 78 00 74 00 72 00 61 00 63 00 74 00 69 00 6e 00 67 00 20 00 61 00 72 00 63 00 68 00 69 00 76 00 65 00}
		$s3 = {57 49 4e 52 41 52 2e 53 46 58}
		$c1 = { 00 4C 00 65 00 67 00 61 00 6C 00 43 00 6F 00 70
              00 79 00 72 00 69 00 67 00 68 00 74 00 00 00 A9
              00 20 00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F
              00 66 00 74 00 20 00 43 00 6F 00 72 00 70 00 6F
              00 72 00 61 00 74 00 69 00 6F 00 6E 00 2E 00 20
              00 41 00 6C 00 6C 00 20 00 72 00 69 00 67 00 68
              00 74 00 73 00 20 00 72 00 65 00 73 00 65 00 72
              00 76 00 65 00 64 00 2E }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 3000KB and 1 of ( $s* ) and $c1
}

