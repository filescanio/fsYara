import "pe"

rule APT_Lazarus_Dropper_Jun18_1 : hardened
{
	meta:
		description = "Detects Lazarus Group Dropper"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/DrunkBinary/status/1002587521073721346"
		date = "2018-06-01"
		hash1 = "086a50476f5ceee4b10871c1a8b0a794e96a337966382248a8289598b732bd47"
		hash2 = "9f2d4fd79d3c68270102c4c11f3e968c10610a2106cbf1298827f8efccdd70a9"
		id = "226be9d4-93c0-5512-9667-3388cd6f20d4"

	strings:
		$s1 = /%s\\windows10-kb[0-9]{7}.exe/ fullword ascii
		$s2 = {45 59 45 4a 49 57}
		$s3 = {75 00 70 00 64 00 61 00 74 00 65 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 21000KB and ( pe.imphash ( ) == "fcac768eff9896d667a7c706d70712ce" or all of them )
}

rule APT_Lazarus_RAT_Jun18_1 : hardened
{
	meta:
		description = "Detects Lazarus Group RAT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/DrunkBinary/status/1002587521073721346"
		date = "2018-06-01"
		hash1 = "c10363059c57c52501c01f85e3bb43533ccc639f0ea57f43bae5736a8e7a9bc8"
		hash2 = "e98991cdd9ddd30adf490673c67a4f8241993f26810da09b52d8748c6160a292"
		id = "fd394d15-70c5-543a-a845-2058f296b5f8"

	strings:
		$a1 = {77 77 77 2e 6d 61 72 6d 61 72 61 64 65 6d 6f 2e 63 6f 6d 2f 69 6e 63 6c 75 64 65 2f 65 78 74 65 6e 64 2e 70 68 70}
		$a2 = {77 77 77 2e 33 33 63 6f 77 2e 63 6f 6d 2f 69 6e 63 6c 75 64 65 2f 63 6f 6e 74 72 6f 6c 2e 70 68 70}
		$a3 = {77 77 77 2e 39 37 6e 62 2e 6e 65 74 2f 69 6e 63 6c 75 64 65 2f 61 72 63 2e 73 67 6c 69 73 74 76 69 65 77 2e 70 68 70}
		$c1 = {43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65 3d 22 66 69 6c 65 31 22 3b 20 66 69 6c 65 6e 61 6d 65 3d 22 65 78 61 6d 70 6c 65 2e 64 61 74 22}
		$c2 = {43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65 3d 22 66 69 6c 65 31 22 3b 20 66 69 6c 65 6e 61 6d 65 3d 22 70 72 61 74 69 63 65 2e 70 64 66 22}
		$c3 = {43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65 3d 22 66 69 6c 65 31 22 3b 20 66 69 6c 65 6e 61 6d 65 3d 22 68 61 70 70 79 2e 70 64 66 22}
		$c4 = {43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65 3d 22 66 69 6c 65 31 22 3b 20 66 69 6c 65 6e 61 6d 65 3d 22 6d 79 2e 64 6f 63 22}
		$c5 = {43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65 3d 22 62 6f 61 72 64 5f 69 64 22}
		$s1 = {57 69 6e 68 74 74 70 2e 64 6c 6c}
		$s2 = {57 73 6f 63 6b 33 32 2e 64 6c 6c}
		$s3 = {57 4d 2a 2e 74 6d 70}
		$s4 = {46 4d 2a 2e 74 6d 70}
		$s5 = {43 61 63 68 65 2d 43 6f 6e 74 72 6f 6c 3a 20 6d 61 78 2d 61 67 65 3d 30}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 500KB and ( 1 of ( $a* ) or 2 of ( $c* ) or 4 of them )
}

rule APT_Lazarus_RAT_Jun18_2 : hardened
{
	meta:
		description = "Detects Lazarus Group RAT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/DrunkBinary/status/1002587521073721346"
		date = "2018-06-01"
		hash1 = "e6096fb512a6d32a693491f24e67d772f7103805ad407dc37065cebd1962a547"
		id = "4f2e280e-ed76-5fb9-b137-5191bbea2155"

	strings:
		$s1 = {5c 4b 42 5c 52 65 6c 65 61 73 65 5c}
		$s3 = {4b 00 42 00 2c 00 20 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 20 00 31 00 2e 00 30 00}
		$s4 = {54 00 4f 00 44 00 4f 00 3a 00 20 00 28 00 63 00 29 00 20 00 3c 00 43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 20 00 6e 00 61 00 6d 00 65 00 3e 00 2e 00 20 00 20 00 41 00 6c 00 6c 00 20 00 72 00 69 00 67 00 68 00 74 00 73 00 20 00 72 00 65 00 73 00 65 00 72 00 76 00 65 00 64 00 2e 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 5000KB and 2 of them
}

