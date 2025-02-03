rule Sofacy_Fybis_ELF_Backdoor_Gen1 : hardened
{
	meta:
		description = "Detects Sofacy Fysbis Linux Backdoor"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://researchcenter.paloaltonetworks.com/2016/02/a-look-into-fysbis-sofacys-linux-backdoor/"
		date = "2016-02-13"
		modified = "2023-01-27"
		score = 80
		hash1 = "02c7cf55fd5c5809ce2dce56085ba43795f2480423a4256537bfdfda0df85592"
		hash2 = "8bca0031f3b691421cb15f9c6e71ce193355d2d8cf2b190438b6962761d0c6bb"
		id = "c6abf33e-9c5b-5e0f-b7f0-a0741bf9cc3a"

	strings:
		$x1 = {59 6f 75 72 20 63 6f 6d 6d 61 6e 64 20 6e 6f 74 20 77 72 69 74 65 64 20 74 6f 20 70 69 70 65}
		$x2 = {54 65 72 6d 69 6e 61 6c 20 64 6f 6e 60 74 20 73 74 61 72 74 65 64 20 66 6f 72 20 65 78 65 63 75 74 69 6e 67 20 63 6f 6d 6d 61 6e 64}
		$x3 = {43 6f 6d 6d 61 6e 64 20 77 69 6c 6c 20 68 61 76 65 20 65 6e 64 20 77 69 74 68 20 5c 6e}
		$s1 = {57 61 6e 74 65 64 42 79 3d 6d 75 6c 74 69 2d 75 73 65 72 2e 74 61 72 67 65 74 27 20 3e 3e 20 2f 75 73 72 2f 6c 69 62 2f 73 79 73 74 65 6d 64 2f 73 79 73 74 65 6d 2f}
		$s2 = {53 75 63 63 65 73 73 20 65 78 65 63 75 74 65 20 63 6f 6d 6d 61 6e 64 20 6f 72 20 6c 6f 6e 67 20 66 6f 72 20 77 61 69 74 69 6e 67 20 65 78 65 63 75 74 69 6e 67 20 79 6f 75 72 20 63 6f 6d 6d 61 6e 64}
		$s3 = {6c 73 20 2f 65 74 63 20 7c 20 65 67 72 65 70 20 2d 65 22 66 65 64 6f 72 61 2a 7c 64 65 62 69 61 6e 2a 7c 67 65 6e 74 6f 6f 2a 7c 6d 61 6e 64 72 69 76 61 2a 7c 6d 61 6e 64 72 61 6b 65 2a 7c 6d 65 65 67 6f 2a 7c 72 65 64 68 61 74 2a 7c 6c 73 62 2d 2a 7c 73 75 6e 2d 2a 7c 53 55 53 45 2a 7c 72 65 6c 65 61 73 65 22}
		$s4 = {72 6d 20 2d 66 20 2f 75 73 72 2f 6c 69 62 2f 73 79 73 74 65 6d 64 2f 73 79 73 74 65 6d 2f}
		$s5 = {45 78 65 63 53 74 61 72 74 3d}
		$s6 = {3c 74 61 62 6c 65 3e 3c 63 61 70 74 69 6f 6e 3e 3c 66 6f 6e 74 20 73 69 7a 65 3d 34 20 63 6f 6c 6f 72 3d 72 65 64 3e 54 41 42 4c 45 20 45 58 45 43 55 54 45 20 46 49 4c 45 53 3c 2f 66 6f 6e 74 3e 3c 2f 63 61 70 74 69 6f 6e 3e}

	condition:
		( uint16( 0 ) == 0x457f and filesize < 500KB and 1 of ( $x* ) ) or ( 1 of ( $x* ) and 3 of ( $s* ) )
}

rule Sofacy_Fysbis_ELF_Backdoor_Gen2 : hardened
{
	meta:
		description = "Detects Sofacy Fysbis Linux Backdoor"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://researchcenter.paloaltonetworks.com/2016/02/a-look-into-fysbis-sofacys-linux-backdoor/"
		date = "2016-02-13"
		score = 80
		hash1 = "02c7cf55fd5c5809ce2dce56085ba43795f2480423a4256537bfdfda0df85592"
		hash2 = "8bca0031f3b691421cb15f9c6e71ce193355d2d8cf2b190438b6962761d0c6bb"
		hash3 = "fd8b2ea9a2e8a67e4cb3904b49c789d57ed9b1ce5bebfe54fe3d98214d6a0f61"
		id = "d4e3a8bb-b23a-53a4-b5fb-b321a3417b43"

	strings:
		$s1 = {52 65 6d 6f 74 65 53 68 65 6c 6c}
		$s2 = {62 61 73 69 63 5f 73 74 72 69 6e 67 3a 3a 5f 4d 5f 72 65 70 6c 61 63 65 5f 64 69 73 70 61 74 63 68}
		$s3 = {48 74 74 70 43 68 61 6e 6e 65 6c}

	condition:
		uint16( 0 ) == 0x457f and filesize < 500KB and all of them
}

