rule APT_MAL_RANSOM_ViceSociety_PolyVice_Jan23_1 : hardened
{
	meta:
		description = "Detects NTRU-ChaChaPoly (PolyVice) malware used by Vice Society"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.sentinelone.com/labs/custom-branded-ransomware-the-vice-society-group-and-the-threat-of-outsourced-development/"
		date = "2023-01-12"
		modified = "2023-01-13"
		score = 75
		hash1 = "326a159fc2e7f29ca1a4c9a64d45b76a4a072bc39ba864c49d804229c5f6d796"
		hash2 = "8c8cb887b081e0d92856fb68a7df0dabf0b26ed8f0a6c8ed22d785e596ce87f4"
		hash3 = "9d9e949ecd72d7a7c4ae9deae4c035dcae826260ff3b6e8a156240e28d7dbfef"
		id = "e450407c-6c21-56bf-aedf-8e7f3890abe2"

	strings:
		$x1 = {43 3a 5c 55 73 65 72 73 5c 72 6f 6f 74 5c 44 65 73 6b 74 6f 70 5c 6e 69 58 5c 43 42 5c 6c 69 62 6e 74 72 75 5c}
		$s1 = {43 3a 5c 55 73 65 72 73 5c 72 6f 6f 74}
		$s2 = {23 44 42 47 3a 20 74 61 72 67 65 74 20 3d 20 25 73}
		$s3 = {23 20 2e 2f 25 73 20 5b 2d 70 20 3c 70 61 74 68 3e 5d 2f 5b 2d 66 20 3c 66 69 6c 65 3e 20 5d 20 5b 2d 65 20 3c 65 6e 63 2e 65 78 74 65 6e 73 69 6f 6e 3e 5d 20 5b 2d 6d 20 3c 72 65 71 75 69 72 65 6d 65 6e 74 73 20 66 69 6c 65 20 6e 61 6d 65 3e 5d}
		$s4 = {23 23 23 20 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 20 23 23 23}
		$op1 = { 89 ca 41 01 fa 89 ef 8b 6c 24 24 44 89 c9 09 d1 44 31 e6 89 c8 }
		$op2 = { bd 02 00 00 00 29 cd 48 0f bf d1 8b 44 46 02 01 44 53 02 8d 54 0d 00 83 c1 02 48 0f bf c2 }
		$op3 = { 48 29 c4 4c 8d 74 24 30 4c 89 f1 e8 46 3c 00 00 84 c0 41 89 c4 0f 85 2b 02 00 00 0f b7 45 f2 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 400KB and ( 1 of ( $x* ) or 2 of them ) or 4 of them
}

rule APT_MAL_RANSOM_ViceSociety_Chily_Jan23_1 : hardened
{
	meta:
		description = "Detects Chily or SunnyDay malware used by Vice Society"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.sentinelone.com/labs/custom-branded-ransomware-the-vice-society-group-and-the-threat-of-outsourced-development/"
		date = "2023-01-12"
		score = 80
		hash1 = "4dabb914b8a29506e1eced1d0467c34107767f10fdefa08c40112b2e6fc32e41"
		id = "1be4adb9-e60c-5023-9230-07f5fd16daaa"

	strings:
		$x1 = {2e 5b 43 68 69 6c 79 40 44 72 2e 43 6f 6d 5d}
		$s1 = {6c 6f 63 61 6c 62 69 74 63 6f 69 6e 73 2e 63 6f 6d 2f 62 75 79 5f 62 69 74 63 6f 69 6e 73 27 3e 68 74 74 70 73 3a 2f 2f 6c 6f 63 61 6c 62 69 74 63 6f 69 6e 73 2e 63 6f 6d 2f 62 75 79 5f 62 69 74 63 6f 69 6e 73 3c 2f 61 3e}
		$s2 = {43 3a 5c 55 73 65 72 73 5c 72 6f 6f 74 5c 44 65 73 6b 74 6f 70}
		$s3 = {66 00 6f 00 72 00 20 00 2f 00 46 00 20 00 22 00 74 00 6f 00 6b 00 65 00 6e 00 73 00 3d 00 2a 00 22 00 20 00 25 00 31 00 20 00 69 00 6e 00 20 00 28 00 27 00 77 00 65 00 76 00 74 00 75 00 74 00 69 00 6c 00 2e 00 65 00 78 00 65 00 20 00 65 00 6c 00 27 00 29 00 20 00 44 00 4f 00 20 00 77 00 65 00 76 00 74 00 75 00 74 00 69 00 6c 00 2e 00 65 00 78 00 65 00 20 00 63 00 6c 00 20 00 22 00 25 00 31 00 22 00}
		$s4 = {63 00 64 00 20 00 25 00 75 00 73 00 65 00 72 00 70 00 72 00 6f 00 66 00 69 00 6c 00 65 00 25 00 5c 00 64 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 73 00 5c 00}
		$s5 = {6e 00 6f 00 69 00 73 00 65 00 2e 00 62 00 6d 00 70 00}
		$s6 = {20 45 78 65 63 75 74 69 6f 6e 20 74 69 6d 65 3a 20 25 66 6d 73 20 28 31 73 65 63 3d 31 30 30 30 6d 73 29}
		$s7 = {2f 00 63 00 20 00 76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2e 00 65 00 78 00 65 00 20 00 44 00 65 00 6c 00 65 00 74 00 65 00 20 00 53 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 41 00 6c 00 6c 00 20 00 2f 00 51 00 75 00 69 00 65 00 74 00}
		$op1 = { 4c 89 c5 89 ce 89 0d f5 41 02 00 4c 89 cf 44 8d 04 49 0f af f2 89 15 e9 41 02 00 44 89 c0 }
		$op2 = { 48 8b 03 48 89 d9 ff 50 10 84 c0 0f 94 c0 01 c0 48 83 c4 20 5b }
		$op3 = { 31 c0 47 8d 2c 00 45 85 f6 4d 63 ed 0f 8e ec 00 00 00 0f 1f 80 00 00 00 00 0f b7 94 44 40 0c 00 00 83 c1 01 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 500KB and ( 1 of ( $x* ) or 3 of them ) or 4 of them
}

