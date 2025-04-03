rule MAL_RANSOM_Darkside_May21_1 : hardened
{
	meta:
		description = "Detects Darkside Ransomware"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://app.any.run/tasks/020c1740-717a-4191-8917-5819aa25f385/"
		date = "2021-05-10"
		hash1 = "ec368752c2cf3b23efbfa5705f9e582fc9d6766435a7b8eea8ef045082c6fbce"
		id = "e5592065-591e-597b-bebb-f20bc306fe52"

	strings:
		$op1 = { 85 c9 75 ed ff 75 10 ff b5 d8 fe ff ff ff b5 dc fe ff ff e8 7d fc ff ff ff 8d cc fe ff ff 8b 8d cc fe ff ff }
		$op2 = { 66 0f 6f 06 66 0f 7f 07 83 c6 10 83 c7 10 49 85 c9 75 ed 5f }
		$op3 = { 6a 00 ff 15 72 0d 41 00 ab 46 81 fe 80 00 00 00 75 2e 6a ff 6a 01 }
		$op4 = { 0f b7 0c 5d 88 0f 41 00 03 4c 24 04 89 4c 24 04 83 e1 3f 0f b7 14 4d 88 0f 41 00 03 54 24 08 89 54 24 08 83 e2 3f }
		$s1 = {68 74 74 70 3a 2f 2f 64 61 72 6b 73 69 64}
		$s2 = {5b 20 57 65 6c 63 6f 6d 65 20 74 6f 20 44 61 72 6b 53 69 64 65 20 5d}
		$s3 = {2e 6f 6e 69 6f 6e 2f}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 200KB and 3 of them or all of ( $op* ) or all of ( $s* )
}

rule MAL_Ransomware_Win_DARKSIDE_v1_1 : hardened
{
	meta:
		author = "FireEye"
		date = "2021-03-22"
		score = 75
		description = "Detection for early versions of DARKSIDE ransomware samples based on the encryption mode configuration values."
		hash = "1a700f845849e573ab3148daef1a3b0b"
		reference = "https://www.fireeye.com/blog/threat-research/2021/05/shining-a-light-on-darkside-ransomware-operations.html"
		id = "322a3de5-a7e5-52b9-8648-6019954e92d7"

	strings:
		$consts = { 80 3D [4] 01 [1-10] 03 00 00 00 [1-10] 03 00 00 00 [1-10] 00 00 04 00 [1-10] 00 00 00 00 [1-30] 80 3D [4] 02 [1-10] 03 00 00 00 [1-10] 03 00 00 00 [1-10] FF FF FF FF [1-10] FF FF FF FF [1-30] 03 00 00 00 [1-10] 03 00 00 00 }

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and $consts
}

rule MAL_Dropper_Win_Darkside_1 : hardened limited
{
	meta:
		author = "FireEye"
		date_created = "2021-05-11"
		description = "Detection for on the binary that was used as the dropper leading to DARKSIDE."
		reference = "https://www.fireeye.com/blog/threat-research/2021/05/shining-a-light-on-darkside-ransomware-operations.html"
		id = "910a581c-25a4-5d5e-acdc-6d87cbedd3cf"

	strings:
		$CommonDLLs1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 4b 45 52 4e 45 4c 33 32 2e 64 6c 6c (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$CommonDLLs2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 55 53 45 52 33 32 2e 64 6c 6c (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$CommonDLLs3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 41 44 56 41 50 49 33 32 2e 64 6c 6c (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$CommonDLLs4 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 6f 6c 65 33 32 2e 64 6c 6c (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$KeyString1 = { 74 79 70 65 3D 22 77 69 6E 33 32 22 20 6E 61 6D 65 3D 22 4D 69 63 72 6F 73 6F 66 74 2E 57 69 6E 64 6F 77 73 2E 43 6F 6D 6D 6F 6E 2D 43 6F 6E 74 72 6F 6C 73 22 20 76 65 72 73 69 6F 6E 3D 22 36 2E 30 2E 30 2E 30 22 20 70 72 6F 63 65 73 73 6F 72 41 72 63 68 69 74 65 63 74 75 72 65 3D 22 78 38 36 22 20 70 75 62 6C 69 63 4B 65 79 54 6F 6B 65 6E 3D 22 36 35 39 35 62 36 34 31 34 34 63 63 66 31 64 66 22 }
		$KeyString2 = { 74 79 70 65 3D 22 77 69 6E 33 32 22 20 6E 61 6D 65 3D 22 4D 69 63 72 6F 73 6F 66 74 2E 56 43 39 30 2E 4D 46 43 22 20 76 65 72 73 69 6F 6E 3D 22 39 2E 30 2E 32 31 30 32 32 2E 38 22 20 70 72 6F 63 65 73 73 6F 72 41 72 63 68 69 74 65 63 74 75 72 65 3D 22 78 38 36 22 20 70 75 62 6C 69 63 4B 65 79 54 6F 6B 65 6E 3D 22 31 66 63 38 62 33 62 39 61 31 65 31 38 65 33 62 22 }
		$Slashes = { 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C }

	condition:
		filesize < 2MB and filesize > 500KB and uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 and ( all of ( $CommonDLLs* ) ) and ( all of ( $KeyString* ) ) and $Slashes
}

rule MAL_Backdoor_Win_C3_1 : hardened limited
{
	meta:
		author = "FireEye"
		date_created = "2021-05-11"
		description = "Detection to identify the Custom Command and Control (C3) binaries."
		md5 = "7cdac4b82a7573ae825e5edb48f80be5"
		reference = "https://www.fireeye.com/blog/threat-research/2021/05/shining-a-light-on-darkside-ransomware-operations.html"
		id = "60eb022e-6f4e-5c7d-9ddf-b458a593071e"

	strings:
		$dropboxAPI = {44 72 6f 70 62 6f 78 2d 41 50 49 2d 41 72 67}
		$knownDLLs1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 57 49 4e 48 54 54 50 2e 64 6c 6c (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$knownDLLs2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 53 48 4c 57 41 50 49 2e 64 6c 6c (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$knownDLLs3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 4e 45 54 41 50 49 33 32 2e 64 6c 6c (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$knownDLLs4 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 4f 44 42 43 33 32 2e 64 6c 6c (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$tokenString1 = { 5B 78 5D 20 65 72 72 6F 72 20 73 65 74 74 69 6E 67 20 74 6F 6B 65 6E }
		$tokenString2 = { 5B 78 5D 20 65 72 72 6F 72 20 63 72 65 61 74 69 6E 67 20 54 6F 6B 65 6E }
		$tokenString3 = { 5B 78 5D 20 65 72 72 6F 72 20 64 75 70 6C 69 63 61 74 69 6E 67 20 74 6F 6B 65 6E }

	condition:
		filesize < 5MB and uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 and ( ( ( all of ( $knownDLLs* ) ) and ( $dropboxAPI or ( 1 of ( $tokenString* ) ) ) ) or ( all of ( $tokenString* ) ) )
}

