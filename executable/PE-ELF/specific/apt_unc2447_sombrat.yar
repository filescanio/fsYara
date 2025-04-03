rule APT_UNC2447_MAL_SOMBRAT_May21_1 : hardened limited
{
	meta:
		description = "Detects SombRAT samples from UNC2447 campaign"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2021/04/unc2447-sombrat-and-fivehands-ransomware-sophisticated-financial-threat.html"
		date = "2021-05-01"
		modified = "2023-01-07"
		hash1 = "61e286c62e556ac79b01c17357176e58efb67d86c5d17407e128094c3151f7f9"
		hash2 = "99baffcd7a6b939b72c99af7c1e88523a50053ab966a079d9bf268aff884426e"
		id = "78b46bed-4fd4-596f-bba7-12243f467af3"

	strings:
		$x1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 7e 61 72 75 6e 67 76 63 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s1 = {70 6c 75 67 69 6e 36 34 5f}
		$s2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 30 78 55 6e 6b 6e 6f 77 6e (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 62 25 78 2e 25 73 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s4 = {2f 6e 65 77 73}
		$sc1 = { 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 73
               00 2E 00 65 00 78 00 65 00 00 00 00 00 00 00 00
               00 49 73 57 6F 77 36 34 50 72 6F 63 65 73 73 00
               00 6B 00 65 00 72 00 6E 00 65 00 6C 00 33 00 32
               00 00 00 00 00 00 00 00 00 47 00 6C 00 6F 00 62
               00 61 00 6C 00 5C 00 25 00 73 }
		$op1 = { 66 90 0f b6 45 80 32 44 0d 81 34 de 88 44 0d 81 48 ff c1 48 83 f9 19 72 e9 }
		$op2 = { 48 8b d0 66 0f 6f 05 ?1 ?? 0? 00 f3 0f 7f 44 24 68 66 89 7c 24 58 41 b8 10 00 00 00 4c 39 40 10 4c 0f 42 40 10 48 83 78 18 08 }
		$op3 = { 49 f7 b0 a0 00 00 00 42 0f b6 04 0a 41 30 44 33 fe 48 83 79 18 10 72 03 48 8b 09 33 d2 b8 05 00 00 00 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 3000KB and ( ( 1 of ( $x* ) and 1 of ( $s* ) ) or 3 of them ) or 5 of them
}

rule APT_UNC2447_MAL_RANSOM_HelloKitty_May21_1 : hardened limited
{
	meta:
		description = "Detects HelloKitty Ransomware samples from UNC2447 campaign"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2021/04/unc2447-sombrat-and-fivehands-ransomware-sophisticated-financial-threat.html"
		date = "2021-05-01"
		hash1 = "02a08b994265901a649f1bcf6772bc06df2eb51eb09906af9fd0f4a8103e9851"
		hash2 = "0e5f7737704c8f25b2b8157561be54a463057cd4d79c7e016c30a1cf6590a85c"
		hash3 = "52dace403e8f9b4f7ea20c0c3565fa11b6953b404a7d49d63af237a57b36fd2a"
		hash4 = "7be901c5f7ffeb8f99e4f5813c259d0227335680380ed06df03fb836a041cb06"
		hash5 = "947e357bfdfe411be6c97af6559fd1cdc5c9d6f5cea122bf174d124ee03d2de8"
		hash6 = "9a7daafc56300bd94ceef23eac56a0735b63ec6b9a7a409fb5a9b63efe1aa0b0"
		hash7 = "a147945635d5bd0fa832c9b55bc3ebcea7a7787e8f89b98a44279f8eddda2a77"
		hash8 = "bade05a30aba181ffbe4325c1ba6c76ef9e02cbe41a4190bd3671152c51c4a7b"
		hash9 = "c2498845ed4b287fd0f95528926c8ee620ef0cbb5b27865b2007d6379ffe4323"
		hash10 = "dc007e71085297883ca68a919e37687427b7e6db0c24ca014c148f226d8dd98f"
		hash11 = "ef614b456ca4eaa8156a895f450577600ad41bd553b4512ae6abf3fb8b5eb04e"
		id = "c84b2430-dcf1-5a80-96a0-02d292ea386b"
		score = 75

	strings:
		$xop1 = { 8b 45 08 8b 75 f4 fe 85 f7 fd ff ff 0f 11 44 05 b4 83 c0 10 89 45 08 83 f8 30 7c 82 }
		$xop2 = { 81 c3 dc a9 b0 5c c1 c9 0b 33 c8 89 55 a0 8b c7 8b 7d e0 c1 c8 06 33 f7 }
		$s1 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 73 00 65 00 6c 00 65 00 63 00 74 00 20 00 2a 00 20 00 66 00 72 00 6f 00 6d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 53 00 68 00 61 00 64 00 6f 00 77 00 43 00 6f 00 70 00 79 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s2 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 62 00 6f 00 6f 00 74 00 66 00 6f 00 6e 00 74 00 2e 00 62 00 69 00 6e 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s3 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 44 00 45 00 43 00 52 00 59 00 50 00 54 00 5f 00 4e 00 4f 00 54 00 45 00 2e 00 74 00 78 00 74 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s4 = {2e 00 6f 00 6e 00 69 00 6f 00 6e 00}
		$sop1 = { 8b f9 0f 57 c0 68 18 01 00 00 6a 00 0f 11 45 dc 8d 5f 20 53 0f 11 45 ec }
		$sop2 = { 56 57 8b f9 0f 57 c0 68 18 01 00 00 6a 00 0f 11 45 dc 8d 5f 20 }
		$sop3 = { 57 8b f9 0f 57 c0 68 18 01 00 00 6a 00 0f 11 45 dc 8d 5f 20 53 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 800KB and 1 of ( $x* ) or 3 of them
}

rule APT_UNC2447_MAL_RANSOM_HelloKitty_May21_2 : hardened limited
{
	meta:
		description = "Detects HelloKitty Ransomware samples from UNC2447 campaign"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2021/04/unc2447-sombrat-and-fivehands-ransomware-sophisticated-financial-threat.html"
		date = "2021-05-01"
		hash1 = "10887d13dba1f83ef34e047455a04416d25a83079a7f3798ce3483e0526e3768"
		hash2 = "3ae7bedf236d4e53a33f3a3e1e80eae2d93e91b1988da2f7fcb8fde5dcc3a0e9"
		hash3 = "501487b025f25ddf1ca32deb57a2b4db43ccf6635c1edc74b9cff54ce0e5bcfe"
		hash4 = "9a7daafc56300bd94ceef23eac56a0735b63ec6b9a7a409fb5a9b63efe1aa0b0"
		id = "82aaabc6-102a-512e-8c2a-4d6fda864c68"

	strings:
		$xop1 = { 50 8d 45 f8 50 ff 75 fc ff 15 ?? ?? 42 00 3d ea 00 00 00 75 18 83 7d f8 00 }
		$s1 = {48 00 65 00 6c 00 6c 00 6f 00 4b 00 69 00 74 00 74 00 79 00 4d 00 75 00 74 00 65 00 78 00}
		$s2 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 25 00 73 00 5c 00 72 00 65 00 61 00 64 00 5f 00 6d 00 65 00 5f 00 6c 00 6b 00 64 00 2e 00 74 00 78 00 74 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s3 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 2f 00 43 00 20 00 70 00 69 00 6e 00 67 00 20 00 31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 20 00 26 00 20 00 64 00 65 00 6c 00 20 00 25 00 73 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s4 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 28 25 64 29 20 5b 25 64 5d 20 25 73 3a 20 53 54 4f 50 20 44 4f 55 42 4c 45 20 50 52 4f 43 45 53 53 20 52 55 4e (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$sop1 = { 6a 00 6a 01 ff 75 fc ff 15 ?? ?? 42 00 85 c0 0f 94 c3 ff 75 fc ff 15 ?? ?? 42 00 }
		$sop2 = { 74 12 6a 00 6a 01 ff 75 fc ff 15 ?? ?? 42 00 85 c0 0f 94 c3 ff 75 fc }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 600KB and 1 of ( $x* ) or 2 of them
}

rule APT_UNC2447_PS1_WARPRISM_May21_1 : hardened limited
{
	meta:
		description = "Detects WARPRISM PowerShell samples from UNC2447 campaign"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2021/04/unc2447-sombrat-and-fivehands-ransomware-sophisticated-financial-threat.html"
		date = "2021-05-01"
		score = 65
		hash1 = "3090bff3d16b0b150444c3bfb196229ba0ab0b6b826fa306803de0192beddb80"
		hash2 = "63ba6db8c81c60dd9f1a0c7c4a4c51e2e56883f063509ed7b543ad7651fd8806"
		hash3 = "b41a303a4caa71fa260dd601a796033d8bfebcaa6bd9dfd7ad956fac5229a735"
		id = "fa389a45-3b31-5a84-9882-49fd6ee8cac5"

	strings:
		$x1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 69 66 20 28 24 4d 79 49 6e 76 6f 63 61 74 69 6f 6e 2e 4d 79 43 6f 6d 6d 61 6e 64 2e 50 61 74 68 20 2d 6d 61 74 63 68 20 27 5c 53 27 29 20 7b (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s1 = {((5b 44 6c 6c 49 6d 70 6f 72 74 28 22 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 22 29 5d 70 75 62 6c 69 63 20 73 74 61 74 69 63 20 65 78 74 65 72 6e 20 49 6e 74 50 74 72 20 56 69 72 74 75 61 6c 41 6c 6c 6f 63 28 49 6e 74 50 74 72 20) | (5b 00 44 00 6c 00 6c 00 49 00 6d 00 70 00 6f 00 72 00 74 00 28 00 22 00 6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 22 00 29 00 5d 00 70 00 75 00 62 00 6c 00 69 00 63 00 20 00 73 00 74 00 61 00 74 00 69 00 63 00 20 00 65 00 78 00 74 00 65 00 72 00 6e 00 20 00 49 00 6e 00 74 00 50 00 74 00 72 00 20 00 56 00 69 00 72 00 74 00 75 00 61 00 6c 00 41 00 6c 00 6c 00 6f 00 63 00 28 00 49 00 6e 00 74 00 50 00 74 00 72 00 20 00))}
		$s2 = {((5b 52 75 6e 74 69 6d 65 2e 49 6e 74 65 72 6f 70 53 65 72 76 69 63 65 73 2e 4d 61 72 73 68 61 6c 5d 3a 3a 43 6f 70 79 28 24) | (5b 00 52 00 75 00 6e 00 74 00 69 00 6d 00 65 00 2e 00 49 00 6e 00 74 00 65 00 72 00 6f 00 70 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 2e 00 4d 00 61 00 72 00 73 00 68 00 61 00 6c 00 5d 00 3a 00 3a 00 43 00 6f 00 70 00 79 00 28 00 24 00))}
		$s3 = {((5b 53 79 73 74 65 6d 2e 44 69 61 67 6e 6f 73 74 69 63 73 2e 50 72 6f 63 65 73 73 5d 3a 3a 53 74 61 72 74 28 28 2d 6a 6f 69 6e 28) | (5b 00 53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 44 00 69 00 61 00 67 00 6e 00 6f 00 73 00 74 00 69 00 63 00 73 00 2e 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 5d 00 3a 00 3a 00 53 00 74 00 61 00 72 00 74 00 28 00 28 00 2d 00 6a 00 6f 00 69 00 6e 00 28 00))}

	condition:
		filesize < 5000KB and 1 of ( $x* ) or 2 of them
}

rule APT_UNC2447_BAT_Runner_May21_1 : hardened
{
	meta:
		description = "Detects Batch script runners from UNC2447 campaign"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2021/04/unc2447-sombrat-and-fivehands-ransomware-sophisticated-financial-threat.html"
		date = "2021-05-01"
		modified = "2023-01-07"
		hash1 = "ccacf4658ae778d02e4e55cd161b5a0772eb8b8eee62fed34e2d8f11db2cc4bc"
		id = "0bacd4f7-421a-570f-9f74-5a19ab806dd0"

	strings:
		$x1 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 63 20 22 5b 53 79 73 74 65 6d 2e 54 65 78 74 2e 45 6e 63 6f 64 69 6e 67 5d 3a 3a 55 54 46 38 2e 47 65 74 53 74 72 69 6e 67 28 5b 53 79 73 74 65 6d 2e 43 6f 6e 76 65 72 74 5d 3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 5b 49 4f 2e 46 69 6c 65 5d 3a 3a}
		$x2 = {77 77 61 6e 73 76 63 2e 74 78 74 27 29 29 29 22 20 7c 20 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d}

	condition:
		filesize < 5000KB and 1 of them
}

