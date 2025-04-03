rule APT_MAL_NK_Lazarus_VHD_Ransomware_Oct20_1 : hardened limited
{
	meta:
		description = "Detects Lazarus VHD Ransomware"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/lazarus-on-the-hunt-for-big-game/97757/"
		date = "2020-10-05"
		hash1 = "52888b5f881f4941ae7a8f4d84de27fc502413861f96ee58ee560c09c11880d6"
		hash2 = "5e78475d10418c6938723f6cfefb89d5e9de61e45ecf374bb435c1c99dd4a473"
		hash3 = "6cb9afff8166976bd62bb29b12ed617784d6e74b110afcf8955477573594f306"
		id = "5cb3c136-ec5c-5596-8dcc-e4c6ef33050a"

	strings:
		$s1 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 48 00 6f 00 77 00 54 00 6f 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 2e 00 74 00 78 00 74 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s2 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 72 00 73 00 61 00 2e 00 63 00 70 00 70 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 73 63 20 73 74 6f 70 20 22 4d 69 63 72 6f 73 6f 66 74 20 45 78 63 68 61 6e 67 65 20 43 6f 6d 70 6c 69 61 6e 63 65 20 53 65 72 76 69 63 65 22 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$op1 = { 8b 8d bc fc ff ff 8b 94 bd 34 03 00 00 33 c0 50 }
		$op2 = { 8b 8d 98 f9 ff ff 8d 64 24 00 8b 39 3b bc 85 34 }
		$op3 = { 8b 94 85 34 03 00 00 89 11 40 83 c1 04 3b 06 7c }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 400KB and 2 of them
}

rule APT_MAL_NK_Lazarus_VHD_Ransomware_Oct20_2 : hardened
{
	meta:
		description = "Detects Lazarus VHD Ransomware"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/lazarus-on-the-hunt-for-big-game/97757/"
		date = "2020-10-05"
		hash1 = "097ca829e051a4877bca093cee340180ff5f13a9c266ad4141b0be82aae1a39b"
		hash2 = "73a10be31832c9f1cbbd798590411009da0881592a90feb472e80025dfb0ea79"
		id = "b75668de-93e6-57e7-90f0-fa335295be7c"

	strings:
		$op1 = { f9 36 88 08 8d ad fc ff ff ff 66 ff c1 e9 72 86 }
		$op2 = { c6 c4 58 0f a4 c8 12 8d ad ff ff ff ff 0f b6 44 }
		$op3 = { 88 02 66 c1 f0 54 8d bf fc ff ff ff 0f ba e0 19 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 9000KB and all of them
}

