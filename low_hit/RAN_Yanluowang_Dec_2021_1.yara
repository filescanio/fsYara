rule RAN_Yanluowang_Dec_2021_1 : hardened
{
	meta:
		description = "Detect Yanluowang ransomware"
		author = "Arkbird_SOLG"
		date = "2021-12-17"
		reference1 = "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/yanluowang-ransomware-attacks-continue"
		reference2 = "https://samples.vx-underground.org/samples/Families/YanluowangRansomware/"
		hash1 = "49d828087ca77abc8d3ac2e4719719ca48578b265bbb632a1a7a36560ec47f2d"
		hash2 = "d11793433065633b84567de403c1989640a07c9a399dd2753aaf118891ce791c"
		tlp = "white"
		adversary = "-"

	strings:
		$s1 = { 6a 00 68 7b 4d 45 00 e8 52 2a 00 00 6a 00 6a 00 68 44 58 45 00 68 78 58 45 00 68 d8 56 45 00 c6 45 fc 15 8b 3d d8 71 44 00 6a 00 ff d7 6a 00 6a 00 68 80 58 45 00 68 78 58 45 00 68 d8 56 45 00 6a 00 ff d7 6a 00 6a 00 68 a0 58 45 00 68 78 58 45 00 68 d8 56 45 00 6a 00 ff d7 6a 00 6a 00 68 b8 58 45 00 68 78 58 45 00 68 d8 56 45 00 6a 00 ff d7 6a 00 6a 00 68 cc 58 45 00 68 78 58 45 00 68 d8 56 45 00 6a 00 ff d7 6a 00 6a 00 68 e4 58 45 00 68 78 58 45 00 68 d8 56 45 00 6a 00 ff d7 6a 00 6a 00 68 fc 58 45 00 68 78 58 45 00 68 d8 56 45 00 6a 00 ff d7 6a 00 6a 00 68 10 59 45 00 68 78 58 45 00 68 d8 56 45 00 6a 00 ff d7 6a 00 6a 00 68 2c 59 45 00 68 78 58 45 00 68 d8 56 45 00 6a 00 ff d7 6a 00 6a 00 68 40 59 45 00 68 78 58 45 00 68 d8 56 45 00 6a 00 ff d7 6a 00 6a 00 68 54 59 45 00 68 78 58 45 00 68 d8 56 45 00 6a 00 ff d7 6a 00 6a 00 68 68 59 45 00 68 78 58 45 00 68 d8 56 45 00 6a 00 ff d7 6a 00 6a 00 68 88 59 45 00 68 78 58 45 00 68 d8 56 45 00 6a 00 ff d7 6a 00 6a 00 68 a0 59 45 00 68 78 58 45 00 68 d8 56 45 00 6a 00 ff d7 6a 00 6a 00 68 b8 59 45 00 68 78 58 45 00 68 d8 56 45 00 6a 00 ff d7 6a 00 6a 00 68 d0 59 45 00 68 78 58 45 00 68 d8 56 45 00 6a 00 ff d7 6a 00 6a 00 68 ec 59 45 00 68 78 58 45 00 68 d8 56 45 00 6a 00 ff d7 6a 00 6a 00 68 00 5a 45 00 68 78 58 45 00 68 d8 56 45 00 6a 00 ff d7 6a 00 6a 00 68 14 5a 45 00 68 78 58 45 00 68 d8 56 45 00 6a 00 ff d7 6a 00 6a 00 68 28 5a 45 00 68 78 58 45 00 68 d8 56 45 00 6a 00 ff d7 6a 00 6a 00 68 40 5a 45 00 68 78 58 45 00 68 d8 56 45 00 6a 00 ff d7 6a 00 6a 00 68 54 5a 45 00 68 78 58 45 00 68 d8 56 45 00 6a 00 ff d7 6a 00 6a 00 68 80 58 45 00 68 78 58 45 00 68 d8 56 45 00 6a 00 ff d7 6a 00 6a 00 68 68 5a 45 00 68 78 58 45 00 68 d8 56 45 00 6a 00 ff d7 6a 00 6a 00 68 7c 5a 45 00 68 78 58 45 00 }
		$s2 = { 83 bd d4 ee ff ff 10 8d 85 c0 ee ff ff 51 0f 43 85 c0 ee ff ff 8d 8d 90 ee ff ff 50 6a 30 68 a0 56 45 00 8d 85 c0 ee ff ff 50 ff b5 e8 ee ff ff e8 83 45 00 00 83 bd a4 ee ff ff 10 8d 85 90 ee ff ff 6a 00 0f 43 85 90 ee ff ff 6a 00 50 68 d4 56 45 00 68 d8 56 45 00 6a 00 ff d7 8b 95 a4 ee ff ff 83 fa 10 72 2f 8b 8d 90 ee ff ff 42 8b c1 81 fa 00 10 00 00 72 14 8b 49 fc 83 c2 23 2b c1 83 c0 fc }
		$s3 = { 68 00 00 00 f0 6a 01 6a 00 6a 00 8d 85 5c ee ff ff 50 ff 15 14 70 44 00 8d 85 40 ee ff ff 50 57 6a 01 ff b5 5c ee ff ff ff 15 40 70 44 00 8b 35 1c 70 44 00 8d 85 60 ec ff ff 6a 20 50 6a 00 6a 00 6a 01 6a 00 ff b5 40 ee ff ff c7 85 e8 ee ff ff 20 00 00 00 c7 85 60 ec ff ff 20 00 00 00 ff d6 ff b5 60 ec ff ff e8 1f cc 01 00 8b 8d 50 ec ff ff 83 c4 04 89 85 4c ec ff ff 0f 10 01 0f 11 00 0f 10 41 10 8d 8d e8 ee ff ff 0f 11 40 10 ff b5 60 ec ff ff 51 50 6a 00 6a 01 6a 00 ff b5 40 ee ff ff ff d6 8d 85 6c ec ff ff 33 ff 50 57 6a 01 68 80 00 00 00 ff b5 4c ec ff ff 89 bd 40 ec ff ff 89 bd bc ee ff ff ff 15 3c 70 44 00 85 c0 74 47 ff b5 6c ec ff ff e8 ae cb 01 00 83 c4 04 8b f0 8d 85 6c ec ff ff 89 b5 bc ee ff ff 50 56 6a 01 68 80 00 00 00 ff b5 4c ec ff ff ff 15 3c 70 44 00 85 }
		$s4 = { 8b ec 6a ff 68 2b 52 44 00 64 a1 00 00 00 00 50 81 ec 8c 02 00 00 a1 c0 c8 45 00 33 c5 89 45 f0 56 57 50 8d 45 f4 64 a3 00 00 00 00 6a 05 33 c0 c7 45 c0 00 00 00 00 68 84 57 45 00 8d 4d c0 c7 45 d0 00 00 00 00 c7 45 d4 07 00 00 00 66 89 45 c0 e8 59 3f 00 00 c7 45 fc 00 00 00 00 8d 4d d8 6a 03 33 c0 c7 45 d8 00 00 00 00 68 90 57 45 00 c7 45 e8 00 00 00 00 c7 45 ec 07 00 00 00 66 89 45 d8 e8 28 3f 00 00 6a 00 6a 0f c7 45 fc 01 00 00 00 ff 15 98 70 44 00 8b f0 89 b5 74 fd ff ff 83 fe ff 0f 84 2c 02 00 00 a1 9c 70 44 00 8d 7d c0 8b 0d 48 70 44 00 89 85 7c fd ff ff a1 80 70 44 00 89 85 78 fd ff ff a1 4c 70 44 00 89 85 80 fd ff ff a1 90 70 44 00 c7 85 88 fd ff ff 00 00 00 00 89 bd 84 fd ff ff 89 8d 6c fd ff ff 89 85 70 fd ff ff 66 66 66 }

	condition:
		uint16( 0 ) == 0x5A4D and filesize > 100KB and all of ( $s* )
}

