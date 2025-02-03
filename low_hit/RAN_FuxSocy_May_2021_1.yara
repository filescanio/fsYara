rule RAN_FuxSocy_May_2021_1 : hardened
{
	meta:
		description = "Detect FuxSocy ransomware"
		author = "Arkbird_SOLG"
		reference = "Internal Research"
		date = "2020-05-09"
		hash1 = "d786355c1b3dc741103873aed46d8ffa3430d113a27482f37f3ffc7c978747f6"
		hash2 = "43bbfb3389deb3846bba19a8ab2e9c8fd9b581720962b8170d4a63ad816b5804"
		tlp = "White"
		adversary = "-"

	strings:
		$seq1 = { b8 48 14 00 00 e8 b8 83 00 00 53 55 56 8d 44 24 48 8b e9 50 55 89 54 24 14 33 f6 ff 15 84 02 41 00 8b d8 85 db 0f 84 fa 00 00 00 57 8b cb e8 2b 09 00 00 8b f8 85 ff 0f 84 e7 00 00 00 57 53 56 55 ff 15 8c 02 41 00 8b 1d 78 02 41 00 8d 44 24 18 50 8d 44 24 18 50 68 cc 14 48 00 57 89 74 24 24 89 74 24 28 ff d3 83 7c 24 18 04 0f 82 ab 00 00 00 8b 44 24 10 8b 4c 24 14 c7 44 24 1c 00 15 48 00 c7 44 24 20 14 15 48 00 c7 44 24 24 30 15 48 00 c7 44 24 28 48 15 48 00 c7 44 24 2c 60 15 48 00 c7 44 24 30 80 15 48 00 c7 44 24 34 a0 15 48 00 c7 44 24 38 c0 15 48 00 c7 44 24 3c e0 15 48 00 c7 44 24 40 fc 15 48 00 c7 44 24 44 14 16 48 00 c7 44 24 48 38 16 48 00 ff 74 84 1c 0f b7 41 02 50 0f b7 01 50 8d 44 24 60 68 54 16 48 00 50 ff 15 64 02 41 00 83 c4 14 8d 44 24 50 50 8d 44 24 14 50 8d 44 24 5c 50 57 ff d3 85 c0 74 0d 8b 4c 24 10 33 d2 e8 47 0a 00 00 8b f0 8b cf e8 c9 08 00 00 5f 8b c6 5e 5d 5b 81 c4 48 14 00 00 }
		$seq2 = { 8d 44 24 50 50 8d 44 24 4c 50 8d 44 24 2c 50 55 ff 15 ec 00 41 00 8b 44 24 14 8b 74 24 18 ff 74 24 68 88 87 57 01 08 00 66 a1 80 4d 41 00 [10] 88 9f 54 01 08 00 c6 87 63 01 08 00 10 89 b7 58 01 08 00 66 89 87 5d 01 08 00 ff 15 6c 00 41 00 0f b6 97 63 01 08 00 03 c0 66 89 87 55 01 08 00 8b 44 24 20 8d 8f 64 01 08 00 88 87 5c 01 08 00 e8 14 2b 00 00 8b 44 24 14 0f b6 c8 0f b7 87 55 01 08 00 83 c1 03 8d 0c c8 89 8f 4c 01 08 00 e8 2e 3a 00 00 8b c8 89 8f 48 01 08 00 85 c9 0f 84 0f 01 00 00 8b 44 24 28 89 41 04 8b 8f 48 01 08 00 8b 44 24 24 89 01 8b 8f 48 01 08 00 8b 44 24 4c 89 41 0c 8b 8f 48 01 08 00 8b 44 24 48 89 41 08 8b 8f 48 01 08 00 8b 44 24 54 89 41 14 8b 8f 48 01 08 00 8b 44 24 50 89 41 10 0f b7 87 55 01 08 00 50 8b 87 48 01 08 00 ff 74 24 6c 83 c0 18 50 e8 b4 b5 00 00 8b 4c 24 6c 33 d2 e8 bd 3b 00 00 8b 4c 24 70 33 d2 89 47 08 e8 af 3b 00 00 0f b6 97 63 01 08 00 89 47 0c 8b 44 24 78 89 87 28 02 08 00 8b 44 24 44 89 47 04 8d 87 44 00 08 00 50 8d 8f 64 01 08 00 89 2f e8 4d 24 00 00 89 b7 18 02 08 00 8b 87 c5 01 08 00 f7 a7 58 01 08 00 8b c8 0f b6 87 5c 01 08 00 8b f2 99 83 c4 10 ff b7 28 02 08 00 03 c8 13 f2 03 0d 80 4d 41 00 13 35 84 4d 41 00 89 8f 1c 02 08 00 89 b7 20 02 08 00 ff 15 c4 00 41 00 53 57 ff 74 24 44 55 ff 15 e8 00 41 00 }
		$seq3 = { 57 68 ff 01 0f 00 ff 75 08 8b fa 51 32 db ff 15 0c 00 41 00 8b f0 85 f6 74 76 32 ff eb 52 84 ff 75 65 33 c0 50 50 50 50 50 50 50 6a ff 6a 04 6a ff 56 ff 15 10 00 41 00 8b 45 c0 83 f8 01 74 2c 76 2e 83 f8 03 76 1a 83 f8 04 75 24 8d 45 e0 50 6a 01 56 ff 15 18 00 41 00 }
		$seq4 = { 6a ff 8d 45 fc 50 8d 45 08 50 8d 45 f8 50 ff 33 33 ff 89 7d f8 89 7d 08 89 7d fc ff 15 c8 00 41 00 85 c0 8b 45 08 0f 95 c1 85 c0 74 59 56 }
		$seq5 = { 8b 45 08 56 ff 70 08 ff 15 dc 00 41 00 8b ce e8 af 2e 00 00 33 ff 57 ff 75 08 57 ff 33 ff 15 e4 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 30KB and 3 of ( $seq* )
}

