rule RAN_Conti_May_2021_2 : hardened
{
	meta:
		description = "Detect unpacked Conti ransomware (May 2021)"
		author = "Arkbird_SOLG"
		reference = "Internal Research"
		date = "2021-05-20"
		hash1 = "Redacted"
		hash2 = "a5751a46768149c5ddf318fd75afc66b3db28a5b76254ee0d6ae27b21712e266"
		hash3 = "74b7a1da50ce44b640d84422bb3f99e2f338cc5d5be9ef5f1ad03c8e947296c3"
		hash4 = "ef2cd9ded5532af231e0990feaf2df8fd79dc63f7a677192e17b89ef4adb7dd2"

	strings:
		$seq1 = { 33 db 3c 2f 74 0a 3c 5c 74 06 3c 3a 8a c3 75 02 b0 01 2b cf 0f b6 c0 41 89 9d 68 fd ff ff f7 d8 89 9d 6c fd ff ff 56 1b c0 89 9d 70 fd ff ff 23 c1 89 9d 74 fd ff ff 89 85 88 fd ff ff 89 9d 78 fd ff ff 88 9d 7c fd ff ff e8 [4] 50 8d 85 68 fd ff ff 50 57 e8 68 fc ff ff 83 c4 0c 8d 8d ac fd ff ff f7 d8 1b c0 53 53 53 51 f7 d0 23 85 70 fd ff ff 53 50 ff 15 [4] 8b f0 83 fe ff 75 18 ff b5 a4 fd ff ff 53 53 57 e8 42 fe ff ff 83 c4 10 8b d8 e9 1c 01 00 00 8b 85 a4 fd ff ff 8b 48 04 2b 08 c1 f9 02 89 8d 84 fd ff ff 89 9d 8c fd ff ff 89 9d 90 fd ff ff 89 9d 94 fd ff ff 89 9d 98 fd ff ff 89 9d 9c fd ff ff 88 9d a0 fd ff ff e8 [4] 50 8d 85 ab fd ff ff 50 8d 85 8c fd ff ff 50 8d 85 d8 fd ff ff 50 e8 01 fb ff ff 83 c4 10 f7 d8 1b c0 f7 d0 23 85 94 fd ff ff 80 }
		$seq2 = { 38 9d a0 fd ff ff 74 0c ff b5 94 fd ff ff e8 [2] ff ff 59 8d 85 ac fd ff ff 50 56 ff 15 [4] 85 c0 0f 85 4d ff ff ff 8b 85 a4 fd ff ff 8b 8d 84 fd ff ff 8b 10 8b 40 04 2b c2 c1 f8 02 3b c8 74 34 68 [4] 2b c1 6a 04 50 8d 04 8a 50 e8 [2] 00 00 83 c4 10 eb 1c 38 9d a0 fd ff ff 74 12 ff b5 94 fd ff ff e8 [2] ff ff 8b 85 80 fd ff ff 59 8b d8 56 ff 15 [4] 80 bd 7c fd ff ff 00 5e 74 0c ff b5 70 fd ff ff e8 [2] ff ff 59 8b }
		$seq3 = { 6a 0c 68 [4] e8 [2] ff ff 33 f6 89 75 e4 8b 45 08 ff 30 e8 [2] ff ff 59 89 75 fc 8b 45 0c 8b 00 8b 38 8b d7 c1 fa 06 8b c7 83 e0 3f 6b c8 38 8b 04 95 [4] f6 44 08 28 01 74 21 57 e8 [2] ff ff 59 50 ff 15 [4] 85 c0 75 1d e8 [2] ff ff 8b f0 ff 15 [4] 89 06 e8 [2] ff ff c7 00 09 00 00 00 83 ce ff 89 75 e4 c7 45 fc fe ff ff ff e8 0d 00 00 00 8b c6 e8 [2] ff }
		$seq4 = { 8b ff 55 8b ec 56 6a 00 ff 75 10 ff 75 0c ff 75 08 ff 35 [4] ff 15 [4] 8b f0 85 f6 75 2d ff 15 [4] 83 f8 06 75 22 e8 b6 ff ff ff e8 73 ff ff ff 56 ff 75 10 ff 75 0c ff 75 08 ff 35 [4] ff 15 [4] 8b f0 8b c6 5e }
		$seq5 = { 55 8b ec 81 ec b4 09 00 00 a1 08 [3] 33 c5 89 45 fc 53 56 57 6a ?? 68 [4] ba 18 00 00 00 33 c9 e8 [2] ff ff 83 c4 08 6a 00 6a 00 ff d0 8b f0 85 f6 0f 88 9a 03 00 00 c7 85 8c f7 ff ff [3] 00 bb 03 00 00 00 8b 85 8c f7 ff ff 99 f7 fb 8b 85 8c f7 ff ff 8d 7b 02 85 d2 74 57 83 c0 02 03 c6 89 85 8c f7 ff ff 8b 85 8c f7 ff ff 25 03 00 00 80 79 07 48 83 c8 fc 83 c0 01 0f 85 64 01 00 00 66 66 0f 1f 84 00 00 00 00 00 8b 85 8c f7 ff ff 40 89 85 8c f7 ff ff 8b 85 8c f7 ff ff 25 03 00 00 80 79 07 48 83 c8 fc 83 c0 01 74 dd e9 32 01 00 00 25 01 00 00 80 79 07 48 83 c8 fe 83 c0 01 74 47 b8 02 00 00 00 2b }
		$seq6 = { 83 3b 00 c7 45 94 00 00 00 00 0f 86 57 02 00 00 8b 35 b4 21 41 00 8d 4b 14 8b 3d c8 21 41 00 8b 1d 9c 21 41 00 89 4d 90 c7 45 98 7f 00 00 00 89 b5 7c ff ff ff 89 bd 78 ff ff ff 89 5d 9c 0f 1f 40 00 8b 11 8d 45 d0 89 55 cc b9 2c 00 00 00 0f 1f 00 c6 00 00 8d 40 01 83 e9 01 75 f5 52 ff d6 8b f0 ff d7 c6 45 b4 00 bf 7f 00 00 00 c6 45 b5 42 c6 45 b6 31 c6 45 b7 2a c6 45 b8 0b c6 45 b9 63 8a 4d b5 80 7d b4 00 75 28 33 c9 66 0f 1f 44 00 00 8a 44 0d b5 0f b6 c0 83 e8 63 6b c0 25 99 f7 ff 8d 42 7f 99 f7 ff 88 54 0d b5 41 83 f9 05 72 e0 8d 45 b5 50 56 ff d3 c6 45 a0 00 c6 45 a1 51 c6 45 a2 1f c6 45 a3 2b c6 45 a4 44 c6 45 a5 51 c6 45 a6 12 c6 45 a7 45 c6 45 a8 44 c6 45 a9 26 89 45 84 8a 45 a1 80 7d a0 00 75 27 33 c9 0f 1f 00 8a 44 0d a1 0f b6 c0 83 e8 26 8d 04 80 03 c0 99 f7 ff 8d 42 7f 99 f7 ff 88 54 0d a1 41 83 f9 09 72 de 8d 45 a1 50 56 ff d3 c6 45 bc 00 8b d8 c6 45 bd 42 c6 45 be 19 c6 45 bf 46 c6 45 c0 59 8a 4d bd 80 7d bc 00 89 5d 88 75 2c 33 ff 8d 5f 7f 8a 44 3d bd 0f b6 c8 83 e9 59 8b c1 c1 e0 05 2b c1 99 f7 fb 8d 42 7f 99 f7 fb 88 54 3d bd 47 83 ff 04 72 dc 8b 5d 88 8d 45 bd 50 56 ff 55 9c c6 45 ac 00 8b f8 c6 45 ad 76 c6 45 ae 30 c6 45 af 06 c6 45 b0 21 c6 45 b1 2a 8a 4d ad 80 7d ac 00 75 24 33 c9 8a 44 0d ad 0f b6 c0 83 e8 2a 8d 04 c0 99 f7 7d 98 8d 42 7f 99 f7 7d 98 88 54 0d ad 41 83 f9 05 72 de 8d 45 ad 50 56 ff 55 9c }

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 50KB and 5 of ( $seq* )
}

