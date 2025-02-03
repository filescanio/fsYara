rule RAN_ELF_Darkside_Apr_2021_1 : hardened
{
	meta:
		description = "Detect the ELF version of Darkside ransomware"
		author = "Arkbird_SOLG"
		reference = "https://twitter.com/JAMESWT_MHT/status/1388301138437578757"
		date = "2021-05-01"
		hash1 = "984ce69083f2865ce90b48569291982e786980aeef83345953276adfcbbeece8"
		hash2 = "9cc3c217e3790f3247a0c0d3d18d6917701571a8526159e942d0fffb848acffb"
		hash3 = "c93e6237abf041bc2530ccb510dd016ef1cc6847d43bf023351dce2a96fdc33b"
		tlp = "White"
		adversary = "-"

	strings:
		$seq1 = { 48 8d 3d d1 e8 3b 00 e8 9c 51 f2 ff 85 c0 74 c6 4c 8d 6c 24 10 4c 89 ef e8 ab bf 02 00 48 8d 1d 34 bb 37 00 49 8d 75 08 48 8d 3d 31 e1 3b 00 48 8d 43 10 48 89 05 1e e1 3b 00 e8 09 1e 02 00 48 8d 05 22 d8 0e 00 48 8b 7c 24 18 c7 05 4b e1 3b 00 01 00 00 00 48 89 05 1c e1 3b 00 48 8d 05 4d d8 0e 00 48 85 ff 48 89 05 13 e1 3b 00 48 8d 05 84 d8 0e 00 48 89 05 0d e1 3b 00 48 8d 05 be d8 0e 00 48 89 05 07 e1 3b 00 48 8d 05 48 d9 0e 00 48 89 05 01 e1 3b 00 48 8d 43 10 48 89 44 24 10 74 05 e8 21 45 f2 ff 4c 8d ac 24 30 03 00 00 4c 89 ef e8 11 bf 02 00 4c 8d b4 24 10 03 00 00 ba 03 00 00 00 4c 89 ee 4c 89 f7 e8 39 62 ff ff 48 8b bc 24 38 03 00 00 48 8d 43 10 48 89 84 24 30 03 00 00 48 85 ff 74 05 e8 db 44 f2 ff 4c 8d 6c 24 30 ba 01 00 00 00 4c 89 f6 4c 89 ef e8 06 62 ff ff 48 8b bc 24 18 03 00 00 48 8d 43 10 48 89 84 24 10 03 00 00 48 85 ff 74 05 e8 a8 44 f2 ff 48 8d 43 10 49 8d 75 08 48 8d 3d 81 e0 3b 00 48 89 05 72 e0 3b 00 e8 0d 1d 02 00 48 8d 05 26 d7 0e 00 48 8b 7c 24 38 c7 05 9f e0 3b 00 01 00 00 00 48 89 05 70 e0 3b 00 48 8d 05 51 d7 0e 00 48 85 ff 48 89 05 67 e0 3b 00 48 8d 05 88 d7 0e 00 48 89 05 61 e0 3b 00 48 8d 05 c2 d7 0e 00 48 89 05 5b e0 3b 00 48 8d 05 4c d8 0e 00 48 89 05 55 e0 3b 00 48 8d 43 10 48 89 44 24 30 74 05 e8 25 44 f2 ff 4c 8d b4 24 50 03 00 00 4c 89 f7 e8 05 c5 02 00 4c 8d 6c 24 50 ba 01 00 00 00 4c 89 f6 4c 89 ef e8 40 61 ff ff 48 8b bc 24 58 03 00 00 48 8d 43 10 48 89 84 24 50 03 00 00 48 85 ff 74 05 e8 e2 43 f2 ff 48 8d 43 10 49 8d 75 08 48 8d 3d 0b e0 3b 00 48 89 05 fc df 3b 00 e8 47 1c 02 00 48 8d 05 18 d8 0e 00 48 8b 7c 24 58 c7 05 29 e0 3b 00 01 00 00 00 48 89 05 fa df 3b 00 48 8d 05 33 d8 0e 00 48 85 ff 48 89 05 f1 df 3b 00 48 8d 05 5a d8 0e 00 48 89 05 eb df 3b 00 48 8d 05 84 d8 0e 00 48 89 05 e5 df 3b 00 48 8d 05 de d8 0e 00 48 89 05 df df 3b 00 48 8d 43 10 48 89 44 24 50 74 05 e8 5f 43 f2 ff 4c 8d b4 24 70 03 00 00 4c 89 f7 e8 3f c4 02 00 4c 8d 6c 24 70 ba 07 00 00 00 4c 89 f6 4c 89 ef e8 7a 60 ff ff 48 8b bc 24 78 03 00 00 48 8d 43 10 48 89 84 24 70 03 00 00 48 85 ff 74 05 e8 1c 43 f2 ff 48 8d 43 10 49 8d 75 08 48 8d 3d 95 df 3b 00 48 89 05 86 df 3b 00 e8 81 1b 02 00 48 8d 05 9a d8 0e 00 48 8b 7c 24 78 c7 05 b3 df 3b 00 01 00 00 00 48 89 05 84 df 3b 00 48 8d 05 c5 d8 0e 00 48 85 ff 48 89 05 7b df 3b 00 48 8d 05 fc d8 0e 00 48 89 05 75 df 3b 00 48 8d 05 36 d9 0e 00 48 89 05 6f df 3b 00 48 8d 05 b0 d9 0e 00 48 89 05 69 df 3b 00 48 8d 43 10 48 89 44 24 70 74 05 e8 99 42 f2 ff 4c 8d ac 24 90 03 00 00 4c 89 ef e8 19 be 02 00 4c 8d b4 24 b0 03 00 00 ba 01 00 00 00 4c 89 ee 4c 89 f7 e8 b1 5f ff ff 4c 8d ac 24 90 00 00 00 ba 01 00 00 00 4c 89 f6 4c 89 ef e8 99 5f ff ff 48 8b bc 24 b8 03 00 00 48 8d 43 10 48 89 84 24 b0 03 00 00 48 85 ff 74 05 e8 3b 42 f2 ff 48 8b bc 24 98 03 00 00 48 8d 43 10 48 89 84 24 90 03 00 00 48 85 ff 74 05 e8 1d 42 f2 ff 48 8d 43 10 49 8d 75 08 48 8d 3d e6 de 3b 00 48 89 05 d7 de 3b 00 e8 82 1a 02 00 48 8d 05 43 d9 0e 00 48 8b bc 24 98 00 00 00 c7 05 01 df 3b 00 01 00 00 00 48 89 05 d2 de 3b 00 48 8d 05 53 d9 0e 00 48 85 ff 48 89 05 c9 de 3b 00 48 8d 05 72 d9 0e 00 48 89 05 c3 de 3b 00 48 8d 05 94 d9 0e 00 48 89 05 bd de 3b 00 48 8d 05 de d9 0e 00 48 89 05 b7 de 3b 00 48 8d 43 10 48 89 84 24 90 00 00 00 74 05 e8 94 41 f2 ff 4c 8d ac 24 d0 03 00 00 4c 89 ef e8 14 bd 02 00 4c 8d b4 24 f0 03 00 00 ba 01 00 00 00 4c 89 ee 4c 89 f7 e8 ac 5e ff ff 4c 8d ac 24 b0 00 00 00 ba 03 00 00 00 4c 89 f6 4c 89 ef e8 94 5e ff ff 48 8b bc 24 f8 03 00 00 48 8d 43 10 48 89 84 24 f0 03 00 00 48 85 ff 74 05 e8 36 41 f2 ff 48 8b bc 24 d8 03 00 00 48 8d 43 10 48 89 84 24 d0 03 00 00 48 85 ff 74 05 e8 18 41 f2 ff 48 8d 43 10 49 8d 75 08 48 8d 3d 31 de 3b 00 48 89 05 22 de 3b 00 e8 7d 19 02 00 48 8d 05 56 d9 0e 00 48 8b bc 24 b8 00 00 00 c7 05 4c de 3b 00 01 00 00 00 48 89 05 1d de 3b 00 48 8d 05 6e d9 0e 00 48 85 ff 48 89 05 14 de 3b 00 48 8d 05 95 d9 0e 00 48 89 05 0e de 3b 00 48 8d 05 bf d9 0e 00 48 89 05 08 de 3b 00 48 8d 05 19 da 0e 00 48 89 05 02 de 3b 00 48 8d 43 10 48 89 84 24 b0 00 00 00 74 05 e8 8f 40 f2 ff 4c 8d ac 24 10 04 00 00 4c 89 ef e8 0f bc 02 00 4c 8d b4 24 30 04 00 00 ba 01 00 00 00 4c 89 ee 4c 89 f7 e8 a7 5d ff ff 4c 8d ac 24 d0 00 00 00 ba 05 00 00 00 4c 89 f6 4c 89 ef e8 8f 5d ff ff 48 8b bc 24 38 04 00 00 48 8d 43 10 48 89 84 24 30 04 00 00 48 85 ff 74 05 e8 31 40 f2 ff 48 8b bc 24 18 04 00 00 48 8d 43 10 48 89 84 24 10 04 00 00 48 85 ff 74 05 e8 13 40 f2 ff 48 8d 43 10 49 8d 75 08 48 8d 3d 7c dd 3b 00 48 89 05 6d dd 3b 00 e8 78 18 02 00 48 8d 05 99 d9 0e 00 48 8b bc 24 d8 00 00 00 c7 05 97 dd 3b 00 01 00 00 00 48 89 05 68 dd 3b 00 48 8d 05 b9 d9 0e 00 48 85 ff 48 89 05 5f dd 3b 00 48 8d 05 e8 d9 0e 00 48 89 05 59 dd 3b 00 48 8d 05 1a da 0e 00 48 89 05 53 dd 3b 00 48 8d 05 84 da 0e 00 48 89 05 4d dd 3b 00 48 8d 43 10 48 89 84 24 d0 00 00 00 74 05 e8 8a 3f f2 ff 4c 8d ac 24 50 04 00 00 4c 89 ef e8 0a bb 02 00 4c 8d b4 24 70 04 00 00 ba 01 00 00 00 4c 89 ee 4c 89 f7 e8 a2 5c ff ff 4c 8d ac 24 f0 00 00 00 ba 07 00 00 00 4c 89 f6 4c 89 ef e8 8a 5c ff ff 48 8b bc 24 78 04 00 00 48 8d 43 10 48 89 84 24 70 04 00 00 48 85 ff 74 05 e8 2c 3f f2 ff 48 8b bc 24 58 04 00 00 48 8d 43 10 48 89 84 24 50 04 00 00 48 85 ff 74 05 e8 0e 3f f2 ff 48 8d 43 10 49 8d 75 08 48 8d 3d c7 dc 3b 00 48 89 05 b8 dc 3b 00 e8 73 17 02 00 48 8d 05 0c da 0e 00 48 8b bc 24 f8 00 00 00 c7 05 e2 dc 3b 00 01 00 00 00 48 89 05 b3 dc 3b 00 48 8d 05 34 da 0e 00 48 85 ff 48 89 05 aa dc 3b 00 48 8d 05 6b da 0e 00 48 89 05 a4 dc 3b 00 48 8d 05 a5 da 0e 00 48 89 05 9e dc 3b 00 48 8d 05 1f db 0e 00 48 89 05 98 dc 3b 00 48 8d 43 10 48 89 84 24 f0 00 00 00 74 05 e8 85 3e f2 ff 4c 8d ac 24 90 04 00 00 4c 89 ef e8 05 ba 02 00 4c 8d b4 24 b0 04 00 00 ba 01 00 00 00 4c 89 ee 4c 89 f7 e8 9d 5b ff ff 4c 8d ac 24 10 01 00 00 ba 09 00 00 00 4c 89 f6 4c 89 ef e8 85 5b ff ff 48 8b bc 24 b8 04 00 00 48 8d 43 10 48 89 84 24 b0 04 00 00 48 85 ff 74 05 e8 27 3e f2 ff 48 8b bc 24 98 04 00 00 48 8d 43 10 48 89 84 24 90 04 00 00 48 85 ff 74 05 e8 09 3e f2 ff 48 8d 43 10 49 8d }
		$seq2 = { 41 56 49 89 fe 41 55 41 89 cd 41 54 45 8d 60 01 55 53 44 89 c3 48 81 ec 98 06 00 00 41 39 cc 89 74 24 10 48 89 54 24 30 0f 84 ab 09 00 00 48 8d 84 24 80 00 00 00 41 8d 70 ff 48 8d ac 24 10 01 00 00 48 89 c7 48 89 44 24 48 e8 0f 89 f6 ff be 01 00 00 00 48 89 ef e8 02 51 f6 ff 4c 8d a4 24 e0 00 00 00 89 de 4c 89 e7 e8 f0 88 f6 ff 48 8d 84 24 b0 00 00 00 48 89 ea 4c 89 e6 48 89 c7 48 89 44 24 20 e8 55 8d f6 ff 48 8d 1d 4e a2 2f 00 49 8d 7c 24 08 4c 8d 7b 10 4c 89 bc 24 e0 00 00 00 e8 48 eb ea ff 48 8d 7d 08 4c 89 bc 24 10 01 00 00 e8 37 eb ea ff 48 8d 84 24 40 01 00 00 41 8d 75 ff 48 89 c7 48 89 44 24 38 e8 8e 88 f6 ff 48 8d 84 24 d0 01 00 00 be 01 00 00 00 48 89 c7 49 89 c7 48 89 44 24 50 e8 71 50 f6 ff 48 8d ac 24 a0 01 00 00 44 89 ee 48 89 ef e8 5e 88 f6 ff 48 8d 84 24 70 01 00 00 4c 89 fa 48 89 ee 48 89 c7 48 89 44 24 40 e8 c3 8c f6 ff 4c 8d 63 10 48 8d 7d 08 48 8d ac 24 00 02 00 00 4c 89 a4 24 a0 01 00 00 e8 b6 ea ea ff 4c 89 ff 4c 89 a4 24 d0 01 00 00 4c 8d a4 24 30 02 00 00 48 83 c7 08 e8 9a ea ea ff 4c 63 7c 24 10 49 8d 46 30 48 89 44 24 18 0f 1f 40 00 e8 b3 7c f6 ff 49 89 c5 e8 ab 75 f6 ff 4c 89 2c 24 4c 8b 6c 24 18 49 89 c1 48 8b 4c 24 20 48 8b 54 24 48 41 b8 01 00 00 00 48 8b 74 24 30 4c 89 ef e8 32 f9 f6 ff 4c 89 fe 48 89 ef e8 b7 4f f6 ff 4c 89 ea 48 89 ee 4c 89 e7 e8 09 d9 f6 ff 48 8b 4c 24 40 48 8b 54 24 38 4d 89 e1 48 8b 74 24 30 4c 89 2c 24 41 b8 01 00 00 00 4c 89 f7 e8 f5 f8 f6 ff 48 8b 94 24 50 02 00 00 48 8b 8c 24 40 02 00 00 41 89 c5 48 39 8c 24 48 02 00 00 48 8d 43 10 48 0f 46 8c 24 48 02 00 00 48 85 d2 48 89 84 24 30 02 00 00 74 10 48 89 d7 31 c0 f3 48 ab 48 89 d7 e8 40 4f f7 ff 48 8b 94 24 20 02 00 00 48 8b 8c 24 10 02 00 00 48 8d 43 10 48 39 8c 24 18 02 00 00 48 0f 46 8c 24 18 02 00 00 48 89 84 24 00 02 00 00 48 85 d2 74 10 48 89 d7 31 c0 f3 48 ab 48 89 d7 e8 fe 4e f7 ff 45 84 ed 0f 84 fd fe ff ff 83 7c 24 10 01 0f 84 bc 04 00 00 48 8d 84 24 e0 03 00 00 4c 8d ac 24 c0 05 00 00 48 89 44 24 10 48 8d 84 24 10 04 00 00 48 89 44 24 08 49 8d 45 08 }
		$seq3 = { 4c 8d bc 24 00 05 00 00 be 01 00 00 00 4c 89 ff e8 9b 4e f6 ff 4c 8d a4 24 30 05 00 00 4c 89 fa 4c 89 f6 4c 89 e7 e8 05 88 f6 ff 48 8d ac 24 60 05 00 00 48 8b 54 24 18 4c 89 e6 48 89 ef e8 5d d3 f6 ff 48 8d 84 24 90 05 00 00 4c 89 f1 4c 89 ea 48 89 ee 48 89 c7 48 89 44 24 28 e8 ef b9 ff ff 48 8b 74 24 28 49 8d 7e 60 e8 01 59 f6 ff 48 8b 94 24 b0 05 00 00 48 8b 8c 24 a0 05 00 00 48 8d 43 10 48 39 8c 24 a8 05 00 00 48 0f 46 8c 24 a8 05 00 00 48 89 84 24 90 05 00 00 48 85 d2 74 10 48 89 d7 31 c0 f3 48 ab 48 89 d7 e8 ff 4d f7 ff 48 8b 94 24 80 05 00 00 48 8b 8c 24 70 05 00 00 48 8d 43 10 48 39 8c 24 78 05 00 00 48 0f 46 8c 24 78 05 00 00 48 89 84 24 60 05 00 00 48 85 d2 74 10 48 89 d7 31 c0 f3 48 ab 48 89 d7 e8 bd 4d f7 ff 48 8b 94 24 50 05 00 00 48 8b 8c 24 40 05 00 00 48 8d 43 10 48 39 8c 24 48 05 00 00 48 0f 46 8c 24 48 05 00 00 48 89 84 24 30 05 00 00 }
		$seq4 = { 49 89 ff 41 56 49 89 f6 41 55 41 54 55 53 49 8d 9e c8 01 00 00 48 81 ec f8 05 00 00 48 8d bc 24 d0 00 00 00 e8 e5 52 00 00 48 8d bc 24 00 01 00 00 be 06 0e 5d 00 e8 33 99 ff ff 48 8d b4 24 00 01 00 00 48 8d bc 24 d0 00 00 00 48 89 da e8 bb eb ff ff 48 8b 84 24 00 01 00 00 48 8d b4 24 60 04 00 00 49 8d 9e c0 01 00 00 48 8d 78 e8 e8 9b 10 fd ff 48 8d bc 24 20 01 00 00 be 79 e3 5b 00 e8 e9 98 ff ff 48 8d b4 24 20 01 00 00 48 8d bc 24 d0 00 00 00 48 89 da e8 71 eb ff ff 48 8b 84 24 20 01 00 00 48 8d b4 24 60 04 00 00 48 8d 78 e8 e8 58 10 fd ff 48 8d 7c 24 20 4c 89 f6 e8 6b 9d ff ff 48 8d bc 24 40 01 00 00 be 14 e4 5b 00 e8 99 98 ff ff 48 8d 54 24 20 48 8d b4 24 40 01 00 00 48 8d bc 24 d0 00 00 00 e8 1f eb ff ff 48 8b 84 24 40 01 00 00 48 8d b4 24 60 04 00 00 48 8d 78 e8 e8 06 10 fd ff 48 8b 44 24 20 48 8d b4 24 60 04 00 00 48 8d 78 e8 e8 f0 0f fd ff 48 8d bc 24 60 01 00 00 be 1d e4 5b 00 e8 3e 98 ff ff 48 8d bc 24 c0 00 00 00 e8 41 22 fd ff 48 8d b4 24 c0 00 00 00 48 8d bc 24 60 04 00 00 e8 cc 0f fd ff 48 8d 8c 24 60 04 00 00 48 8d b4 24 60 01 00 00 48 8d bc 24 d0 00 00 00 ba 3f 26 5e 00 e8 fa ce 00 00 48 8d bc 24 60 04 00 00 e8 7d 19 fd ff 48 8d bc 24 c0 00 00 00 e8 70 19 fd ff 48 8b 84 24 60 01 00 00 48 8d b4 24 60 04 00 00 48 8d 78 e8 e8 67 0f fd ff 48 8d bc 24 80 01 00 00 be 90 e4 5b 00 e8 b5 97 ff ff 48 8d b4 24 80 01 00 00 48 8d bc 24 d0 00 00 00 ba 48 38 8a 00 e8 3b ea ff ff 48 8b 84 24 80 01 00 00 48 8d b4 24 60 04 00 00 48 8d 78 e8 e8 22 0f fd ff 48 8d 94 24 20 04 00 00 48 8d b4 24 00 04 00 00 4c 89 f7 48 c7 84 24 00 04 00 00 78 24 8a 00 48 c7 84 24 20 04 00 00 78 24 8a 00 e8 f2 9c ff ff 48 8d bc 24 a0 01 00 00 be 24 e4 5b 00 e8 40 97 ff ff 48 8d 94 24 00 04 00 00 48 8d b4 24 a0 01 00 00 48 8d bc 24 d0 00 00 00 e8 c3 e9 ff ff 48 8b 84 24 a0 01 00 00 48 8d b4 24 60 04 00 00 48 8d 78 e8 e8 aa 0e fd ff 48 8d bc 24 c0 01 00 00 be 2d e4 5b 00 e8 f8 96 ff ff 48 8d 94 24 20 04 00 00 48 8d b4 24 c0 01 00 00 48 8d bc 24 d0 00 00 00 e8 7b e9 ff ff 48 8b 84 24 c0 01 00 00 48 8d b4 24 60 04 00 00 48 8d ac 24 e0 03 00 00 48 8d 78 e8 e8 5a 0e fd ff c7 84 24 e0 03 00 00 00 00 00 00 48 89 ac 24 60 04 00 00 e8 e2 e4 fd ff 48 8d 94 24 60 04 00 00 48 8d bc 24 40 04 00 }
		$seq5 = { e8 bb e4 fd ff 48 8d bc 24 40 04 00 00 48 89 84 24 e0 01 00 00 e8 b6 e9 05 00 48 89 c3 48 89 84 24 e8 01 00 00 e8 96 1d fd ff 8b 40 08 48 83 c3 08 be 33 e4 5b 00 48 89 df 89 84 24 f0 01 00 00 e8 7b e9 fd ff 48 8b b4 24 00 04 00 00 48 89 df 48 8b 56 e8 e8 67 e6 fd ff 48 8d bc 24 e0 01 00 00 e8 5a d9 fd ff 48 83 bc 24 40 04 00 00 00 75 8f c7 84 24 e0 03 00 00 00 00 00 00 48 89 ac 24 60 04 00 00 e8 37 e4 fd ff 48 8d 94 24 60 04 00 00 48 8d bc 24 40 04 00 00 48 89 c6 }
		$seq6 = { 48 8d bc 24 40 04 00 00 48 89 84 24 00 02 00 00 e8 0e e9 05 00 48 89 c3 48 89 84 24 08 02 00 00 e8 ee 1c fd ff 8b 40 08 48 83 c3 08 be 3e e4 5b 00 48 89 df 89 84 24 10 02 00 00 e8 d3 e8 fd ff 48 8b b4 24 20 04 00 00 48 89 df 48 8b 56 e8 e8 bf e5 fd ff 48 8d bc 24 00 02 00 00 e8 b2 d8 fd ff 48 83 bc 24 40 04 00 00 00 75 8f 48 8b 84 24 20 04 00 00 48 8d b4 24 60 04 00 00 48 8d 78 e8 e8 ee 0c fd ff 48 8b 84 24 00 04 00 00 48 8d b4 24 60 04 00 00 48 8d 78 e8 e8 d5 0c fd ff e8 10 c9 fe ff 84 c0 0f 84 48 02 00 00 48 8d 74 24 1d c6 04 24 00 48 89 ef e8 07 97 00 00 48 8b bc 24 e0 03 00 00 48 8d b4 24 00 04 00 00 48 c7 84 24 00 04 00 00 00 00 00 00 48 c7 84 24 08 04 00 00 00 00 00 00 48 c7 84 24 10 04 00 00 00 00 00 00 e8 3e db fe ff 84 c0 0f 84 c9 00 00 00 48 8b 84 24 08 04 00 00 48 2b 84 24 00 04 00 00 48 c1 f8 03 }
		$seq7 = { 48 83 bc 24 40 04 00 00 00 75 95 48 8d bc 24 00 04 00 00 e8 b0 9e fe ff 48 8b bc 24 e8 03 00 00 48 85 ff 74 05 e8 0e 66 ff ff 48 8d bc 24 f0 00 00 00 e8 81 4d 00 00 48 8d b4 24 f0 00 00 00 4c 89 f7 e8 81 f0 ff ff 48 8d bc 24 40 04 00 00 be 02 e5 5b 00 e8 bf 93 ff ff 48 8d 94 24 f0 00 00 00 48 8d b4 24 40 04 00 00 48 8d bc 24 d0 00 00 00 e8 f2 d1 00 00 48 8b 84 24 40 04 00 00 48 8d b4 24 60 04 00 00 48 8d 78 e8 e8 29 0b fd ff 48 8d bc 24 60 04 00 00 be 18 00 00 00 e8 07 0e fd ff 48 8d bc 24 70 04 00 00 48 8d b4 24 d0 00 00 00 ba 01 00 00 00 e8 5d ad 00 00 48 8d b4 24 78 04 00 00 48 8d bc 24 b0 00 00 00 e8 38 0c fd ff 48 8d 94 24 b0 00 00 00 4c 89 f6 4c 89 ff e8 e5 c6 ff ff 48 8b 84 24 b0 00 00 00 48 8d b4 24 40 04 00 00 48 8d 78 e8 e8 bc 0a fd ff 48 8d bc 24 60 04 00 00 e8 cf 16 fd ff 48 8d bc 24 f0 00 00 00 e8 52 4d 00 00 48 8d bc 24 d0 00 00 00 e8 45 4d 00 00 48 81 c4 f8 05 00 00 4c 89 f8 5b 5d 41 5c 41 5d }
		$seq8 = { 4c 8d a4 24 64 05 00 00 66 0f 1f 44 00 00 e8 23 de fd ff 48 8d 94 24 20 04 00 00 48 8d bc 24 a0 03 00 00 48 89 c6 e8 eb df fd ff 48 8b 9c 24 a8 03 00 00 be f7 e4 5b 00 48 8d 7b 08 e8 f5 e2 fd ff 48 8d 7b 70 4c 89 e6 e8 d9 0b fd ff 48 8d bc 24 a0 03 00 00 e8 dc d2 fd ff 48 83 bc 24 20 04 00 00 00 75 a9 48 8d 84 24 c0 03 00 00 be 6c e4 5b 00 48 89 c7 48 89 44 24 08 e8 77 8f ff ff 48 8b 5c 24 08 48 8d 94 24 60 04 00 00 48 8d bc 24 d0 00 00 00 48 89 de e8 7a c8 00 00 48 8b 84 24 c0 03 00 00 48 8d b4 24 40 04 00 00 48 8d 78 e8 e8 e1 06 fd ff 48 8d b4 24 23 05 00 00 48 8d bc 24 a0 00 00 00 48 89 da e8 29 0d fd ff 48 8d 94 24 a0 03 00 00 48 8d b4 24 60 04 00 00 48 8d bc 24 90 00 00 00 e8 0c 0d fd ff 48 8d bc 24 90 00 00 00 be 90 d6 5c 00 e8 ba 16 fd ff 48 8b 10 48 89 94 24 20 04 00 00 48 c7 00 78 24 8a 00 48 8b 94 24 20 04 00 00 48 8b 84 24 a0 00 00 00 48 8b 4a e8 48 89 ce 48 03 70 e8 48 3b 72 f0 76 0a 48 3b 70 f0 0f 86 b7 08 00 00 48 8d b4 24 a0 00 00 00 48 8d bc 24 20 04 00 00 e8 08 0c fd ff 48 8b 10 be 8d e4 5b 00 48 89 ef 48 89 94 24 40 04 00 00 48 c7 00 78 24 8a 00 e8 89 8e ff ff 48 8d 94 24 40 04 00 00 48 8d bc 24 d0 00 00 00 48 89 ee e8 11 e1 ff ff 48 8b 84 24 e0 03 00 00 48 8d b4 24 00 04 00 00 48 8d 78 e8 e8 f8 05 fd ff 48 8b 84 24 40 04 00 00 48 8d b4 24 00 04 00 00 48 8d 78 e8 e8 df 05 fd ff 48 8b 84 24 20 04 00 00 48 8d b4 24 40 04 00 00 48 8d 78 e8 e8 c6 05 fd ff 48 8b 84 24 90 00 00 00 48 8d b4 24 40 04 00 00 48 8d 78 e8 e8 ad 05 fd ff 48 8b 84 24 a0 00 00 00 48 8d b4 24 40 04 00 00 48 8d 78 e8 e8 94 05 fd ff 48 8d bc 24 00 04 00 00 be 4c e4 5b 00 e8 e2 8d ff ff 48 8d 94 24 e2 04 00 00 48 8d b4 24 00 04 00 00 48 8d bc 24 d0 00 00 00 e8 e5 c6 00 00 48 8b 84 24 00 04 00 00 48 8d b4 24 40 04 00 00 48 8d 78 e8 e8 4c 05 fd ff 48 8d bc 24 20 04 00 00 be 98 e4 5b 00 e8 9a 8d ff ff 48 8d 94 24 64 05 00 00 48 8d b4 24 20 04 00 00 48 8d bc 24 d0 00 00 00 e8 9d c6 00 00 48 8b 84 24 20 04 00 00 48 8d b4 24 40 04 00 00 48 8d 78 e8 }

	condition:
		uint32( 0 ) == 0x464c457f and filesize > 300KB and 7 of ( $s* )
}

