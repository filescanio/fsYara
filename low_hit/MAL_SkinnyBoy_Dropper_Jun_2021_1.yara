rule MAL_SkinnyBoy_Dropper_Jun_2021_1 : hardened
{
	meta:
		description = "Detect SkinnyBoy Dropper"
		author = "Arkbird_SOLG"
		reference = "https://cluster25.io/wp-content/uploads/2021/05/2021-05_FancyBear.pdf"
		date = "2021-05-01"
		hash1 = "12331809c3e03d84498f428a37a28cf6cbb1dafe98c36463593ad12898c588c9"
		tlp = "White"
		adversary = "APT28"

	strings:
		$s1 = { 55 8b ec b8 48 12 00 00 e8 a3 52 00 00 a1 00 d0 40 00 33 c5 89 45 fc 56 57 68 08 02 00 00 8d 85 cc ed ff ff 50 51 ff 15 2c 80 40 00 6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 8d 85 cc ed ff ff 50 c7 85 b8 ed ff ff 00 00 00 00 ff 15 18 80 40 00 8b f0 ff 15 1c 80 40 00 8b f8 83 fe ff 74 12 6a 00 56 ff 15 58 80 40 00 56 8b f8 ff 15 20 80 40 00 8d 85 c8 ed ff ff 50 8d 95 b8 ed ff ff 8d 8d cc ed ff ff 89 bd c8 ed ff ff e8 bc fd ff ff 8b bd b8 ed ff ff b8 4d 5a 00 00 83 c4 04 66 39 07 74 1b 68 c1 00 00 00 ff 15 34 80 40 00 5f 5e 8b 4d fc 33 cd e8 fe 08 00 00 8b e5 }
		$s2 = { 8b 47 3c 81 3c 07 50 45 00 00 75 d9 8b 47 1c 8b b5 c8 ed ff ff 8b 4f 20 2b f0 85 c9 74 04 8b f1 2b f0 53 56 6a 08 ff 15 0c 80 40 00 50 ff 15 08 80 40 00 8b 4f 1c 56 03 cf 8b d8 51 53 89 9d c4 ed ff ff e8 96 5d 00 00 68 08 02 00 00 8d 85 f4 f9 ff ff 6a 00 50 e8 33 25 00 00 83 c4 18 8d 85 f4 f9 ff ff 50 6a 00 6a 00 68 1c 80 00 00 6a 00 ff 15 30 81 40 00 b8 18 00 00 00 68 ee 00 00 00 66 89 85 0c fc ff ff 8d 85 0e fc ff ff 6a 00 50 c7 85 fc fb ff ff 00 00 3f 00 c7 85 00 fc ff ff 47 00 5b 00 c7 85 04 fc ff ff 09 00 19 00 c7 85 08 fc ff ff 08 00 0d 00 e8 d1 24 00 00 f3 0f 7e 05 c4 bd 40 00 a1 d4 bd 40 00 68 ec 00 00 00 89 85 0c ff ff ff 66 0f d6 85 fc fe ff ff f3 0f 7e 05 cc bd 40 00 8d 85 10 ff ff ff 6a 00 50 66 0f d6 85 04 ff ff ff e8 93 24 00 00 83 c4 18 33 }
		$s3 = { 0f b7 8c 05 fc fe ff ff 66 31 8c 05 fc fb ff ff 0f b7 8c 05 fe fe ff ff 66 31 8c 05 fe fb ff ff 0f b7 8c 05 00 ff ff ff 66 31 8c 05 00 fc ff ff 0f b7 8c 05 02 ff ff ff 66 31 8c 05 02 fc ff ff 83 c0 08 3d 00 01 00 00 72 b6 8d 85 f4 f9 ff ff 50 ff 15 38 81 40 00 8d 85 fc fb ff ff 50 8d 85 f4 f9 ff ff 50 ff 15 40 80 40 00 6a 00 8d 85 f4 f9 ff ff 50 ff 15 28 80 40 00 68 d8 00 00 00 8d 85 24 fe ff ff 6a 00 50 c7 85 fc fd ff ff 1f 00 33 00 c7 85 00 fe ff ff 58 00 4e 00 c7 85 04 fe ff ff 5d 00 1b 00 c7 85 08 fe ff ff 59 00 27 00 c7 85 0c fe ff ff 70 00 2d 00 c7 85 10 fe ff ff 16 00 13 00 c7 85 14 fe ff ff 03 00 1c 00 c7 85 18 fe ff ff 0d 00 2a 00 c7 85 1c fe ff ff 07 00 51 00 c7 85 20 fe ff ff 08 00 13 00 e8 8f 23 00 00 f3 0f 7e 05 d8 bd 40 00 66 a1 00 be 40 00 66 0f d6 85 fc fe ff ff f3 0f 7e 05 e0 bd 40 00 66 0f d6 85 04 ff ff ff f3 0f 7e 05 e8 bd 40 00 66 0f d6 85 0c ff ff ff f3 0f 7e 05 f0 bd 40 00 68 d6 00 00 00 66 89 85 24 ff ff ff 66 0f d6 85 14 ff ff ff f3 0f 7e 05 f8 bd 40 00 8d 85 26 ff ff ff 6a 00 50 66 0f d6 85 1c ff ff ff e8 1f 23 00 00 83 c4 18 33 }
		$s4 = { 0f b7 84 0d fc fe ff ff 66 31 84 0d fc fc ff ff 0f b7 84 0d fe fe ff ff 66 31 84 0d fe fc ff ff 0f b7 84 0d 00 ff ff ff 66 31 84 0d 00 fd ff ff 0f b7 84 0d 02 ff ff ff 66 31 84 0d 02 fd ff ff 83 c1 08 81 f9 00 01 00 00 72 b5 8d 85 f4 f9 ff ff 50 ff 15 38 81 40 00 8d 85 fc fc ff ff 50 8d 85 f4 f9 ff ff 50 ff 15 40 80 40 00 6a 00 6a 00 8d 85 c0 ed ff ff 50 6a 00 6a 01 56 53 8b 1d 00 80 40 00 c7 85 c0 ed ff ff 00 00 00 00 ff d3 ff b5 c0 ed ff ff 6a 08 ff 15 0c 80 40 00 50 ff 15 08 80 40 00 6a 00 6a 00 8d 8d c0 ed ff ff 51 50 6a 01 56 ff b5 c4 ed ff ff 89 85 bc ed ff ff ff d3 8b 85 c0 ed ff ff 6a 00 68 80 00 00 00 6a 04 6a 00 6a 02 89 85 b8 ed ff ff 68 00 00 00 40 8d 85 f4 f9 ff ff 50 ff 15 18 80 40 00 8b f0 ff 15 1c 80 40 00 8b 1d 38 80 40 00 83 fe ff 74 55 3d b7 00 00 00 75 0b 6a 00 6a 00 6a 00 56 ff }
		$s5 = { 55 8b ec 83 ec 0c a1 00 d0 40 00 33 c5 89 45 fc 53 8b 5d 08 56 57 6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 51 89 55 f4 ff 15 18 80 40 00 8b f0 ff 15 1c 80 40 00 8b f8 83 fe ff 74 67 83 ff 02 74 62 6a 00 56 ff 15 58 80 40 00 89 03 85 c0 74 47 c7 45 f8 00 00 00 00 ff 15 0c 80 40 00 ff 33 6a 08 50 ff 15 08 80 40 00 8b 4d f4 6a 00 89 01 8d 4d f8 51 ff 33 50 56 ff 15 14 80 40 00 56 ff 15 20 80 40 00 8b c7 5f 5e 5b 8b 4d fc 33 cd e8 d4 0a 00 00 8b e5 }
		$s6 = { 54 56 71 51 41 41 4d 41 41 41 41 45 41 41 41 41 2f 2f }

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 40KB and 5 of ( $s* )
}

