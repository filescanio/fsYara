rule RAN_ELF_HelloKitty_Aug_2021_1 : hardened
{
	meta:
		description = "Detect HelloKitty ransomware"
		author = "Arkbird_SOLG"
		reference = "Internal Research"
		date = "2021-08-14"
		hash1 = "ca607e431062ee49a21d69d722750e5edbd8ffabcb54fa92b231814101756041"
		hash2 = "b4f90cff1e3900a3906c3b74f307498760462d719c31d008fc01937f5400fb85"
		tlp = "White"
		adversary = "RAAS"

	strings:
		$seq1 = { 48 8d 74 24 08 bf d0 4a 61 00 48 c7 44 24 10 00 00 00 00 48 c7 44 24 08 01 00 00 00 e8 [2] ff ff 48 8b 05 ?? 13 21 00 48 8b 3d ?? 14 21 00 48 89 e9 ba ?? 0c 41 00 be 01 00 00 00 48 8b 04 18 44 8b 00 31 c0 e8 ?? e2 ff ff 48 8b 3d ?? 14 21 00 e8 [2] ff ff bf d0 4a 61 00 e8 [2] ff ff 48 8b 05 ?? 13 21 00 48 8b 3d ?? 12 21 00 48 89 e9 ba ?? 0c 41 00 be 01 00 00 00 48 8b 04 18 44 8b 00 31 c0 e8 ?? e2 ff ff 48 8b 05 [2] 21 00 b9 ?? 0c 41 00 ba 80 00 00 00 be 01 00 00 00 4c 89 e7 48 8b 04 18 44 8b 00 31 c0 e8 ?? e5 ff ff 4c 89 e7 e8 cd 10 00 00 48 85 c0 49 89 c7 0f 84 9b 00 00 00 48 83 3d ?? 13 21 00 00 74 60 48 8d 74 24 08 bf d0 4a 61 00 48 c7 44 24 10 00 00 00 00 48 c7 44 24 08 01 00 00 00 e8 ?? e3 ff ff 48 8b 05 ?? 12 21 00 48 8b 3d ?? 13 21 00 48 89 e9 ba [2] 41 00 be 01 00 00 00 48 8b 04 18 44 8b 00 31 c0 e8 ?? e1 ff ff 48 8b 3d ?? 13 21 00 e8 ?? e6 ff ff bf d0 4a 61 00 e8 [2] ff ff 48 8b 05 ?? 12 21 00 48 8b 3d [2] 21 00 48 89 e9 ba [2] 41 00 be 01 00 00 00 48 8b 04 18 44 8b 00 31 c0 e8 ?? e1 ff ff }
		$seq2 = { 31 c0 b9 40 00 00 00 48 89 ef f3 ab be ?? 0d 41 00 48 89 df e8 [2] ff ff 48 85 c0 49 89 c5 0f 84 4c 01 00 00 48 89 c2 48 89 de 48 89 ef 48 29 da e8 71 07 00 00 be 3a 00 00 00 48 89 ef e8 [2] ff ff 48 8d 78 01 e8 [2] ff ff 85 c0 41 89 c7 0f 84 04 01 00 00 bf 10 00 00 00 e8 ?? dd ff ff 4c 89 ef 44 89 38 49 89 c6 48 89 04 24 e8 3d f5 ff ff 48 83 3d ?? 0e 21 00 00 49 89 46 08 74 6f 48 8d 74 24 08 bf d0 4a 61 00 48 c7 44 24 10 00 00 00 00 48 c7 44 24 08 01 00 00 00 e8 [2] ff ff 48 8b 04 24 48 8b 0d ?? 0d 21 00 ba ?? 0d 41 00 48 2b 0d ?? 0d 21 00 48 8b 3d ?? 0e 21 00 be 01 00 00 00 4c 8b 48 08 44 8b 00 31 c0 48 c1 f9 03 48 ff c1 e8 ?? dc ff ff 48 8b 3d [2] 21 00 e8 [2] ff ff bf d0 4a 61 00 e8 [2] ff ff 48 8b 04 24 48 8b 0d [2] 21 00 be 01 00 00 00 48 2b 0d [2] 21 00 48 8b 3d ?? 0c 21 00 ba ?? 0d 41 00 4c 8b 48 08 44 8b 00 31 c0 48 c1 f9 03 48 ff c1 e8 [2] ff ff 48 8b 35 [2] 21 00 48 3b 35 [2] 21 00 74 16 48 85 f6 74 07 48 8b 04 24 48 89 06 48 83 05 [2] 21 00 08 eb 0d 48 89 e2 bf e0 49 61 00 e8 af 02 00 00 48 8d 7b 01 be ?? 0d 41 00 e8 ?? dd ff ff 48 89 c3 e9 86 fe ff ff 4d 85 e4 74 08 4c 89 e7 e8 [2] ff ff 48 83 3d ?? 0d 21 00 00 74 61 48 8d 74 24 08 bf d0 4a 61 00 48 c7 44 24 10 00 00 00 00 48 c7 44 24 08 01 00 00 00 e8 [2] ff ff 48 8b 0d ?? 0c 21 00 48 2b 0d ?? 0c 21 00 ba ?? 0d 41 00 48 8b 3d ?? 0d 21 00 be 01 00 00 00 31 c0 48 c1 f9 03 e8 ?? db ff ff 48 8b 3d [2] 21 00 e8 [2] ff ff bf d0 4a 61 00 e8 [2] ff ff 48 8b 0d ?? 0c 21 00 48 2b 0d [2] 21 00 31 c0 48 8b 3d ?? 0b 21 00 ba ?? 0d 41 00 be 01 00 00 00 48 c1 f9 03 e8 [2] ff ff 48 8b 84 24 18 01 00 00 64 48 33 04 25 28 00 00 }
		$seq3 = { 48 8d b4 24 90 00 00 00 bf d0 4a 61 00 48 c7 84 24 98 00 00 00 00 00 00 00 48 c7 84 24 90 00 00 00 01 00 00 00 e8 [2] ff ff e8 ?? 22 00 00 89 44 24 08 8b 05 [2] 21 00 89 d9 44 8b 0d [2] 21 00 44 8b 05 [2] 21 00 ba ?? 0e 41 00 48 8b 3d [2] 21 00 be 01 00 00 00 89 04 24 31 c0 e8 ?? f8 ff ff 48 8b 3d [2] 21 00 e8 [2] ff ff bf d0 4a 61 00 e8 [2] ff ff 31 f6 ba 0a 00 00 00 bf 40 4a 61 00 e8 ?? fa ff ff ba 0a 00 00 00 31 f6 bf 20 4a 61 00 e8 ?? fa ff ff be 01 00 00 00 bf 11 00 00 00 e8 [2] ff ff be 01 00 00 00 bf 14 00 00 00 e8 [2] ff ff be 01 00 00 00 bf 16 00 00 00 e8 [2] ff ff be 01 00 00 00 bf 15 00 00 00 e8 [2] ff ff 83 3d ?? 28 21 00 00 }

	condition:
		uint32( 0 ) == 0x464C457F and filesize > 20KB and all of ( $seq* )
}

