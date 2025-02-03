rule Ran_ELF_EXX_Nov_2020_1 : hardened
{
	meta:
		description = "Detect EXX variant ELF ransomware"
		author = "Arkbird_SOLG"
		reference = "Internal Research"
		date = "2020-12-09"
		level = "experimental"
		hash1 = "cb408d45762a628872fa782109e8fcfc3a5bf456074b007de21e9331bb3c5849"

	strings:
		$dbg1 = { 55 6e 65 78 70 65 63 74 65 64 20 65 72 72 6f 72 2c 20 72 65 74 75 72 6e 20 63 6f 64 65 20 3d 20 25 30 38 58 0a }
		$dbg2 = { 47 72 65 65 74 69 6e 67 73 20 [3-10] 21 }
		$dbg3 = { 63 79 63 6c 65 73 3d 25 6c 75 20 72 61 74 69 6f 3d 25 6c 75 20 6d 69 6c 6c 69 73 65 63 73 3d 25 6c 75 20 73 65 63 73 3d 25 6c 75 20 68 61 72 64 66 61 69 6c 3d 25 64 20 61 3d 25 6c 75 20 62 3d 25 6c 75 0a }
		$dbg4 = { 53 48 41 2d 25 64 20 74 65 73 74 20 23 25 64 3a }
		$lib1 = {70 74 68 72 65 61 64 5f 6d 75 74 65 78 5f 75 6e 6c 6f 63 6b 40 40 47 4c 49 42 43 5f 32 2e 32 2e 35}
		$lib2 = {70 74 68 72 65 61 64 5f 6d 75 74 65 78 5f 6c 6f 63 6b 40 40 47 4c 49 42 43 5f 32 2e 32 2e 35}
		$lib3 = {6d 62 65 64 74 6c 73 5f 72 73 61 5f 69 6d 70 6f 72 74}
		$lib4 = {6d 62 65 64 74 6c 73 5f 72 73 61 5f 65 78 70 6f 72 74}
		$lib5 = {6d 62 65 64 74 6c 73 5f 6f 69 64 5f 67 65 74 5f 65 78 74 65 6e 64 65 64 5f 6b 65 79 5f 75 73 61 67 65}
		$lib6 = {6d 62 65 64 74 6c 73 5f 73 68 61 32 35 36 5f 70 72 6f 63 65 73 73}
		$seq1 = { 48 83 ec 20 89 7d ec 48 89 75 e0 b8 00 00 00 00 e8 77 00 00 00 48 8d 45 f0 b9 00 00 00 00 48 8d 15 b5 ff ff ff be 00 00 00 00 48 89 c7 e8 d6 fb ff ff c7 45 fc 01 00 00 00 eb }
		$seq2 = { 00 00 00 00 e8 b2 fe ff ff 48 8b 45 e8 48 89 c7 e8 92 ed ff ff 48 83 c0 01 48 89 c7 e8 c6 ee ff ff 48 89 45 f8 48 83 7d f8 00 74 3a 48 8b 55 e8 48 8b 45 f8 48 89 d6 48 89 c7 e8 f8 ec ff ff 48 8b 45 f8 48 89 c7 e8 12 fd ff ff 48 8b 45 f8 48 89 c7 e8 90 ec ff ff b8 00 00 00 00 e8 95 fc ff ff }
		$seq3 = { e5 41 55 41 54 53 48 81 ec 18 18 00 00 c7 45 dc 00 00 00 00 48 c7 45 d0 00 00 00 00 bf 00 00 00 00 e8 13 fd ff ff 89 c7 e8 7c fc ff ff e8 d7 fd ff ff 41 89 c5 e8 cf fd ff ff 41 89 c4 e8 c7 fd ff ff 89 c3 e8 c0 fd ff ff 89 c2 48 8d 85 d0 e7 ff ff 4d 89 e9 4d 89 e0 48 89 d9 48 8d 35 bf 0a 02 00 48 89 }

	condition:
		uint16( 0 ) == 0x457f and filesize > 80KB and 3 of ( $dbg* ) and 4 of ( $lib* ) and 2 of ( $seq* )
}

