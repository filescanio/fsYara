rule Ran_Loader_Hades_Dec_2020_1 : hardened
{
	meta:
		description = "Detect the loader used by Hades ransomware for load the final implant in memory"
		author = "Arkbird_SOLG"
		reference = "Internal Research"
		date = "2020-12-27"
		hash1 = "0dfcf4d5f66310de87c2e422d7804e66279fe3e3cd6a27723225aecf214e9b00"
		hash2 = "ea310cc4fd4e8669e014ff417286da5edf2d3bef20abfb0a4f4951afe260d33d"
		level = "Experimental"

	strings:
		$seq1 = { 48 83 ec 58 8b 0d 9e aa 1c 00 ba 01 14 00 00 ff 15 93 9a 1c 00 48 85 c0 74 07 33 c0 e9 c1 3b 00 00 48 8b 05 58 99 1c 00 48 89 44 24 30 c7 44 24 3c 2c 01 00 00 c7 44 24 38 01 00 00 00 33 c9 ff 15 cb 99 1c 00 48 89 05 74 aa 1c 00 48 8b 05 6d aa 1c 00 48 63 48 3c 48 8b 05 62 aa 1c 00 48 03 c1 48 89 05 88 aa 1c 00 48 8d 44 24 3c 48 89 44 24 28 48 8d 05 a7 aa 1c 00 48 89 44 24 20 4c 8d 4c 24 38 45 33 c0 48 8d 15 53 aa 1c 00 48 8b 0d e4 ac 1c 00 ff 54 24 30 48 85 c0 74 05 e8 5e ff ff ff 48 8d 05 2d 3d 00 00 48 89 05 38 aa 1c 00 48 8b 05 31 aa 1c 00 }
		$seq2 = { 89 54 24 10 89 4c 24 08 48 83 ec 18 8b 44 24 20 89 04 24 8b 44 24 28 89 44 24 04 8b 44 24 04 39 04 24 73 0f c7 44 24 20 04 00 00 00 8b 04 24 eb 0e eb 0c c7 44 24 20 35 00 00 00 8b 44 24 04 48 83 c4 18 }
		$seq3 = { 48 8b 05 c1 ?? 1c 00 48 89 05 32 ?? 1c 00 }
		$s1 = {31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 5c 00 7b 00 61 00 61 00 35 00 62 00 36 00 61 00 38 00 30 00 2d 00 62 00 38 00 33 00 34 00 2d 00 31 00 31 00 64 00 30 00 2d 00 39 00 33 00 32 00 66 00 2d 00 30 00 30 00 61 00 30 00 63 00 39 00 30 00 64 00 63 00 61 00 61 00 39 00 7d 00}
		$s2 = {5f 00 56 00 45 00 52 00 53 00 49 00 4f 00 4e 00 5f 00 49 00 4e 00 46 00 4f 00}
		$s3 = {56 6b 4b 65 79 53 63 61 6e 57}
		$s4 = { 53 43 61 4d 69 72 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 300KB and 2 of ( $seq* ) and 3 of ( $s* )
}

