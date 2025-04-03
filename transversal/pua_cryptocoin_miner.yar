rule CoinHive_Javascript_MoneroMiner : HIGHVOL hardened limited
{
	meta:
		description = "Detects CoinHive - JavaScript Crypto Miner"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 50
		reference = "https://coinhive.com/documentation/miner"
		date = "2018-01-04"
		id = "4f40c342-fcdc-5c73-a3cf-7b2ed438eaaf"

	strings:
		$s2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 43 6f 69 6e 48 69 76 65 2e 43 4f 4e 46 49 47 2e 52 45 51 55 49 52 45 53 5f 41 55 54 48 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		filesize < 65KB and 1 of them
}

rule PUA_CryptoMiner_Jan19_1 : hardened limited
{
	meta:
		description = "Detects Crypto Miner strings"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2019-01-31"
		score = 80
		hash1 = "ede858683267c61e710e367993f5e589fcb4b4b57b09d023a67ea63084c54a05"
		id = "aebfdce9-c2dd-5f24-aa25-071e1a961239"

	strings:
		$s1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 53 74 72 61 74 75 6d 20 6e 6f 74 69 66 79 3a 20 69 6e 76 61 6c 69 64 20 4d 65 72 6b 6c 65 20 62 72 61 6e 63 68 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 2d 74 2c 20 2d 2d 74 68 72 65 61 64 73 3d 4e 20 20 20 20 20 20 20 6e 75 6d 62 65 72 20 6f 66 20 6d 69 6e 65 72 20 74 68 72 65 61 64 73 20 28 64 65 66 61 75 6c 74 3a 20 6e 75 6d 62 65 72 20 6f 66 20 70 72 6f 63 65 73 73 6f 72 73 29 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s3 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 63 70 75 6d 69 6e 65 72 2f}
		$s4 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 68 61 73 68 20 3e 20 74 61 72 67 65 74 20 28 66 61 6c 73 65 20 70 6f 73 69 74 69 76 65 29 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s5 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 74 68 72 65 61 64 20 25 64 3a 20 25 6c 75 20 68 61 73 68 65 73 2c 20 25 73 20 6b 68 61 73 68 2f 73 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		filesize < 1000KB and 1 of them
}

rule PUA_Crypto_Mining_CommandLine_Indicators_Oct21 : SCRIPT hardened
{
	meta:
		description = "Detects command line parameters often used by crypto mining software"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.poolwatch.io/coin/monero"
		date = "2021-10-24"
		score = 65
		id = "afe5a63a-08c3-5cb7-b4b1-b996068124b7"

	strings:
		$s01 = {20 2d 2d 63 70 75 2d 70 72 69 6f 72 69 74 79 3d}
		$s02 = {2d 2d 64 6f 6e 61 74 65 2d 6c 65 76 65 6c 3d 30}
		$s03 = {20 2d 6f 20 70 6f 6f 6c 2e}
		$s04 = {20 2d 6f 20 73 74 72 61 74 75 6d 2b 74 63 70 3a 2f 2f}
		$s05 = {20 2d 2d 6e 69 63 65 68 61 73 68}
		$s06 = {20 2d 2d 61 6c 67 6f 3d 72 78 2f 30 20}
		$se1 = {4c 53 31 6b 62 32 35 68 64 47 55 74 62 47 56 32 5a 57 77 39}
		$se2 = {30 74 5a 47 39 75 59 58 52 6c 4c 57 78 6c 64 6d 56 73 50}
		$se3 = {74 4c 57 52 76 62 6d 46 30 5a 53 31 73 5a 58 5a 6c 62 44}
		$se4 = {63 33 52 79 59 58 52 31 62 53 74 30 59 33 41 36 4c 79}
		$se5 = {4e 30 63 6d 46 30 64 57 30 72 64 47 4e 77 4f 69 38 76}
		$se6 = {7a 64 48 4a 68 64 48 56 74 4b 33 52 6a 63 44 6f 76 4c}
		$se7 = {63 33 52 79 59 58 52 31 62 53 74 31 5a 48 41 36 4c 79}
		$se8 = {4e 30 63 6d 46 30 64 57 30 72 64 57 52 77 4f 69 38 76}
		$se9 = {7a 64 48 4a 68 64 48 56 74 4b 33 56 6b 63 44 6f 76 4c}

	condition:
		filesize < 5000KB and 1 of them
}

