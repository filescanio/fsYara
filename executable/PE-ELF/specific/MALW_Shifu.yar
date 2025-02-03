rule Shifu_Banking_Trojan_0 : banking hardened
{
	meta:
		description = "Detects Shifu Banking Trojan"
		author = "Florian Roth"
		reference = "https://securityintelligence.com/shifu-masterful-new-banking-trojan-is-attacking-14-japanese-banks/"
		date = "2015-09-01"
		hash1 = "4ff1ebea2096f318a2252ebe1726bcf3bbc295da9204b6c720b5bbf14de14bb2"
		hash2 = "4881c7d89c2b5e934d4741a653fbdaf87cc5e7571b68c723504069d519d8a737"

	strings:
		$x1 = {63 3a 5c 6f 69 6c 5c 66 65 65 74 5c 53 65 76 65 6e 5c 53 65 6e 64 5c 47 61 74 68 65 72 5c 44 69 76 69 64 65 72 61 69 6c 2e 70 64 62}
		$s1 = {6c 00 69 00 73 00 74 00 65 00 6e 00 20 00 61 00 62 00 6f 00 76 00 65 00}
		$s2 = {66 00 61 00 6d 00 69 00 6c 00 79 00 63 00 6f 00 75 00 6c 00 64 00 20 00 63 00 6f 00 73 00 74 00}
		$s3 = {53 65 74 53 79 73 74 65 6d 54 69 6d 65 41 64 6a 75 73 74 6d 65 6e 74}
		$s4 = {50 65 65 6b 4e 61 6d 65 64 50 69 70 65}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1000KB and ( $x1 or all of ( $s* ) )
}

rule SHIFU_Banking_Trojan_1 : banking hardened
{
	meta:
		description = "Detects SHIFU Banking Trojan"
		author = "Florian Roth"
		reference = "http://goo.gl/52n8WE"
		date = "2015-10-31"
		score = 70
		hash1 = "0066d1c8053ff8b0c07418c7f8d20e5cd64007bb850944269f611febd0c1afe0"
		hash2 = "3956d32a870d81be34cafc867769b2a2f55a96360070f1cb3d9addc2918357d5"
		hash3 = "3fde1b2b50fcb36a695f1e6bc577cd930c2343066d98982cf982393e55bfce0d"
		hash4 = "457ad4a4d4e675fe09f63873ca3364434dc872dde7d9b64ce7db919eaff47485"
		hash5 = "51edba913e8b83d1388b1be975957e439015289d51d3d5774d501551f220df6f"
		hash6 = "6611a2b79a3acf0003b1197aa5bfe488a33db69b663c79c6c5b023e86818d38b"
		hash7 = "72e239924faebf8209f8e3d093f264f778a55efb56b619f26cea73b1c4feb7a4"
		hash8 = "7a29cb641b9ac33d1bb405d364bc6e9c7ce3e218a8ff295b75ca0922cf418290"
		hash9 = "92fe4f9a87c796e993820d1bda8040aced36e316de67c9c0c5fc71aadc41e0f8"
		hash10 = "93ecb6bd7c76e1b66f8c176418e73e274e2c705986d4ac9ede9d25db4091ab05"
		hash11 = "a0b7fac69a4eb32953c16597da753b15060f6eba452d150109ff8aabc2c56123"
		hash12 = "a8b6e798116ce0b268e2c9afac61536b8722e86b958bd2ee95c6ecdec86130c9"
		hash13 = "d6244c1177b679b3d67f6cec34fe0ae87fba21998d4f5024d8eeaf15ca242503"
		hash14 = "dcc9c38e695ffd121e793c91ca611a4025a116321443297f710a47ce06afb36d"

	strings:
		$x1 = {5c 47 61 74 68 65 72 5c 44 69 76 69 64 65 72 61 69 6c 2e 70 64 62}
		$s0 = {5c 70 61 79 6c 6f 61 64 5c 70 61 79 6c 6f 61 64 2e 78 38 36 2e 70 64 62}
		$s1 = {55 00 53 00 45 00 52 00 5f 00 50 00 52 00 49 00 56 00 5f 00 47 00 55 00 45 00 53 00 54 00}
		$s2 = {55 00 53 00 45 00 52 00 5f 00 50 00 52 00 49 00 56 00 5f 00 41 00 44 00 4d 00 49 00 4e 00}
		$s3 = {55 00 53 00 45 00 52 00 5f 00 50 00 52 00 49 00 56 00 5f 00 55 00 53 00 45 00 52 00}
		$s4 = {50 50 53 57 56 50 50}
		$s5 = {57 69 6e 53 43 61 72 64 2e 64 6c 6c}

	condition:
		uint16( 0 ) == 0x5a4d and ( $x1 or 5 of ( $s* ) )
}

rule Shifu : banking hardened
{
	meta:
		reference = "https://blogs.mcafee.com/mcafee-labs/japanese-banking-trojan-shifu-combines-malware-tools/"
		author = "McAfee Labs"
		score = 75

	strings:
		$b = {52 65 67 43 72 65 61 74 65 4b 65 79 41}
		$a = {43 72 79 70 74 43 72 65 61 74 65 48 61 73 68}
		$c = {2F 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 22 00 22 00 20 00 22 00 25 00 73 00 22 00 20 00 25 00 73 00 00 00 00 00 63 00 6D 00 64 00 2E 00 65 00 78 00 65 00 00 00 72 00 75 00 6E}
		$d = {53 00 6E 00 64 00 56 00 6F 00 6C 00 2E 00 65 00 78 00 65}
		$e = {52 00 65 00 64 00 69 00 72 00 65 00 63 00 74 00 45 00 58 00 45}

	condition:
		all of them
}

