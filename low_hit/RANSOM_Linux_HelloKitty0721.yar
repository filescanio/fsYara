rule ransom_Linux_HelloKitty_0721 : hardened
{
	meta:
		description = "rule to detect Linux variant of the Hello Kitty Ransomware"
		author = "Christiaan @ ATR"
		date = "2021-07-19"
		Rule_Version = "v1"
		malware_type = "ransomware"
		malware_family = "Ransom:Linux/HelloKitty"
		hash1 = "ca607e431062ee49a21d69d722750e5edbd8ffabcb54fa92b231814101756041"
		hash2 = "556e5cb5e4e77678110961c8d9260a726a363e00bf8d278e5302cb4bfccc3eed"

	strings:
		$v1 = {65 73 78 63 6c 69 20 76 6d 20 70 72 6f 63 65 73 73 20 6b 69 6c 6c 20 2d 74 3d 66 6f 72 63 65 20 2d 77 3d 25 64}
		$v2 = {65 73 78 63 6c 69 20 76 6d 20 70 72 6f 63 65 73 73 20 6b 69 6c 6c 20 2d 74 3d 68 61 72 64 20 2d 77 3d 25 64}
		$v3 = {65 73 78 63 6c 69 20 76 6d 20 70 72 6f 63 65 73 73 20 6b 69 6c 6c 20 2d 74 3d 73 6f 66 74 20 2d 77 3d 25 64}
		$v4 = {65 72 72 6f 72 20 65 6e 63 72 79 70 74 3a 20 25 73 20 72 65 6e 61 6d 65 20 62 61 63 6b 3a 25 73}
		$v5 = {65 73 78 63 6c 69 20 76 6d 20 70 72 6f 63 65 73 73 20 6c 69 73 74}
		$v6 = {54 6f 74 61 6c 20 56 4d 20 72 75 6e 20 6f 6e 20 68 6f 73 74 3a}
		$v7 = {65 72 72 6f 72 20 6c 6f 63 6b 5f 65 78 63 6c 75 73 69 76 65 6c 79 3a 25 73 20 6f 77 6e 65 72 20 70 69 64 3a 25 64}
		$v8 = {45 72 72 6f 72 20 6f 70 65 6e 20 25 73 20 69 6e 20 74 72 79 5f 6c 6f 63 6b 5f 65 78 63 6c 75 73 69 76 65 6c 79}
		$v9 = {4d 6f 64 65 3a 25 64 20 20 56 65 72 62 6f 73 65 3a 25 64 20 44 61 65 6d 6f 6e 3a 25 64 20 41 45 53 4e 49 3a 25 64 20 52 44 52 41 4e 44 3a 25 64 20}
		$v10 = {70 74 68 72 65 61 64 5f 63 6f 6e 64 5f 73 69 67 6e 61 6c 28 29 20 65 72 72 6f 72}
		$v11 = {43 68 61 43 68 61 32 30 20 66 6f 72 20 78 38 36 5f 36 34 2c 20 43 52 59 50 54 4f 47 41 4d 53 20 62 79 20 3c 61 70 70 72 6f 40 6f 70 65 6e 73 73 6c 2e 6f 72 67 3e}

	condition:
		( uint16( 0 ) == 0x457f and filesize < 200KB and ( 8 of them ) ) or ( all of them )
}

