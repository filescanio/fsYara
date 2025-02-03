rule CloudDuke_Malware : hardened
{
	meta:
		description = "Detects CloudDuke Malware"
		author = "Florian Roth"
		reference = "https://www.f-secure.com/weblog/archives/00002822.html"
		date = "2015-07-22"
		score = 60
		hash1 = "97d8725e39d263ed21856477ed09738755134b5c0d0b9ae86ebb1cdd4cdc18b7"
		hash2 = "88a40d5b679bccf9641009514b3d18b09e68b609ffaf414574a6eca6536e8b8f"
		hash3 = "1d4ac97d43fab1d464017abb5d57a6b4601f99eaa93b01443427ef25ae5127f7"
		hash4 = "97d8725e39d263ed21856477ed09738755134b5c0d0b9ae86ebb1cdd4cdc18b7"
		hash5 = "1d4ac97d43fab1d464017abb5d57a6b4601f99eaa93b01443427ef25ae5127f7"
		hash6 = "88a40d5b679bccf9641009514b3d18b09e68b609ffaf414574a6eca6536e8b8f"
		hash7 = "ed7abf93963395ce9c9cba83a864acb4ed5b6e57fd9a6153f0248b8ccc4fdb46"
		hash8 = "97d8725e39d263ed21856477ed09738755134b5c0d0b9ae86ebb1cdd4cdc18b7"
		hash9 = "ed7abf93963395ce9c9cba83a864acb4ed5b6e57fd9a6153f0248b8ccc4fdb46"
		hash10 = "ee5eb9d57c3611e91a27bb1fc2d0aaa6bbfa6c69ab16e65e7123c7c49d46f145"
		hash11 = "a713982d04d2048a575912a5fc37c93091619becd5b21e96f049890435940004"
		hash12 = "56ac764b81eb216ebed5a5ad38e703805ba3e1ca7d63501ba60a1fb52c7ebb6e"
		hash13 = "ee5eb9d57c3611e91a27bb1fc2d0aaa6bbfa6c69ab16e65e7123c7c49d46f145"
		hash14 = "a713982d04d2048a575912a5fc37c93091619becd5b21e96f049890435940004"
		hash15 = "56ac764b81eb216ebed5a5ad38e703805ba3e1ca7d63501ba60a1fb52c7ebb6e"

	strings:
		$s1 = {50 72 6f 63 44 61 74 61 57 72 61 70}
		$s2 = {69 6d 61 67 65 68 6c 70 2e 64 6c 6c}
		$s3 = {64 6e 6c 69 62 73 68}
		$s4 = {25 00 77 00 73 00 5f 00 6f 00 75 00 74 00 25 00 77 00 73 00}
		$s5 = {41 00 6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00}
		$op0 = { 0f b6 80 68 0e 41 00 0b c8 c1 e1 08 0f b6 c2 8b }
		$op1 = { 8b ce e8 f8 01 00 00 85 c0 74 41 83 7d f8 00 0f }
		$op2 = { e8 2f a2 ff ff 83 20 00 83 c8 ff 5f 5e 5d c3 55 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 720KB and 4 of ( $s* ) and 1 of ( $op* )
}

rule SFXRAR_Acrotray : hardened
{
	meta:
		description = "Most likely a malicious file acrotray in SFX RAR / CloudDuke APT 5442.1.exe, 5442.2.exe"
		author = "Florian Roth"
		reference = "https://www.f-secure.com/weblog/archives/00002822.html"
		date = "2015-07-22"
		super_rule = 1
		score = 70
		hash1 = "51e713c7247f978f5836133dd0b8f9fb229e6594763adda59951556e1df5ee57"
		hash2 = "5d695ff02202808805da942e484caa7c1dc68e6d9c3d77dc383cfa0617e61e48"
		hash3 = "56531cc133e7a760b238aadc5b7a622cd11c835a3e6b78079d825d417fb02198"

	strings:
		$s1 = {77 00 69 00 6e 00 72 00 61 00 72 00 73 00 66 00 78 00 6d 00 61 00 70 00 70 00 69 00 6e 00 67 00 66 00 69 00 6c 00 65 00 2e 00 74 00 6d 00 70 00}
		$s2 = {47 00 45 00 54 00 50 00 41 00 53 00 53 00 57 00 4f 00 52 00 44 00 31 00}
		$s3 = {61 63 72 6f 74 72 61 79 2e 65 78 65}
		$s4 = {43 00 72 00 79 00 70 00 74 00 55 00 6e 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 20 00 66 00 61 00 69 00 6c 00 65 00 64 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 2449KB and all of them
}

