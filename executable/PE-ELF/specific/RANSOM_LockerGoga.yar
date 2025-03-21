rule LockerGogaRansomware : hardened
{
	meta:
		description = "LockerGoga Ransomware"
		author = "Christiaan Beek - McAfee ATR team"
		date = "2019-03-20"
		rule_version = "v1"
		malware_type = "ransomware"
		malware_family = "Ransom:W32/LockerGoga"
		actor_type = "Cybercrime"
		actor_group = "Unknown"
		hash = "ba15c27f26265f4b063b65654e9d7c248d0d651919fafb68cb4765d1e057f93f"
		score = 80

	strings:
		$1 = {62 6f 6f 73 74 3a 3a 69 6e 74 65 72 70 72 6f 63 65 73 73 3a 3a 73 70 69 6e 5f 72 65 63 75 72 73 69 76 65 5f 6d 75 74 65 78 20 72 65 63 75 72 73 69 76 65 20 6c 6f 63 6b 20 6f 76 65 72 66 6c 6f 77}
		$2 = {2e 3f 41 55 3f 24 65 72 72 6f 72 5f 69 6e 66 6f 5f 69 6e 6a 65 63 74 6f 72 40 55 73 79 6e 63 5f 71 75 65 75 65 5f 69 73 5f 63 6c 6f 73 65 64 40 63 6f 6e 63 75 72 72 65 6e 74 40 62 6f 6f 73 74 40 40 40 65 78 63 65 70 74 69 6f 6e 5f 64 65 74 61 69 6c 40 62 6f 6f 73 74 40 40}
		$3 = {2e 3f 41 56 3f 24 43 69 70 68 65 72 4d 6f 64 65 46 69 6e 61 6c 54 65 6d 70 6c 61 74 65 5f 43 69 70 68 65 72 48 6f 6c 64 65 72 40 56 3f 24 42 6c 6f 63 6b 43 69 70 68 65 72 46 69 6e 61 6c 40 24 30 30 56 44 65 63 40 52 43 36 40 43 72 79 70 74 6f 50 50 40 40 40 43 72 79 70 74 6f 50 50 40 40 56 43 42 43 5f 44 65 63 72 79 70 74 69 6f 6e 40 32 40 40 43 72 79 70 74 6f 50 50 40 40}
		$4 = {3f 68 74 74 70 3a 2f 2f 63 72 6c 2e 75 73 65 72 74 72 75 73 74 2e 63 6f 6d 2f 55 53 45 52 54 72 75 73 74 52 53 41 43 65 72 74 69 66 69 63 61 74 69 6f 6e 41 75 74 68 6f 72 69 74 79 2e 63 72 6c 30 76}
		$5 = {63 69 70 68 65 72 2e 65 78 65}
		$6 = {2e 3f 41 55 3f 24 70 6c 61 63 65 6d 65 6e 74 5f 64 65 73 74 72 6f 79 40 55 74 72 61 63 65 5f 71 75 65 75 65 40 40 40 69 70 63 64 65 74 61 69 6c 40 69 6e 74 65 72 70 72 6f 63 65 73 73 40 62 6f 6f 73 74 40 40}
		$7 = {33 68 74 74 70 3a 2f 2f 63 72 74 2e 75 73 65 72 74 72 75 73 74 2e 63 6f 6d 2f 55 53 45 52 54 72 75 73 74 52 53 41 41 64 64 54 72 75 73 74 43 41 2e 63 72 74 30 25}
		$8 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 20 66 61 69 6c 65 64}
		$9 = {62 6f 6f 73 74 3a 3a 64 6c 6c 3a 3a 73 68 61 72 65 64 5f 6c 69 62 72 61 72 79 3a 3a 6c 6f 61 64 28 29 20 66 61 69 6c 65 64}
		$op1 = { 8b df 83 cb 0f 81 fb ff ff ff 7f 76 07 bb ff ff }
		$op2 = { 8b df 83 cb 0f 81 fb ff ff ff 7f 76 07 bb ff ff }

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 2000KB and ( 6 of them ) and all of ( $op* ) ) or ( all of them )
}

