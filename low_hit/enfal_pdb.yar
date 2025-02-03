rule enfal_pdb : hardened
{
	meta:
		description = "Rule to detect Enfal malware"
		author = "Marc Rivero | McAfee ATR Team"
		date = "2013-08-27"
		rule_version = "v1"
		malware_type = "backdoor"
		malware_family = "Backdoor:W32/Enfal"
		actor_type = "Apt"
		actor_group = "Unknown"
		reference = "https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/enfal"
		hash = "6756808313359cbd7c50cd779f809bc9e2d83c08da90dbd80f5157936673d0bf"

	strings:
		$pdb = {5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 4d 79 20 44 6f 63 75 6d 65 6e 74 73 5c 57 6f 72 6b 5c 45 74 65 6e 46 61 6c 63 6f 6e 5c 52 65 6c 65 61 73 65 5c 44 6c 6c 53 65 72 76 69 63 65 54 72 6f 6a 61 6e 2e 70 64 62}
		$pdb1 = {5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 4d 79 20 44 6f 63 75 6d 65 6e 74 73 5c 57 6f 72 6b 5c 45 74 65 6e 46 61 6c 63 6f 6e 5c 52 65 6c 65 61 73 65 5c 53 65 72 76 69 63 65 44 6c 6c 2e 70 64 62}
		$pdb2 = {5c 52 65 6c 65 61 73 65 5c 53 65 72 76 69 63 65 44 6c 6c 2e 70 64 62}
		$pdb3 = {5c 6d 75 6d 61 5c 30 35 31 31 5c 52 65 6c 65 61 73 65 5c 53 65 72 76 69 63 65 44 6c 6c 2e 70 64 62}
		$pdb4 = {5c 70 72 6f 67 72 61 6d 73 5c 4c 75 72 69 64 44 6f 77 6e 4c 6f 61 64 65 72 5c 4c 75 72 69 64 44 6f 77 6e 6c 6f 61 64 65 72 20 66 6f 72 20 46 61 6c 63 6f 6e 5c 53 65 72 76 69 63 65 44 6c 6c 5c 52 65 6c 65 61 73 65 5c 53 65 72 76 69 63 65 44 6c 6c 2e 70 64 62}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 150KB and any of them
}

