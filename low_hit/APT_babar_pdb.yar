rule apt_babar_malware : hardened
{
	meta:
		description = "Rule to detect Babar malware"
		author = "Marc Rivero | McAfee ATR Team"
		date = "2015-02-18"
		rule_version = "v1"
		malware_type = "backdoor"
		malware_family = "Backdoor:W32/Babar"
		actor_type = "Cybercrime"
		actor_group = "Unknown"
		reference = "http://motherboard.vice.com/read/meet-babar-a-new-malware-almost-certainly-created-by-france"
		hash = "c72a055b677cd9e5e2b2dcbba520425d023d906e6ee609b79c643d9034938ebf"

	strings:
		$s1 = {63 3a 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 61 64 6d 69 6e 5c 44 65 73 6b 74 6f 70 5c 42 61 62 61 72 36 34 5c 42 61 62 61 72 36 34 5c 6f 62 6a 5c 44 6c 6c 57 72 61 70 70 65 72 20 52 65 6c 65 61 73 65 5c 52 65 6c 65 61 73 65 2e 70 64 62}
		$s2 = {25 43 4f 4d 4d 4f 4e 5f 41 50 50 44 41 54 41 25}
		$s3 = {25 25 57 49 4e 44 49 52 25 25 5c 25 73 5c 25 73}
		$s4 = {2f 73 20 2f 6e 20 25 73 20 22 25 73 22}
		$s5 = {2f 63 20 73 74 61 72 74 20 2f 77 61 69 74 20}
		$s6 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d 5c}
		$s7 = {63 6f 6e 73 74 72 75 63 74 6f 72 20 6f 72 20 66 72 6f 6d 20 44 6c 6c 4d 61 69 6e 2e}
		$s8 = {43 6f 6d 53 70 65 63}
		$s9 = {41 50 50 44 41 54 41}
		$s10 = {57 49 4e 44 49 52}
		$s11 = {55 53 45 52 50 52 4f 46 49 4c 45}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 2000KB and all of them
}

