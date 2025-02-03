rule apt_turla_pdb : hardened
{
	meta:
		description = "Rule to detect a component of the APT Turla"
		author = "Marc Rivero | McAfee ATR Team"
		date = "2017-05-31"
		rule_version = "v1"
		malware_type = "backdoor"
		malware_family = "Backdoor:W32/Turla"
		actor_type = "Apt"
		actor_group = "Unknown"
		reference = "https://attack.mitre.org/groups/G0010/"
		hash = "3b8bd0a0c6069f2d27d759340721b78fd289f92e0a13965262fea4e8907af122"

	strings:
		$pdb = {5c 57 6f 72 6b 73 68 6f 70 5c 50 72 6f 6a 65 63 74 73 5c 63 6f 62 72 61 5c 63 61 72 62 6f 6e 5f 73 79 73 74 65 6d 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 63 61 72 62 6f 6e 5f 73 79 73 74 65 6d 2e 70 64 62}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 650KB and any of them
}

