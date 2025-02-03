rule apt_hikit_rootkit : hardened
{
	meta:
		description = "Rule to detect the rootkit hikit based on PDB"
		author = "Marc Rivero | McAfee ATR Team"
		date = "2012-08-20"
		rule_version = "v1"
		malware_type = "rootkit"
		malware_family = "Rootkit:W32/Hikit"
		actor_type = "Cybercrime"
		actor_group = "Unknown"
		reference = "https://www.fireeye.com/blog/threat-research/2012/08/hikit-rootkit-advanced-persistent-attack-techniques-part-1.html"

	strings:
		$pdb = {5c 4a 6d 56 6f 64 53 65 72 76 65 72 5c 68 69 6b 69 74 5c 62 69 6e 33 32 5c 52 53 65 72 76 65 72 2e 70 64 62}
		$pdb1 = {5c 4a 6d 56 6f 64 53 65 72 76 65 72 5c 68 69 6b 69 74 5c 62 69 6e 33 32 5c 77 37 66 77 2e 70 64 62}
		$pdb2 = {5c 4a 6d 56 6f 64 53 65 72 76 65 72 5c 68 69 6b 69 74 5c 62 69 6e 33 32 5c 77 37 66 77 5f 32 6b 2e 70 64 62}
		$pdb3 = {5c 4a 6d 56 6f 64 53 65 72 76 65 72 5c 68 69 6b 69 74 5c 62 69 6e 36 34 5c 77 37 66 77 5f 78 36 34 2e 70 64 62}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 100KB and any of them
}

