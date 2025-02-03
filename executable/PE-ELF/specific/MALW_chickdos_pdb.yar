rule chikdos_malware_pdb : hardened
{
	meta:
		description = "Chikdos PDB"
		author = "Marc Rivero | McAfee ATR Team"
		date = "2013-12-02"
		rule_version = "v1"
		malware_type = "dos"
		malware_family = "Dos:W32/ChickDos"
		actor_type = "Cybercrime"
		actor_group = "Unknown"
		reference = "http://hackermedicine.com/tag/trojan-chickdos/"
		hash = "c2a0e9f8e880ac22098d550a74940b1d81bc9fda06cebcf67f74782e55e9d9cc"

	strings:
		$pdb = {5c 49 6e 74 65 72 67 72 61 74 65 43 48 4b 5c 52 65 6c 65 61 73 65 5c 49 6e 74 65 72 67 72 61 74 65 43 48 4b 2e 70 64 62}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 600KB and any of them
}

