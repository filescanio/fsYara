rule Alina_POS_PDB : hardened
{
	meta:
		description = "Rule to detect Alina POS"
		author = "Marc Rivero | McAfee ATR Team"
		date = "2013-08-08"
		rule_version = "v1"
		malware_type = "pos"
		malware_family = "Pos:W32/Alina"
		actor_type = "Cybercrime"
		actor_group = "Unknown"
		reference = "https://www.pandasecurity.com/mediacenter/pandalabs/alina-pos-malware/"
		hash = "28b0c52c0630c15adcc857d0957b3b8002a4aeda3c7ec40049014ce33c7f67c3"

	strings:
		$pdb = {5c 55 73 65 72 73 5c 64 69 63 65 5c 44 65 73 6b 74 6f 70 5c 53 52 43 5f 61 64 6f 62 65 5c 73 72 63 5c 67 72 61 62 5c 52 65 6c 65 61 73 65 5c 41 6c 69 6e 61 2e 70 64 62}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 100KB and any of them
}

