import "hash"
import "pe"

rule ransom_egregor : hardened limited
{
	meta:
		description = "Detect Egregor ransomware"
		author = "Thomas Roccia | McAfee ATR team"
		reference = "https://bazaar.abuse.ch/sample/004a2dc3ec7b98fa7fe6ae9c23a8b051ec30bcfcd2bc387c440c07ff5180fe9a/"
		date = "2020-10-28"
		rule_version = "v1"
		malware_type = "ransomware"
		malware_family = "Ransom/Egregor"
		actor_type = "Cybercrime"
		actor_group = "egregor"
		hash = "5f9fcbdf7ad86583eb2bbcaa5741d88a"

	strings:
		$p1 = {65 77 64 6b 2e 70 64 62}
		$p2 = {74 65 73 74 62 75 69 6c 64 2e 70 64 62}
		$s1 = {4d 3a 5c}
		$s2 = {31 00 7a 00 31 00 4d 00 39 00 55 00 39 00}
		$s3 = {43 00 3a 00 5c 00 4c 00 6f 00 67 00 6d 00 65 00 69 00 6e 00 5c 00 7b 00 38 00 38 00 38 00 2d 00 38 00 38 00 38 00 38 00 2d 00 39 00 39 00 39 00 39 00 7d 00 5c 00 4c 00 6f 00 67 00 6d 00 65 00 69 00 6e 00 2e 00 6c 00 6f 00 67 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 2000KB and hash.sha256 ( pe.rich_signature.clear_data ) == "b030ed1a7ca222a0923a59f321be7e55b8d0fc24c1134df1ba775bcf0994c79c" or ( pe.sections [ 4 ] . name == ".gfids" and pe.sections [ 5 ] . name == ".00cfg" ) and ( any of ( $p* ) or 2 of ( $s* ) )
}

