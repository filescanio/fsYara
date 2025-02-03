rule Apolmy_Privesc_Trojan : hardened
{
	meta:
		description = "Apolmy Privilege Escalation Trojan used in APT Terracotta"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blogs.rsa.com/terracotta-vpn-enabler-of-advanced-threat-anonymity/"
		date = "2015-08-04"
		score = 80
		hash = "d7bd289e6cee228eb46a1be1fcdc3a2bd5251bc1eafb59f8111756777d8f373d"
		id = "2f3f496b-ebfe-5a6e-89ad-a24af6378fd7"

	strings:
		$s1 = {5b 25 64 5d 20 46 61 69 6c 65 64 2c 20 25 30 38 58}
		$s2 = {5b 25 64 5d 20 4f 66 66 73 65 74 20 63 61 6e 20 6e 6f 74 20 66 65 74 63 68 65 64 2e}
		$s3 = {50 00 6f 00 77 00 65 00 72 00 53 00 68 00 61 00 64 00 6f 00 77 00 32 00 30 00 31 00 31 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 300KB and all of them
}

rule Mithozhan_Trojan : hardened
{
	meta:
		description = "Mitozhan Trojan used in APT Terracotta"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blogs.rsa.com/terracotta-vpn-enabler-of-advanced-threat-anonymity/"
		date = "2015-08-04"
		score = 70
		hash = "8553b945e2d4b9f45c438797d6b5e73cfe2899af1f9fd87593af4fd7fb51794a"
		id = "5e2b4e08-1a35-5eb0-8c25-a73d45b0e279"

	strings:
		$s1 = {61 00 64 00 62 00 72 00 6f 00 77 00 73 00 65 00 72 00}
		$s2 = {49 4a 4b 4c 6c 47 64 6d 61 57 68 72 61 6d 30 76 6e 33 36 42 67 49 4f 43 68 59 52 33 4c 34 35 78 63 48 4e 79 64 58 51 76 68 6d 6c 6f 61 32 70 74 62 48 38 76 6f 59 43 44 54 77 3d 3d}
		$s3 = {45 46 47 48 6c 47 64 6d 61 57 68 72 4c 34 31 73 66 33 36 42 67 49 4f 43 4c 36 52 33 64 6b 38 3d}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 300KB and all of them
}

rule RemoteExec_Tool : hardened
{
	meta:
		description = "Remote Access Tool used in APT Terracotta"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blogs.rsa.com/terracotta-vpn-enabler-of-advanced-threat-anonymity/"
		date = "2015-08-04"
		hash = "a550131e106ff3c703666f15d55d9bc8c816d1cb9ac1b73c2e29f8aa01e53b78"
		id = "c3262147-3455-554c-88fc-b523352efe7f"

	strings:
		$s0 = {63 6d 64 2e 65 78 65 20 2f 71 20 2f 63 20 22 25 73 22}
		$s1 = {5c 5c 2e 5c 70 69 70 65 5c 25 73 25 73 25 64}
		$s2 = {54 68 69 73 20 69 73 20 61 20 73 65 72 76 69 63 65 20 65 78 65 63 75 74 61 62 6c 65 21 20 43 6f 75 6c 64 6e 27 74 20 73 74 61 72 74 20 64 69 72 65 63 74 6c 79 2e}
		$s3 = {5c 5c 2e 5c 70 69 70 65 5c 54 65 72 6d 48 6c 70 5f 63 6f 6d 6d 75 6e 69 63 61 74 6f 6e}
		$s4 = {54 65 72 6d 48 6c 70 5f 73 74 64 6f 75 74}
		$s5 = {54 65 72 6d 48 6c 70 5f 73 74 64 69 6e}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 75KB and 4 of ( $s* )
}

rule LiuDoor_Malware_1 : hardened
{
	meta:
		description = "Liudoor Trojan used in Terracotta APT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blogs.rsa.com/terracotta-vpn-enabler-of-advanced-threat-anonymity/"
		date = "2015-08-04"
		score = 70
		super_rule = 1
		hash1 = "deed6e2a31349253143d4069613905e1dfc3ad4589f6987388de13e33ac187fc"
		hash2 = "4575e7fc8f156d1d499aab5064a4832953cd43795574b4c7b9165cdc92993ce5"
		hash3 = "ad1a507709c75fe93708ce9ca1227c5fefa812997ed9104ff9adfec62a3ec2bb"
		id = "ebd5833e-1f5c-5166-aaba-d0be64829e6c"

	strings:
		$s1 = {73 76 63 68 6f 73 74 64 6c 6c 73 65 72 76 65 72 2e 64 6c 6c}
		$s2 = {53 76 63 48 6f 73 74 44 4c 4c 3a 20 52 65 67 69 73 74 65 72 53 65 72 76 69 63 65 43 74 72 6c 48 61 6e 64 6c 65 72 20 25 53 20 66 61 69 6c 65 64}
		$s3 = {5c 6e 62 74 73 74 61 74 2e 65 78 65}
		$s4 = {44 61 74 61 56 65 72 73 69 6f 6e 45 78}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 150KB and all of them
}

rule LiuDoor_Malware_2 : hardened
{
	meta:
		description = "Liudoor Trojan used in Terracotta APT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blogs.rsa.com/terracotta-vpn-enabler-of-advanced-threat-anonymity/"
		date = "2015-08-04"
		score = 70
		super_rule = 1
		hash1 = "f3fb68b21490ded2ae7327271d3412fbbf9d705c8003a195a705c47c98b43800"
		hash2 = "e42b8385e1aecd89a94a740a2c7cd5ef157b091fabd52cd6f86e47534ca2863e"
		id = "30b9d727-ec77-5ead-80dd-6d442478e78b"

	strings:
		$s0 = {73 76 63 68 6f 73 74 64 6c 6c 73 65 72 76 65 72 2e 64 6c 6c}
		$s1 = {4c 70 79 6b 68 7e 6d 7a 43 43 52 76 7c 6d 70 6c 70 79 6b 43 43 48 76 71 7b 70 68 6c 43 43 5c 6a 6d 6d 7a 71 6b 49 7a 6d 6c 76 70 71 43 43}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 100KB and all of them
}

