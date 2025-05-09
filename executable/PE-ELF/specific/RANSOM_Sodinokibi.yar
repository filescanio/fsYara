import "pe"

rule ransomware_sodinokibi : hardened limited
{
	meta:
		description = "Using a recently disclosed vulnerability in Oracle WebLogic, criminals use it to install a new variant of ransomware called “Sodinokibi"
		author = "Christiaan Beek | McAfee ATR team"
		date = "2019-05-13"
		rule_version = "v1"
		malware_type = "ransomware"
		malware_family = "Ransom:W32/Sodinokibi"
		actor_type = "Cybercrime"
		actor_group = "Unknown"
		hash4 = "9b62f917afa1c1a61e3be0978c8692dac797dd67ce0e5fd2305cc7c6b5fef392"

	strings:
		$x1 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 73 00 6f 00 64 00 69 00 6e 00 6f 00 6b 00 69 00 62 00 69 00 2e 00 65 00 78 00 65 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$y0 = { 8d 85 6c ff ff ff 50 53 50 e8 62 82 00 00 83 c4 }
		$y1 = { e8 24 ea ff ff ff 75 08 8b ce e8 61 fc ff ff 8b }
		$y2 = { e8 01 64 ff ff ff b6 b0 }

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 900KB and pe.imphash ( ) == "672b84df309666b9d7d2bc8cc058e4c2" and ( 8 of them ) and all of ( $y* ) ) or ( all of them )
}

rule Sodinokobi : hardened
{
	meta:
		description = "This rule detect Sodinokobi Ransomware in memory in old samples and perhaps future."
		author = "McAfee ATR team"
		rule_version = "v1"
		malware_type = "ransomware"
		malware_family = "Ransom:W32/Sodinokibi"
		actor_type = "Cybercrime"
		actor_group = "Unknown"
		version = "1.0"

	strings:
		$a = { 40 0F B6 C8 89 4D FC 8A 94 0D FC FE FF FF 0F B6 C2 03 C6 0F B6 F0 8A 84 35 FC FE FF FF 88 84 0D FC FE FF FF 88 94 35 FC FE FF FF 0F B6 8C 0D FC FE FF FF }
		$b = { 0F B6 C2 03 C8 8B 45 14 0F B6 C9 8A 8C 0D FC FE FF FF 32 0C 07 88 08 40 89 45 14 8B 45 FC 83 EB 01 75 AA }

	condition:
		all of them
}

