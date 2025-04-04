rule Windows_Trojan_Limerat_24269a79 : hardened limited
{
	meta:
		author = "Elastic Security"
		id = "24269a79-0172-4da5-9b4d-f61327072bf0"
		fingerprint = "cb714cd787519216d25edaad9f89a9c0ce1b8fbbbcdf90bda4c79f5d85fdf381"
		creation_date = "2021-08-17"
		last_modified = "2021-10-04"
		threat_name = "Windows.Trojan.Limerat"
		reference_sample = "ec781a714d6bc6fac48d59890d9ae594ffd4dbc95710f2da1f1aa3d5b87b9e01"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_Limerat.yar"
		repository = "elastic/protections-artifacts"
		source_url = "https://github.com/elastic/protections-artifacts/blob/f98777756fcfbe5ab05a296388044a2dbb962557/yara/rules/Windows_Trojan_Limerat.yar"
		score = 75

	strings:
		$a1 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 20 00 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 66 00 20 00 2f 00 73 00 63 00 20 00 4f 00 4e 00 4c 00 4f 00 47 00 4f 00 4e 00 20 00 2f 00 52 00 4c 00 20 00 48 00 49 00 47 00 48 00 45 00 53 00 54 00 20 00 2f 00 74 00 6e 00 20 00 4c 00 69 00 6d 00 65 00 52 00 41 00 54 00 2d 00 41 00 64 00 6d 00 69 00 6e 00 20 00 2f 00 74 00 72 00 20 00 22 00 27 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}

	condition:
		all of them
}

rule ByteCode_MSIL_Backdoor_LimeRAT : tc_detection malicious hardened
{
	meta:
		author = "ReversingLabs"
		source = "ReversingLabs"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "MALWARE"
		malware = "LIMERAT"
		description = "Yara rule that detects LimeRAT backdoor."
		tc_detection_type = "Backdoor"
		tc_detection_name = "LimeRAT"
		tc_detection_factor = 5
		ruleset = "ByteCode.MSIL.Backdoor.LimeRAT.yara"
		repository = "reversinglabs/reversinglabs-yara-rules"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules/blob/d5a78f30a1669a3dc576d45a77eeba9476795155/yara/backdoor/ByteCode.MSIL.Backdoor.LimeRAT.yara"
		license = "MIT License"
		score = 75

	strings:
		$persistence_mechanism = {
            02 2C ?? 72 ?? ?? ?? ?? 7E ?? ?? ?? ?? 28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ??
            28 ?? ?? ?? ?? 16 16 15 28 ?? ?? ?? ?? 26 2B ?? 7E ?? ?? ?? ?? 72 ?? ?? ?? ?? 6F ??
            ?? ?? ?? 7E ?? ?? ?? ?? 7E ?? ?? ?? ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? DE ?? 28 ?? ??
            ?? ?? 28 ?? ?? ?? ?? DE
        }
		$crypto_miner = {
            72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 8E 69 16 31 ?? 72 ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ??
            ?? ?? 0B 07 73 ?? ?? ?? ?? 6F ?? ?? ?? ?? 0C 08 6F ?? ?? ?? ?? 0D 2B ?? 09 6F ?? ??
            ?? ?? 74 ?? ?? ?? ?? 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 6F ?? ?? ?? ?? 72 ?? ?? ?? ?? 6F
            ?? ?? ?? ?? 2C ?? 72 ?? ?? ?? ?? 0A DE ?? 09 6F ?? ?? ?? ?? 2D ?? DE ?? 09 2C ?? 09
            6F ?? ?? ?? ?? DC DE ?? 25 28 ?? ?? ?? ?? 13 ?? 28 ?? ?? ?? ?? DE ?? 28 ?? ?? ?? ??
            0A DE ?? 25 28 ?? ?? ?? ?? 13 ?? 28 ?? ?? ?? ?? DE ?? 06
        }
		$downloader = {
            73 ?? ?? ?? ?? 0A 28 ?? ?? ?? ?? 7E ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0B 7E
            ?? ?? ?? ?? 72 ?? ?? ?? ?? 16 28 ?? ?? ?? ?? 2C ?? 7E ?? ?? ?? ?? 2C ?? 72 ?? ?? ??
            ?? 28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 16 28 ?? ?? ?? ?? 2C ?? 06 7E ?? ?? ?? ?? 07 6F ??
            ?? ?? ?? 07 28 ?? ?? ?? ?? 26 72 ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 26 2B ??
            06 7E ?? ?? ?? ?? 07 6F ?? ?? ?? ?? 07 28 ?? ?? ?? ?? 26 00 06 6F ?? ?? ?? ?? 14 0A
            DE ?? 25 28 ?? ?? ?? ?? 0C 28 ?? ?? ?? ?? DE ?? DE ?? 25 28 ?? ?? ?? ?? 0D 28 ?? ??
            ?? ?? DE
        }
		$network_communication_p1 = {
            16 80 ?? ?? ?? ?? 7E ?? ?? ?? ?? 6F ?? ?? ?? ?? DE ?? 25 28 ?? ?? ?? ?? 0B 28 ?? ??
            ?? ?? DE ?? 00 7E ?? ?? ?? ?? 6F ?? ?? ?? ?? DE ?? 25 28 ?? ?? ?? ?? 0C 28 ?? ?? ??
            ?? DE ?? 00 7E ?? ?? ?? ?? 6F ?? ?? ?? ?? DE ?? 25 28 ?? ?? ?? ?? 0D 28 ?? ?? ?? ??
            DE ?? 00 73 ?? ?? ?? ?? 80 ?? ?? ?? ?? 7E ?? ?? ?? ?? 20 ?? ?? ?? ?? 6F ?? ?? ?? ??
            7E ?? ?? ?? ?? 20 ?? ?? ?? ?? 6F ?? ?? ?? ?? 7E ?? ?? ?? ?? 15 6F ?? ?? ?? ?? 7E ??
            ?? ?? ?? 15 6F ?? ?? ?? ?? 73 ?? ?? ?? ?? 13 ?? 72 ?? ?? ?? ?? 72 ?? ?? ?? ?? 73 ??
            ?? ?? ?? 13 ?? 11 ?? 11 ?? 6F ?? ?? ?? ?? 11 ?? 14 72 ?? ?? ?? ?? 17 8D ?? ?? ?? ??
            25 16 7E ?? ?? ?? ?? 28 ?? ?? ?? ?? A2 14 14 14 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 72 ??
            ?? ?? ?? 15 16 28 ?? ?? ?? ?? 13 ?? 11 ?? 16 9A 80 ?? ?? ?? ?? 73 ?? ?? ?? ?? 26 11
            ?? 73 ?? ?? ?? ?? 17 11 ?? 8E 69 6F ?? ?? ?? ?? 9A 28 ?? ?? ?? ?? 80 ?? ?? ?? ?? 11
            ?? 6F ?? ?? ?? ?? DE ?? 25 28 ?? ?? ?? ?? 13 ?? 28 ?? ?? ?? ?? DE ?? DE ?? 11 ?? 2C
            ?? 11 ?? 6F ?? ?? ?? ?? DC 7E ?? ?? ?? ?? 7E ?? ?? ?? ?? 7E ?? ?? ?? ?? 6F ?? ?? ??
            ?? 17 80 ?? ?? ?? ?? 73 ?? ?? ?? ?? 80 ?? ?? ?? ?? 1F ?? 8D ?? ?? ?? ?? 25 16 72 ??
            ?? ?? ?? A2 25 17 7E ?? ?? ?? ?? A2 25 18 28 ?? ?? ?? ?? A2 25 19 7E ?? ?? ?? ?? A2
        }
		$network_communication_p2 = {
            25 1A 28 ?? ?? ?? ?? A2 25 1B 7E ?? ?? ?? ?? A2 25 1C 72 ?? ?? ?? ?? A2 25 1D 7E ??
            ?? ?? ?? A2 25 1E 28 ?? ?? ?? ?? A2 25 1F ?? 72 ?? ?? ?? ?? A2 25 1F ?? 28 ?? ?? ??
            ?? A2 25 1F ?? 7E ?? ?? ?? ?? A2 25 1F ?? 28 ?? ?? ?? ?? A2 25 1F ?? 7E ?? ?? ?? ??
            A2 25 1F ?? 28 ?? ?? ?? ?? A2 25 1F ?? 7E ?? ?? ?? ?? A2 25 1F ?? 28 ?? ?? ?? ?? A2
            25 1F ?? 7E ?? ?? ?? ?? A2 25 1F ?? 28 ?? ?? ?? ?? A2 25 1F ?? 7E ?? ?? ?? ?? A2 25
            1F ?? 28 ?? ?? ?? ?? A2 25 1F ?? 7E ?? ?? ?? ?? A2 25 1F ?? 7E ?? ?? ?? ?? 8C ?? ??
            ?? ?? A2 25 1F ?? 7E ?? ?? ?? ?? A2 25 1F ?? 28 ?? ?? ?? ?? A2 25 1F ?? 7E ?? ?? ??
            ?? A2 25 1F ?? 72 ?? ?? ?? ?? A2 25 1F ?? 7E ?? ?? ?? ?? A2 25 1F ?? 72 ?? ?? ?? ??
            A2 25 1F ?? 7E ?? ?? ?? ?? A2 25 1F ?? 28 ?? ?? ?? ?? 13 ?? 12 ?? 28 ?? ?? ?? ?? A2
            25 1F ?? 7E ?? ?? ?? ?? A2 25 1F ?? 7E ?? ?? ?? ?? A2 28 ?? ?? ?? ?? 28 ?? ?? ?? ??
            7E ?? ?? ?? ?? 2C ?? 7E ?? ?? ?? ?? 2B ?? 7E
        }

	condition:
		uint16( 0 ) == 0x5A4D and ( $persistence_mechanism ) and ( $crypto_miner ) and ( $downloader ) and ( all of ( $network_communication_p* ) )
}

rule LimeRAT : hardened limited
{
	meta:
		author = "ditekshen"
		description = "LimeRAT payload"
		cape_type = "LimeRAT Payload"
		ruleset = "LimeRAT.yar"
		repository = "CAPESandbox/community"
		source_url = "https://github.com/CAPESandbox/community/blob/ed71b5eb9179e25174c1a2d0fe451e25cbf97dd1/data/yara/CAPE/LimeRAT.yar"
		score = 75

	strings:
		$s1 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 20 00 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 66 00 20 00 2f 00 73 00 63 00 20 00 4f 00 4e 00 4c 00 4f 00 47 00 4f 00 4e 00 20 00 2f 00 52 00 4c 00 20 00 48 00 49 00 47 00 48 00 45 00 53 00 54 00 20 00 2f 00 74 00 6e 00 20 00 4c 00 69 00 6d 00 65 00 52 00 41 00 54 00 2d 00 41 00 64 00 6d 00 69 00 6e 00 20 00 2f 00 74 00 72 00}
		$s2 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 5c 00 76 00 62 00 6f 00 78 00 68 00 6f 00 6f 00 6b 00 2e 00 64 00 6c 00 6c 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s3 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 57 00 69 00 6e 00 33 00 32 00 5f 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 6f 00 72 00 2e 00 64 00 65 00 76 00 69 00 63 00 65 00 69 00 64 00 3d 00 22 00 43 00 50 00 55 00 30 00 22 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s4 = {73 00 65 00 6c 00 65 00 63 00 74 00 20 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 4c 00 69 00 6e 00 65 00 20 00 66 00 72 00 6f 00 6d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 77 00 68 00 65 00 72 00 65 00 20 00 4e 00 61 00 6d 00 65 00 3d 00 27 00 7b 00 30 00 7d 00 27 00}
		$s5 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 4d 00 69 00 6e 00 6e 00 69 00 6e 00 67 00 2e 00 2e 00 2e 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s6 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 52 00 65 00 67 00 61 00 73 00 6d 00 2e 00 65 00 78 00 65 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s7 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 46 00 6c 00 6f 00 6f 00 64 00 21 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s8 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 52 00 61 00 6e 00 73 00 2d 00 53 00 74 00 61 00 74 00 75 00 73 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s9 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 70 00 69 00 6e 00 67 00 20 00 30 00}

	condition:
		uint16( 0 ) == 0x5a4d and 5 of them
}

rule win_limerat_j1_00cfd931 : hardened
{
	meta:
		author = "Johannes Bader"
		date = "2021-10-01"
		description = "detects the lime rat"
		hash = "2a0575b66a700edb40a07434895bf7a9"
		malpedia_family = "win.limerat"
		tlp = "TLP:WHITE"
		version = "v1.1"
		yarahub_author_email = "yara@bin.re"
		yarahub_author_twitter = "@viql"
		yarahub_license = "CC BY-SA 4.0"
		yarahub_reference_md5 = "2a0575b66a700edb40a07434895bf7a9"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_uuid = "00cfd931-3e03-4e32-b0d7-ca8f6bbfe062"
		ruleset = "win_limerat_j1_00cfd931.yar"
		repository = "LeakIX/yara-repo-abusech"
		source_url = "https://github.com/LeakIX/yara-repo-abusech/blob/5a4620d4d41697fb8d9e1303c0aba2ced8f6932a/win_limerat_j1_00cfd931.yar"
		score = 75

	strings:
		$str_1 = {59 00 32 00 31 00 6b 00 4c 00 6d 00 56 00 34 00 5a 00 53 00 41 00 76 00 59 00 79 00 42 00 77 00 61 00 57 00 35 00 6e 00 49 00 44 00 41 00 67 00 4c 00 57 00 34 00 67 00 4d 00 69 00 41 00 6d 00 49 00 47 00 52 00 6c 00 62 00 43 00 41 00 3d 00}
		$str_2 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 20 00 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 66 00 20 00 2f 00 73 00 63 00 20 00 4f 00 4e 00 4c 00 4f 00 47 00 4f 00 4e 00 20 00 2f 00 52 00 4c 00 20 00 48 00 49 00 47 00 48 00 45 00 53 00 54 00 20 00 2f 00 74 00 6e 00 20 00 4c 00 69 00 6d 00 65 00 52 00 41 00 54 00 2d 00 41 00 64 00 6d 00 69 00 6e 00}
		$str_3 = {4d 00 69 00 6e 00 6e 00 69 00 6e 00 67 00 2e 00 2e 00 2e 00}
		$str_4 = {2d 00 2d 00 64 00 6f 00 6e 00 61 00 74 00 65 00 2d 00 6c 00 65 00 76 00 65 00 6c 00 3d 00}

	condition:
		uint16( 0 ) == 0x5A4D and 3 of them
}

rule LimeRAT_1 : hardened
{
	meta:
		description = "Detects Lime RAT malware samples based on the strings matched"
		author = "RustyNoob619"
		source = "https://valhalla.nextron-systems.com/info/rule/MAL_LimeRAT_Mar23"
		hash = "b62f72df91cffe7861b84a38070e25834ca32334bea0a0e25274a60a242ea669"
		original_yara_name = "LimeRAT"
		ruleset = "EXE_RAT_LimeRAT.yara"
		repository = "RustyNoob-619/YARA"
		source_url = "https://github.com/RustyNoob-619/YARA/blob/b4d14356c117458127705ab545de47cef2769a78/Rules/EXE_RAT_LimeRAT.yara"
		score = 75

	strings:
		$main = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 20 00 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 66 00 20 00 2f 00 73 00 63 00 20 00 4f 00 4e 00 4c 00 4f 00 47 00 4f 00 4e 00 20 00 2f 00 52 00 4c 00 20 00 48 00 49 00 47 00 48 00 45 00 53 00 54 00 20 00 2f 00 74 00 6e 00 20 00 4c 00 69 00 6d 00 65 00 52 00 41 00 54 00 2d 00 41 00 64 00 6d 00 69 00 6e 00 20 00 2f 00 74 00 72 00}
		$cmd1 = {46 00 6c 00 6f 00 6f 00 64 00 21 00}
		$cmd2 = {21 00 50 00 53 00 65 00 6e 00 64 00}
		$cmd3 = {21 00 50 00 53 00 74 00 61 00 72 00 74 00}
		$cmd4 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 41 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00}
		$cmd5 = {53 00 65 00 6c 00 65 00 63 00 74 00 20 00 2a 00 20 00 66 00 72 00 6f 00 6d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 53 00 79 00 73 00 74 00 65 00 6d 00}
		$cmd6 = {5f 00 55 00 53 00 42 00 20 00 45 00 72 00 72 00 6f 00 72 00 21 00}
		$cmd7 = {5f 00 50 00 49 00 4e 00 20 00 45 00 72 00 72 00 6f 00 72 00 21 00}

	condition:
		uint16( 0 ) == 0x5A4D and $main and 4 of ( $cmd* )
}

rule fsLimeRAT : hardened
{
	meta:
		description = "FsYARA - Malware Trends"
		vetted_family = "limerat"
		score = 75

	condition:
		Windows_Trojan_Limerat_24269a79 or ByteCode_MSIL_Backdoor_LimeRAT or LimeRAT or win_limerat_j1_00cfd931 or LimeRAT_1
}

