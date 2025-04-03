rule Remcos : hardened limited
{
	meta:
		author = "kevoreilly"
		description = "Remcos Payload"
		cape_type = "Remcos Payload"
		ruleset = "Remcos.yar"
		repository = "kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/9c8d6da44b595f8140a5cd76edd8101f6812c3b0/data/yara/CAPE/Remcos.yar"
		license = "Other"
		score = 75

	strings:
		$name = {52 65 6d 63 6f 73}
		$time = {25 30 32 69 3a 25 30 32 69 3a 25 30 32 69 3a 25 30 33 69}
		$crypto1 = {81 E1 FF 00 00 80 79 ?? 4? 81 C9 00 FF FF FF 4? 8A ?4 8?}
		$crypto2 = {0F B6 [1-7] 8B 45 08 [0-2] 8D 34 07 8B 01 03 C2 8B CB 99 F7 F9 8A 84 95 ?? ?? FF FF 30 06 47 3B 7D 0C 72}

	condition:
		uint16( 0 ) == 0x5A4D and ( $name ) and ( $time ) and any of ( $crypto* )
}

rule Windows_Trojan_Remcos_b296e965 : hardened limited
{
	meta:
		author = "Elastic Security"
		id = "b296e965-a99e-4446-b969-ba233a2a8af4"
		fingerprint = "a5267bc2dee28a3ef58beeb7e4a151699e3e561c16ce0ab9eb27de33c122664d"
		creation_date = "2021-06-10"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.Remcos"
		reference = "https://www.elastic.co/security-labs/exploring-the-ref2731-intrusion-set"
		reference_sample = "0ebeffa44bd1c3603e30688ace84ea638fbcf485ca55ddcfd6fbe90609d4f3ed"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_Remcos.yar"
		repository = "elastic/protections-artifacts"
		source_url = "https://github.com/elastic/protections-artifacts/blob/3bbef930abab9814b2fdb4704be075ab1daf2ea0/yara/rules/Windows_Trojan_Remcos.yar"
		score = 75

	strings:
		$a1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 52 65 6d 63 6f 73 20 72 65 73 74 61 72 74 65 64 20 62 79 20 77 61 74 63 68 64 6f 67 21 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$a2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 4d 75 74 65 78 5f 52 65 6d 57 61 74 63 68 64 6f 67 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$a3 = {25 30 32 69 3a 25 30 32 69 3a 25 30 32 69 3a 25 30 33 69}
		$a4 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 2a 20 52 65 6d 63 6f 73 20 76 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		2 of them
}

rule Windows_Trojan_Remcos_7591e9f1 : hardened limited
{
	meta:
		author = "Elastic Security"
		id = "7591e9f1-452d-4731-9bec-545fb0272c80"
		fingerprint = "9436c314f89a09900a9b3c2fd9bab4a0423912427cf47b71edce5eba31132449"
		creation_date = "2023-06-23"
		last_modified = "2023-07-10"
		threat_name = "Windows.Trojan.Remcos"
		reference = "https://www.elastic.co/security-labs/exploring-the-ref2731-intrusion-set"
		reference_sample = "4e6e5ecd1cf9c88d536c894d74320c77967fe08c75066098082bf237283842fa"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_Remcos.yar"
		repository = "elastic/protections-artifacts"
		source_url = "https://github.com/elastic/protections-artifacts/blob/3bbef930abab9814b2fdb4704be075ab1daf2ea0/yara/rules/Windows_Trojan_Remcos.yar"
		score = 75

	strings:
		$a1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 53 65 72 76 52 65 6d (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$a2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 53 63 72 65 65 6e 73 68 6f 74 73 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$a3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 4d 69 63 52 65 63 6f 72 64 73 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$a4 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 72 00 65 00 6d 00 63 00 6f 00 73 00 2e 00 65 00 78 00 65 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$a5 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 52 00 65 00 6d 00 63 00 6f 00 73 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$a6 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 6c 00 6f 00 67 00 73 00 2e 00 64 00 61 00 74 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}

	condition:
		3 of them
}

rule malware_Remcos_strings : hardened loosened limited
{
	meta:
		description = "detect Remcos in memory"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "memory scan"
		hash1 = "7d5efb7e8b8947e5fe1fa12843a2faa0ebdfd7137582e5925a0b9c6a9350b0a5"
		ruleset = "Remcos.yara"
		repository = "JPCERTCC/jpcert-yara"
		source_url = "https://github.com/JPCERTCC/jpcert-yara/blob/0722a9365ec6bc969c517c623cd166743d1bc473/other/Remcos.yara"
		license = "Other"
		score = 75

	strings:
		$remcos = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 52 65 6d 63 6f 73 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$url1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 42 72 65 61 6b 69 6e 67 2d 53 65 63 75 72 69 74 79 2e 4e 65 74 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$url2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 42 72 65 61 6b 69 6e 67 53 65 63 75 72 69 74 79 2e 4e 65 74 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$resource = {((53 45 54 54 49 4e 47 53) | (53 00 45 00 54 00 54 00 49 00 4e 00 47 00 53 00))}

	condition:
		1 of ( $url* ) and $remcos and $resource
}

rule win_remcos_auto : hardened
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.remcos."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.remcos"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		ruleset = "win.remcos_auto.yar"
		repository = "malpedia/signator-rules"
		source_url = "https://github.com/malpedia/signator-rules/blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.remcos_auto.yar"
		score = 75

	strings:
		$sequence_0 = { 7410 6a00 ff35???????? ff15???????? }
		$sequence_1 = { 50 ff15???????? 8d45f0 33f6 }
		$sequence_2 = { 6a09 ff35???????? ff15???????? ff35???????? ff15???????? }
		$sequence_3 = { 8d45f8 50 ff15???????? ff7508 }
		$sequence_4 = { 7508 ff15???????? 33c0 5f }
		$sequence_5 = { 6a09 ff35???????? ff15???????? ff35???????? }
		$sequence_6 = { ff15???????? 50 ff15???????? 8d45f0 33f6 }
		$sequence_7 = { 50 6a28 ff15???????? 50 ff15???????? 8d45f0 33f6 }
		$sequence_8 = { 51 51 8d45f8 c745f808000000 50 ff15???????? ff15???????? }
		$sequence_9 = { 85c0 7410 6a00 ff35???????? ff15???????? }

	condition:
		7 of them and filesize < 1054720
}

rule Remcos_1 : hardened
{
	meta:
		author = "@neonprimetime"
		description = "Remcos RAT"
		original_yara_name = "Remcos"
		ruleset = "remcos.yar"
		repository = "kevthehermit/RATDecoders"
		source_url = "https://github.com/kevthehermit/RATDecoders/blob/d675ba1c06e6dd8365149c9ee8a8db1a6e5e508e/malwareconfig/yaraRules/remcos.yar"
		license = "MIT License"
		score = 75

	strings:
		$a1 = {53 6f 66 74 77 61 72 65 5c 52 65 6d 63 6f 73}
		$a2 = {5c 72 65 6d 63 6f 73 5c}
		$a3 = {52 45 4d 43 4f 53 20 76}
		$b1 = {4b 65 79 6c 6f 67 67 65 72 20 53 74 61 72 74 65 64}
		$b2 = {43 6f 6e 6e 65 63 74 65 64 20 74 6f 20 43 26 43}
		$b3 = {53 63 72 65 65 6e 73 68 6f 74 73}
		$b4 = {4f 70 65 6e 43 61 6d 65 72 61}
		$b5 = {55 70 6c 6f 61 64 69 6e 67 20 66 69 6c 65 20 74 6f 20 43 26 43}
		$b6 = {49 6e 69 74 69 61 6c 69 7a 69 6e 67 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 74 6f 20 43 26 43}
		$b7 = {63 6c 65 61 72 65 64 21 5d}
		$b8 = {45 6e 61 62 6c 65 4c 55 41 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 30}
		$b9 = {55 70 6c 6f 61 64 69 6e 67 20 66 69 6c 65 20 74 6f 20 43 26 43}
		$b10 = {25 30 32 69 3a 25 30 32 69 3a 25 30 32 69 3a 25 30 33 69}
		$b11 = {5b 46 69 72 65 66 6f 78 20 53 74 6f 72 65 64 4c 6f 67 69 6e 73 20 43 6c 65 61 72 65 64 21 5d}
		$b12 = {6c 69 63 65 6e 63 65 5f 63 6f 64 65 2e 74 78 74}

	condition:
		1 of ( $a* ) or 3 of ( $b* )
}

rule MAL_Remcos_strings : hardened
{
	meta:
		description = "Matches strings found in Remcos RAT samples."
		last_modified = "2024-03-20"
		author = "@petermstewart"
		DaysofYara = "80/100"
		sha256 = "b3d7fad59a0ae75ffef9e05f47fc381b4adb716c498106482492e56c1b4370a7"
		sha256 = "9046b2e6ce92647474048c30439ab21ee69a46f6067dbaff67de729644120fad"
		ruleset = "MAL_C2_Remcos.yar"
		repository = "100DaysofYARA/2024"
		source_url = "https://github.com/100DaysofYARA/2024/blob/7df92fafb900e3f148d927ac8dd68bfeaea0c332/petermstewart/MAL_C2_Remcos.yar"
		license = "MIT License"
		score = 75

	strings:
		$a = {52 65 6d 63 6f 73 5f 4d 75 74 65 78 5f 49 6e 6a}
		$b1 = {55 70 6c 6f 61 64 69 6e 67 20 66 69 6c 65 20 74 6f 20 43 26 43 3a 20}
		$b2 = {55 6e 61 62 6c 65 20 74 6f 20 64 65 6c 65 74 65 3a 20}
		$b3 = {55 6e 61 62 6c 65 20 74 6f 20 72 65 6e 61 6d 65 20 66 69 6c 65 21}
		$b4 = {42 72 6f 77 73 69 6e 67 20 64 69 72 65 63 74 6f 72 79 3a 20}
		$b5 = {4f 66 66 6c 69 6e 65 20 4b 65 79 6c 6f 67 67 65 72 20 53 74 61 72 74 65 64}
		$b6 = {4f 6e 6c 69 6e 65 20 4b 65 79 6c 6f 67 67 65 72 20 53 74 61 72 74 65 64}
		$b7 = {5b 43 68 72 6f 6d 65 20 53 74 6f 72 65 64 4c 6f 67 69 6e 73 20 66 6f 75 6e 64 2c 20 63 6c 65 61 72 65 64 21 5d}
		$b8 = {5b 46 69 72 65 66 6f 78 20 53 74 6f 72 65 64 4c 6f 67 69 6e 73 20 63 6c 65 61 72 65 64 21 5d}
		$b9 = {43 6c 65 61 72 65 64 20 61 6c 6c 20 62 72 6f 77 73 65 72 20 63 6f 6f 6b 69 65 73 2c 20 6c 6f 67 69 6e 73 20 61 6e 64 20 70 61 73 73 77 6f 72 64 73 2e}
		$b10 = {5b 46 6f 6c 6c 6f 77 69 6e 67 20 74 65 78 74 20 68 61 73 20 62 65 65 6e 20 70 61 73 74 65 64 20 66 72 6f 6d 20 63 6c 69 70 62 6f 61 72 64 3a 5d}
		$b11 = {5b 45 6e 64 20 6f 66 20 63 6c 69 70 62 6f 61 72 64 20 74 65 78 74 5d}
		$b12 = {4f 70 65 6e 43 61 6d 65 72 61}
		$b13 = {43 6c 6f 73 65 43 61 6d 65 72 61}

	condition:
		uint16( 0 ) == 0x5a4d and $a and 10 of ( $b* )
}

rule malware_windows_remcos_rat : hardened
{
	meta:
		description = "https://blog.fortinet.com/2017/02/14/remcos-a-new-rat-in-the-wild-2"
		reference = "https://breaking-security.net/remcos/remcos-changelog/"
		author = "@mimeframe"
		md5 = "c8dafe143fe1d81ae6a3c0cd4724b272"
		ruleset = "malware_windows_remcos_rat.yara"
		repository = "airbnb/binaryalert"
		source_url = "https://github.com/airbnb/binaryalert/blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/malware/windows/malware_windows_remcos_rat.yara"
		license = "Apache License 2.0"
		score = 75

	strings:
		$a1 = {((5b 46 6f 6c 6c 6f 77 69 6e 67 20 74 65 78 74 20 68 61 73 20 62 65 65 6e 20 70 61 73 74 65 64 20 66 72 6f 6d 20 63 6c 69 70 62 6f 61 72 64 3a 5d) | (5b 00 46 00 6f 00 6c 00 6c 00 6f 00 77 00 69 00 6e 00 67 00 20 00 74 00 65 00 78 00 74 00 20 00 68 00 61 00 73 00 20 00 62 00 65 00 65 00 6e 00 20 00 70 00 61 00 73 00 74 00 65 00 64 00 20 00 66 00 72 00 6f 00 6d 00 20 00 63 00 6c 00 69 00 70 00 62 00 6f 00 61 00 72 00 64 00 3a 00 5d 00))}
		$a2 = {((5b 43 68 72 6f 6d 65 20 53 74 6f 72 65 64 4c 6f 67 69 6e 73 20 66 6f 75 6e 64 2c 20 63 6c 65 61 72 65 64 21 5d) | (5b 00 43 00 68 00 72 00 6f 00 6d 00 65 00 20 00 53 00 74 00 6f 00 72 00 65 00 64 00 4c 00 6f 00 67 00 69 00 6e 00 73 00 20 00 66 00 6f 00 75 00 6e 00 64 00 2c 00 20 00 63 00 6c 00 65 00 61 00 72 00 65 00 64 00 21 00 5d 00))}
		$a3 = {((5b 46 69 72 65 66 6f 78 20 53 74 6f 72 65 64 4c 6f 67 69 6e 73 20 63 6c 65 61 72 65 64 21 5d) | (5b 00 46 00 69 00 72 00 65 00 66 00 6f 00 78 00 20 00 53 00 74 00 6f 00 72 00 65 00 64 00 4c 00 6f 00 67 00 69 00 6e 00 73 00 20 00 63 00 6c 00 65 00 61 00 72 00 65 00 64 00 21 00 5d 00))}
		$b1 = {((67 65 74 63 6c 69 70 62 6f 61 72 64) | (67 00 65 00 74 00 63 00 6c 00 69 00 70 00 62 00 6f 00 61 00 72 00 64 00))}
		$b2 = {((73 74 6f 70 6d 69 63 63 61 70 74 75 72 65) | (73 00 74 00 6f 00 70 00 6d 00 69 00 63 00 63 00 61 00 70 00 74 00 75 00 72 00 65 00))}
		$b3 = {((64 6f 77 6e 6c 6f 61 64 66 72 6f 6d 75 72 6c 74 6f 66 69 6c 65) | (64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 66 00 72 00 6f 00 6d 00 75 00 72 00 6c 00 74 00 6f 00 66 00 69 00 6c 00 65 00))}
		$b4 = {((67 65 74 63 61 6d 73 69 6e 67 6c 65 66 72 61 6d 65) | (67 00 65 00 74 00 63 00 61 00 6d 00 73 00 69 00 6e 00 67 00 6c 00 65 00 66 00 72 00 61 00 6d 00 65 00))}
		$c1 = {((42 72 65 61 6b 69 6e 67 2d 53 65 63 75 72 69 74 79 2e 4e 65 74) | (42 00 72 00 65 00 61 00 6b 00 69 00 6e 00 67 00 2d 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 2e 00 4e 00 65 00 74 00))}
		$c2 = {((52 45 4d 43 4f 53 20 76) | (52 00 45 00 4d 00 43 00 4f 00 53 00 20 00 76 00))}

	condition:
		any of ( $a* ) or 3 of ( $b* ) or all of ( $c* )
}

rule win_remcos_rat_unpacked : hardened
{
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/08/27"
		description = "Detects strings present in remcos rat Samples."
		sha_256 = "ec901217558e77f2f449031a6a1190b1e99b30fa1bb8d8dabc3a99bc69833784"
		ruleset = "win_remcos_rat_unpacked_aug_2023.yar"
		repository = "embee-research/Yara-detection-rules"
		source_url = "https://github.com/embee-research/Yara-detection-rules/blob/ac56d6f6fd2a30c8cb6e5c0455d6519210a8b0f4/Rules/win_remcos_rat_unpacked_aug_2023.yar"
		score = 75

	strings:
		$r0 = {20 5f 5f 5f 5f 5f 5f 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20}
		$r1 = {28 5f 5f 5f 5f 5f 20 5c 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20}
		$r2 = {20 5f 5f 5f 5f 5f 29 20 29 5f 5f 5f 5f 5f 20 5f 5f 5f 5f 20 20 20 5f 5f 5f 5f 20 5f 5f 5f 20 20 20 5f 5f 5f 20}
		$r3 = {7c 20 20 5f 5f 20 20 2f 7c 20 5f 5f 5f 20 7c 20 20 20 20 5c 20 2f 20 5f 5f 5f 29 20 5f 20 5c 20 2f 5f 5f 5f 29}
		$r4 = {7c 20 7c 20 20 5c 20 5c 7c 20 5f 5f 5f 5f 7c 20 7c 20 7c 20 28 20 28 5f 5f 7c 20 7c 5f 7c 20 7c 5f 5f 5f 20 7c}
		$r5 = {7c 5f 7c 20 20 20 7c 5f 7c 5f 5f 5f 5f 5f 29 5f 7c 5f 7c 5f 7c 5c 5f 5f 5f 5f 29 5f 5f 5f 2f 28 5f 5f 5f 2f 20}
		$s1 = {57 61 74 63 68 64 6f 67 20 6d 6f 64 75 6c 65 20 61 63 74 69 76 61 74 65 64}
		$s2 = {52 65 6d 63 6f 73 20 72 65 73 74 61 72 74 65 64 20 62 79 20 77 61 74 63 68 64 6f 67 21}
		$s3 = {20 42 72 65 61 6b 69 6e 67 53 65 63 75 72 69 74 79 2e 6e 65 74}

	condition:
		(( all of ( $r* ) ) or ( all of ( $s* ) ) )
}

rule Remcos_2 : hardened limited
{
	meta:
		description = "detect Remcos in memory"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "memory scan"
		hash1 = "7d5efb7e8b8947e5fe1fa12843a2faa0ebdfd7137582e5925a0b9c6a9350b0a5"
		original_yara_name = "Remcos"
		ruleset = "MalConfScan.yar"
		repository = "Yara-Rules/rules"
		source_url = "https://github.com/Yara-Rules/rules/blob/0f93570194a80d2f2032869055808b0ddcdfb360/malware/MalConfScan.yar"
		license = "GNU General Public License v2.0"
		score = 75

	strings:
		$remcos = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 52 65 6d 63 6f 73 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$url = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 42 72 65 61 6b 69 6e 67 2d 53 65 63 75 72 69 74 79 2e 4e 65 74 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$resource = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 53 00 45 00 54 00 54 00 49 00 4e 00 47 00 53 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}

	condition:
		all of them
}

rule win_remcos : rat hardened
{
	meta:
		author = "CERT Polska"

	strings:
		$convenient1 = {20 2a 20 42 72 65 61 6b 69 6e 67 2d 53 65 63 75 72 69 74 79 2e 4e 65 74}
		$convenient2 = {20 2a 20 52 45 4d 43 4f 53 20 76}
		$convenient3 = {53 45 54 54 49 4e 47 53}
		$convenient4 = {52 65 6d 63 6f 73 5f 4d 75 74 65 78 5f 49 6e 6a}
		$convenient5 = {4f 6e 6c 69 6e 65 20 4b 65 79 6c 6f 67 67 65 72 20 53 74 61 72 74 65 64}
		$convenient6 = {55 70 6c 6f 61 64 69 6e 67 20 66 69 6c 65 20 74 6f 20 43 26 43}
		$convenient7 = {52 65 6d 63 6f 73 20 41 67 65 6e 74 20 69 6e 69 74 69 61 6c 69 7a 65 64}

	condition:
		3 of ( $convenient* )
}

rule win_remcos_auto_1 : hardened
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2019-07-05"
		version = "1"
		description = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator 0.2a"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.remcos"
		malpedia_version = "20190620"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		score = 75

	strings:
		$sequence_0 = { 51 50 8bce e8???????? 8b4608 ff7510 2b4508 }
		$sequence_1 = { ff35???????? ff15???????? eb?? 6a09 ff35???????? ff15???????? ff35???????? }
		$sequence_2 = { ff15???????? 57 57 57 8bd8 57 6a02 }
		$sequence_3 = { ff7114 e8???????? 5d c3 55 8bec }
		$sequence_4 = { 75?? 6a01 58 5d c3 8b4028 6a00 }
		$sequence_5 = { 8d45f0 50 ff15???????? 8d4df0 ff15???????? 8b4508 5e }
		$sequence_6 = { 50 e8???????? 834608f4 8bc7 5f 5e 5d }
		$sequence_7 = { 6a00 ff7508 ffd6 50 ff15???????? 50 }
		$sequence_8 = { c3 ff7510 ff750c ff15???????? f7d8 1ac0 fec0 }
		$sequence_9 = { e9???????? 55 8bec 51 56 8bf1 8d45ff }

	condition:
		7 of them
}

rule fsRemcos : hardened
{
	meta:
		description = "FsYARA - Malware Trends"
		vetted_family = "remcos"
		score = 75

	condition:
		Remcos or Windows_Trojan_Remcos_b296e965 or Windows_Trojan_Remcos_7591e9f1 or malware_Remcos_strings or win_remcos_auto or Remcos_1 or MAL_Remcos_strings or malware_windows_remcos_rat or win_remcos_rat_unpacked or Remcos_2 or win_remcos or win_remcos_auto_1
}

