rule RedLine : hardened
{
	meta:
		description = "Identifies RedLine stealer."
		author = "@bartblaze"
		date = "2021-06"
		tlp = "White"
		ruleset = "RedLine.yar"
		repository = "kevthehermit/RATDecoders"
		source_url = "https://github.com/kevthehermit/RATDecoders/blob/d675ba1c06e6dd8365149c9ee8a8db1a6e5e508e/malwareconfig/yaraRules/RedLine.yar"
		license = "MIT License"
		score = 75

	strings:
		$ = {((41 63 63 6f 75 6e 74) | (41 00 63 00 63 00 6f 00 75 00 6e 00 74 00))}
		$ = {((41 6c 6c 57 61 6c 6c 65 74 73 52 75 6c 65) | (41 00 6c 00 6c 00 57 00 61 00 6c 00 6c 00 65 00 74 00 73 00 52 00 75 00 6c 00 65 00))}
		$ = {((41 72 6d 6f 72 79 52 75 6c 65) | (41 00 72 00 6d 00 6f 00 72 00 79 00 52 00 75 00 6c 00 65 00))}
		$ = {((41 74 6f 6d 69 63 52 75 6c 65) | (41 00 74 00 6f 00 6d 00 69 00 63 00 52 00 75 00 6c 00 65 00))}
		$ = {((41 75 74 6f 66 69 6c 6c) | (41 00 75 00 74 00 6f 00 66 00 69 00 6c 00 6c 00))}
		$ = {((42 72 6f 77 73 65 72 45 78 74 65 6e 73 69 6f 6e 73 52 75 6c 65) | (42 00 72 00 6f 00 77 00 73 00 65 00 72 00 45 00 78 00 74 00 65 00 6e 00 73 00 69 00 6f 00 6e 00 73 00 52 00 75 00 6c 00 65 00))}
		$ = {((42 72 6f 77 73 65 72 56 65 72 73 69 6f 6e) | (42 00 72 00 6f 00 77 00 73 00 65 00 72 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00))}
		$ = {((43 68 72 6f 6d 65) | (43 00 68 00 72 00 6f 00 6d 00 65 00))}
		$ = {((43 6f 69 6e 6f 6d 69 52 75 6c 65) | (43 00 6f 00 69 00 6e 00 6f 00 6d 00 69 00 52 00 75 00 6c 00 65 00))}
		$ = {((43 6f 6d 6d 61 6e 64 4c 69 6e 65 55 70 64 61 74 65) | (43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 4c 00 69 00 6e 00 65 00 55 00 70 00 64 00 61 00 74 00 65 00))}
		$ = {((43 72 79 70 74 6f 48 65 6c 70 65 72) | (43 00 72 00 79 00 70 00 74 00 6f 00 48 00 65 00 6c 00 70 00 65 00 72 00))}
		$ = {((43 72 79 70 74 6f 50 72 6f 76 69 64 65 72) | (43 00 72 00 79 00 70 00 74 00 6f 00 50 00 72 00 6f 00 76 00 69 00 64 00 65 00 72 00))}
		$ = {((44 61 74 61 42 61 73 65 43 6f 6e 6e 65 63 74 69 6f 6e) | (44 00 61 00 74 00 61 00 42 00 61 00 73 00 65 00 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6f 00 6e 00))}
		$ = {((44 65 73 6b 74 6f 70 4d 65 73 73 61 6e 67 65 72 52 75 6c 65) | (44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 4d 00 65 00 73 00 73 00 61 00 6e 00 67 00 65 00 72 00 52 00 75 00 6c 00 65 00))}
		$ = {((44 69 73 63 6f 72 64 52 75 6c 65) | (44 00 69 00 73 00 63 00 6f 00 72 00 64 00 52 00 75 00 6c 00 65 00))}
		$ = {((44 69 73 70 6c 61 79 48 65 6c 70 65 72) | (44 00 69 00 73 00 70 00 6c 00 61 00 79 00 48 00 65 00 6c 00 70 00 65 00 72 00))}
		$ = {((44 6f 77 6e 6c 6f 61 64 41 6e 64 45 78 65 63 75 74 65 55 70 64 61 74 65) | (44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 41 00 6e 00 64 00 45 00 78 00 65 00 63 00 75 00 74 00 65 00 55 00 70 00 64 00 61 00 74 00 65 00))}
		$ = {((44 6f 77 6e 6c 6f 61 64 55 70 64 61 74 65) | (44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 55 00 70 00 64 00 61 00 74 00 65 00))}
		$ = {((45 6c 65 63 74 72 75 6d 52 75 6c 65) | (45 00 6c 00 65 00 63 00 74 00 72 00 75 00 6d 00 52 00 75 00 6c 00 65 00))}
		$ = {((45 6e 64 70 6f 69 6e 74 43 6f 6e 6e 65 63 74 69 6f 6e) | (45 00 6e 00 64 00 70 00 6f 00 69 00 6e 00 74 00 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6f 00 6e 00))}
		$ = {((45 74 68 52 75 6c 65) | (45 00 74 00 68 00 52 00 75 00 6c 00 65 00))}
		$ = {((45 78 6f 64 75 73 52 75 6c 65) | (45 00 78 00 6f 00 64 00 75 00 73 00 52 00 75 00 6c 00 65 00))}
		$ = {((45 78 74 65 6e 73 69 6f 6e 73) | (45 00 78 00 74 00 65 00 6e 00 73 00 69 00 6f 00 6e 00 73 00))}
		$ = {((46 69 6c 65 43 6f 70 69 65 72) | (46 00 69 00 6c 00 65 00 43 00 6f 00 70 00 69 00 65 00 72 00))}
		$ = {((46 69 6c 65 53 63 61 6e 6e 65 72) | (46 00 69 00 6c 00 65 00 53 00 63 00 61 00 6e 00 6e 00 65 00 72 00))}
		$ = {((46 69 6c 65 53 63 61 6e 6e 65 72 41 72 67) | (46 00 69 00 6c 00 65 00 53 00 63 00 61 00 6e 00 6e 00 65 00 72 00 41 00 72 00 67 00))}
		$ = {((46 69 6c 65 53 63 61 6e 6e 65 72 52 75 6c 65) | (46 00 69 00 6c 00 65 00 53 00 63 00 61 00 6e 00 6e 00 65 00 72 00 52 00 75 00 6c 00 65 00))}
		$ = {((46 69 6c 65 5a 69 6c 6c 61) | (46 00 69 00 6c 00 65 00 5a 00 69 00 6c 00 6c 00 61 00))}
		$ = {((47 61 6d 65 4c 61 75 6e 63 68 65 72 52 75 6c 65) | (47 00 61 00 6d 00 65 00 4c 00 61 00 75 00 6e 00 63 00 68 00 65 00 72 00 52 00 75 00 6c 00 65 00))}
		$ = {((47 65 63 6b 6f) | (47 00 65 00 63 00 6b 00 6f 00))}
		$ = {((47 65 6f 48 65 6c 70 65 72) | (47 00 65 00 6f 00 48 00 65 00 6c 00 70 00 65 00 72 00))}
		$ = {((47 65 6f 49 6e 66 6f) | (47 00 65 00 6f 00 49 00 6e 00 66 00 6f 00))}
		$ = {((47 65 6f 50 6c 75 67 69 6e) | (47 00 65 00 6f 00 50 00 6c 00 75 00 67 00 69 00 6e 00))}
		$ = {((47 75 61 72 64 61 52 75 6c 65) | (47 00 75 00 61 00 72 00 64 00 61 00 52 00 75 00 6c 00 65 00))}
		$ = {((48 61 72 64 77 61 72 65 54 79 70 65) | (48 00 61 00 72 00 64 00 77 00 61 00 72 00 65 00 54 00 79 00 70 00 65 00))}
		$ = {((49 70 53 62) | (49 00 70 00 53 00 62 00))}
		$ = {((49 52 65 6d 6f 74 65 45 6e 64 70 6f 69 6e 74) | (49 00 52 00 65 00 6d 00 6f 00 74 00 65 00 45 00 6e 00 64 00 70 00 6f 00 69 00 6e 00 74 00))}
		$ = {((49 54 61 73 6b 50 72 6f 63 65 73 73 6f 72) | (49 00 54 00 61 00 73 00 6b 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 6f 00 72 00))}
		$ = {((4a 61 78 78 52 75 6c 65) | (4a 00 61 00 78 00 78 00 52 00 75 00 6c 00 65 00))}
		$ = {((4e 6f 72 64 41 70 70) | (4e 00 6f 00 72 00 64 00 41 00 70 00 70 00))}
		$ = {((4f 70 65 6e 55 70 64 61 74 65) | (4f 00 70 00 65 00 6e 00 55 00 70 00 64 00 61 00 74 00 65 00))}
		$ = {((4f 70 65 6e 56 50 4e 52 75 6c 65) | (4f 00 70 00 65 00 6e 00 56 00 50 00 4e 00 52 00 75 00 6c 00 65 00))}
		$ = {((4f 73 43 72 79 70 74) | (4f 00 73 00 43 00 72 00 79 00 70 00 74 00))}
		$ = {((50 72 6f 67 72 61 6d) | (50 00 72 00 6f 00 67 00 72 00 61 00 6d 00))}
		$ = {((50 72 6f 67 72 61 6d 4d 61 69 6e) | (50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 4d 00 61 00 69 00 6e 00))}
		$ = {((50 72 6f 74 6f 6e 56 50 4e 52 75 6c 65) | (50 00 72 00 6f 00 74 00 6f 00 6e 00 56 00 50 00 4e 00 52 00 75 00 6c 00 65 00))}
		$ = {((52 65 63 6f 72 64 48 65 61 64 65 72 46 69 65 6c 64) | (52 00 65 00 63 00 6f 00 72 00 64 00 48 00 65 00 61 00 64 00 65 00 72 00 46 00 69 00 65 00 6c 00 64 00))}
		$ = {((52 65 63 6f 75 72 73 69 76 65 46 69 6c 65 47 72 61 62 62 65 72) | (52 00 65 00 63 00 6f 00 75 00 72 00 73 00 69 00 76 00 65 00 46 00 69 00 6c 00 65 00 47 00 72 00 61 00 62 00 62 00 65 00 72 00))}
		$ = {((52 65 73 75 6c 74 46 61 63 74 6f 72 79) | (52 00 65 00 73 00 75 00 6c 00 74 00 46 00 61 00 63 00 74 00 6f 00 72 00 79 00))}
		$ = {((53 63 61 6e 44 65 74 61 69 6c 73) | (53 00 63 00 61 00 6e 00 44 00 65 00 74 00 61 00 69 00 6c 00 73 00))}
		$ = {((53 63 61 6e 6e 65 64 42 72 6f 77 73 65 72) | (53 00 63 00 61 00 6e 00 6e 00 65 00 64 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00))}
		$ = {((53 63 61 6e 6e 65 64 43 6f 6f 6b 69 65) | (53 00 63 00 61 00 6e 00 6e 00 65 00 64 00 43 00 6f 00 6f 00 6b 00 69 00 65 00))}
		$ = {((53 63 61 6e 6e 65 64 46 69 6c 65) | (53 00 63 00 61 00 6e 00 6e 00 65 00 64 00 46 00 69 00 6c 00 65 00))}
		$ = {((53 63 61 6e 6e 69 6e 67 41 72 67 73) | (53 00 63 00 61 00 6e 00 6e 00 69 00 6e 00 67 00 41 00 72 00 67 00 73 00))}
		$ = {((53 63 61 6e 52 65 73 75 6c 74) | (53 00 63 00 61 00 6e 00 52 00 65 00 73 00 75 00 6c 00 74 00))}
		$ = {((53 71 6c 69 74 65 4d 61 73 74 65 72 45 6e 74 72 79) | (53 00 71 00 6c 00 69 00 74 00 65 00 4d 00 61 00 73 00 74 00 65 00 72 00 45 00 6e 00 74 00 72 00 79 00))}
		$ = {((53 74 72 69 6e 67 44 65 63 72 79 70 74) | (53 00 74 00 72 00 69 00 6e 00 67 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00))}
		$ = {((53 79 73 74 65 6d 48 61 72 64 77 61 72 65) | (53 00 79 00 73 00 74 00 65 00 6d 00 48 00 61 00 72 00 64 00 77 00 61 00 72 00 65 00))}
		$ = {((53 79 73 74 65 6d 49 6e 66 6f 48 65 6c 70 65 72) | (53 00 79 00 73 00 74 00 65 00 6d 00 49 00 6e 00 66 00 6f 00 48 00 65 00 6c 00 70 00 65 00 72 00))}
		$ = {((54 61 62 6c 65 45 6e 74 72 79) | (54 00 61 00 62 00 6c 00 65 00 45 00 6e 00 74 00 72 00 79 00))}
		$ = {((54 61 73 6b 52 65 73 6f 6c 76 65 72) | (54 00 61 00 73 00 6b 00 52 00 65 00 73 00 6f 00 6c 00 76 00 65 00 72 00))}
		$ = {((55 70 64 61 74 65 41 63 74 69 6f 6e) | (55 00 70 00 64 00 61 00 74 00 65 00 41 00 63 00 74 00 69 00 6f 00 6e 00))}
		$ = {((55 70 64 61 74 65 54 61 73 6b) | (55 00 70 00 64 00 61 00 74 00 65 00 54 00 61 00 73 00 6b 00))}
		$ = {((58 4d 52 52 75 6c 65) | (58 00 4d 00 52 00 52 00 75 00 6c 00 65 00))}

	condition:
		45 of them
}

rule redline_payload : hardened limited
{
	meta:
		description = "Rule to detect the RedLine payload"
		author = "Marc Rivero | McAfee ATR Team"
		date = "2020-04-16"
		rule_version = "v1"
		malware_type = "backdoor"
		malware_family = "Backdoor:W32/RedLine"
		actor_type = "Cybercrime"
		actor_group = "Unknown"
		reference = "https://www.proofpoint.com/us/threat-insight/post/new-redline-stealer-distributed-using-coronavirus-themed-email-campaign"
		hash = "5df956f08d6ad0559efcdb7b7a59b2f3b95dee9e2aa6b76602c46e2aba855eff"
		ruleset = "MALW_redline.yar"
		repository = "advanced-threat-research/Yara-Rules"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules/blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/malware/MALW_redline.yar"
		license = "Apache License 2.0"
		score = 75

	strings:
		$s1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 43 61 6d 62 72 65 6c 2e 65 78 65 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s2 = { 22 00 54 00 65 00 78 00 74 00 49 00 6e 00 70 00 75 00 74 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 2e 00 44 00 59 00 4e 00 4c 00 49 00 4e 00 4b 00 22 00 }
		$op0 = { 06 7c 34 00 00 04 7b 17 00 00 04 7e 21 00 00 0a }
		$op1 = { 96 00 92 0e 83 02 02 00 f4 20 }
		$op2 = { 03 00 c6 01 d9 08 1b 03 44 }
		$p0 = { 80 00 96 20 83 11 b7 02 10 }
		$p1 = { 20 01 00 72 0f 00 20 02 00 8a 0f 00 20 03 00 61 }
		$p2 = { 03 00 c6 01 cd 06 13 03 79 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 60KB and all of ( $s* ) and all of ( $op* ) or all of ( $p* )
}

rule Windows_Trojan_RedLineStealer_17ee6a17 : hardened limited
{
	meta:
		author = "Elastic Security"
		id = "17ee6a17-161e-454a-baf1-2734995c82cd"
		fingerprint = "a1f75937e83f72f61e027a1045374d3bd17cd387b223a6909b9aed52d2bc2580"
		creation_date = "2021-06-12"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.RedLineStealer"
		reference_sample = "497bc53c1c75003fe4ae3199b0ff656c085f21dffa71d00d7a3a33abce1a3382"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_RedLineStealer.yar"
		repository = "elastic/protections-artifacts"
		source_url = "https://github.com/elastic/protections-artifacts/blob/3bbef930abab9814b2fdb4704be075ab1daf2ea0/yara/rules/Windows_Trojan_RedLineStealer.yar"
		score = 75

	strings:
		$a1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 52 65 64 4c 69 6e 65 2e 4c 6f 67 69 63 2e 53 51 4c 69 74 65 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$a2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 52 65 64 4c 69 6e 65 2e 52 65 62 75 72 6e 2e 44 61 74 61 2e 42 72 6f 77 73 65 72 73 2e 47 65 63 6b 6f (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$a3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 52 65 64 4c 69 6e 65 2e 43 6c 69 65 6e 74 2e 4d 6f 64 65 6c 73 2e 47 65 63 6b 6f (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$b1 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 57 00 68 00 65 00 72 00 65 00 20 00 53 00 65 00 73 00 73 00 69 00 6f 00 6e 00 49 00 64 00 3d 00 27 00 7b 00 30 00 7d 00 27 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$b2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 67 65 74 5f 65 6e 63 72 79 70 74 65 64 55 73 65 72 6e 61 6d 65 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$b3 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 69 00 63 00 61 00 6e 00 68 00 61 00 7a 00 69 00 70 00 2e 00 63 00 6f 00 6d 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$b4 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 47 65 74 50 72 69 76 61 74 65 33 4b 65 79 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$b5 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 67 65 74 5f 47 72 61 62 54 65 6c 65 67 72 61 6d (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$b6 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 3c 47 72 61 62 55 73 65 72 41 67 65 6e 74 3e 6b 5f 5f 42 61 63 6b 69 6e 67 46 69 65 6c 64 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		1 of ( $a* ) or all of ( $b* )
}

rule Windows_Trojan_RedLineStealer_f54632eb : hardened limited
{
	meta:
		author = "Elastic Security"
		id = "f54632eb-2c66-4aff-802d-ad1c076e5a5e"
		fingerprint = "6a9d45969c4d58181fca50d58647511b68c1e6ee1eeac2a1838292529505a6a0"
		creation_date = "2021-06-12"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.RedLineStealer"
		reference_sample = "d82ad08ebf2c6fac951aaa6d96bdb481aa4eab3cd725ea6358b39b1045789a25"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_RedLineStealer.yar"
		repository = "elastic/protections-artifacts"
		source_url = "https://github.com/elastic/protections-artifacts/blob/3bbef930abab9814b2fdb4704be075ab1daf2ea0/yara/rules/Windows_Trojan_RedLineStealer.yar"
		score = 75

	strings:
		$a1 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 74 00 74 00 70 00 3a 00 2f 00 2f 00 63 00 68 00 65 00 63 00 6b 00 69 00 70 00 2e 00 61 00 6d 00 61 00 7a 00 6f 00 6e 00 61 00 77 00 73 00 2e 00 63 00 6f 00 6d 00 2f 00 6c 00 6f 00 67 00 69 00 6e 00 73 00 2e 00 6a 00 73 00 6f 00 6e 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$a2 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 69 00 70 00 69 00 6e 00 66 00 6f 00 2e 00 69 00 6f 00 2f 00 69 00 70 00 25 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 25 00 5c 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$a3 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 56 00 61 00 6c 00 76 00 65 00 5c 00 53 00 74 00 65 00 61 00 6d 00 4c 00 6f 00 67 00 69 00 6e 00 20 00 44 00 61 00 74 00 61 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$a4 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 67 65 74 5f 53 63 61 6e 6e 65 64 57 61 6c 6c 65 74 73 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$a5 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 67 65 74 5f 53 63 61 6e 54 65 6c 65 67 72 61 6d (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$a6 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 67 65 74 5f 53 63 61 6e 47 65 63 6b 6f 42 72 6f 77 73 65 72 73 50 61 74 68 73 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$a7 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 3c 50 72 6f 63 65 73 73 65 73 3e 6b 5f 5f 42 61 63 6b 69 6e 67 46 69 65 6c 64 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$a8 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 3c 47 65 74 57 69 6e 64 6f 77 73 56 65 72 73 69 6f 6e 3e 67 5f 5f 48 4b 4c 4d 5f 47 65 74 53 74 72 69 6e 67 7c 31 31 5f 30 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$a9 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 3c 53 63 61 6e 46 54 50 3e 6b 5f 5f 42 61 63 6b 69 6e 67 46 69 65 6c 64 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$a10 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 44 61 74 61 4d 61 6e 61 67 65 72 2e 44 61 74 61 2e 43 72 65 64 65 6e 74 69 61 6c 73 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		6 of ( $a* )
}

rule Windows_Trojan_RedLineStealer_3d9371fd : hardened limited
{
	meta:
		author = "Elastic Security"
		id = "3d9371fd-c094-40fc-baf8-f0e9e9a54ff9"
		fingerprint = "2d7ff7894b267ba37a2d376b022bae45c4948ef3a70b1af986e7492949b5ae23"
		creation_date = "2022-02-17"
		last_modified = "2022-04-12"
		threat_name = "Windows.Trojan.RedLineStealer"
		reference_sample = "0ec522dfd9307772bf8b600a8b91fd6facd0bf4090c2b386afd20e955b25206a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_RedLineStealer.yar"
		repository = "elastic/protections-artifacts"
		source_url = "https://github.com/elastic/protections-artifacts/blob/3bbef930abab9814b2fdb4704be075ab1daf2ea0/yara/rules/Windows_Trojan_RedLineStealer.yar"
		score = 75

	strings:
		$a1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 67 65 74 5f 65 6e 63 72 79 70 74 65 64 5f 6b 65 79 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$a2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 67 65 74 5f 50 61 73 73 65 64 50 61 74 68 73 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$a3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 43 68 72 6f 6d 65 47 65 74 4c 6f 63 61 6c 4e 61 6d 65 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$a4 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 47 65 74 42 72 6f 77 73 65 72 73 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$a5 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 56 00 61 00 6c 00 76 00 65 00 5c 00 53 00 74 00 65 00 61 00 6d 00 4c 00 6f 00 67 00 69 00 6e 00 20 00 44 00 61 00 74 00 61 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$a6 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 25 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 25 00 5c 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$a7 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 53 63 61 6e 50 61 73 73 77 6f 72 64 73 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		all of them
}

rule Windows_Trojan_RedLineStealer_63e7e006 : hardened
{
	meta:
		author = "Elastic Security"
		id = "63e7e006-6c0c-47d8-8090-a6b36f01f3a3"
		fingerprint = "47c7b9a39a5e0a41f26fdf328231eb173a51adfc00948c68332ce72bc442e19e"
		creation_date = "2023-05-01"
		last_modified = "2023-06-13"
		threat_name = "Windows.Trojan.RedLineStealer"
		reference_sample = "e062c99dc9f3fa780ea9c6249fa4ef96bbe17fd1df38dbe11c664a10a92deece"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_RedLineStealer.yar"
		repository = "elastic/protections-artifacts"
		source_url = "https://github.com/elastic/protections-artifacts/blob/3bbef930abab9814b2fdb4704be075ab1daf2ea0/yara/rules/Windows_Trojan_RedLineStealer.yar"
		score = 75

	strings:
		$a1 = { 30 68 44 27 25 5B 3D 79 21 54 3A }
		$a2 = { 40 5E 30 33 5D 44 34 4A 5D 48 33 }
		$a3 = { 4B EF 4D FF 44 DD 41 70 44 DC 41 00 44 DC 41 03 43 D9 3E 00 44 }

	condition:
		all of them
}

rule Windows_Trojan_RedLineStealer_f07b3cb4 : hardened
{
	meta:
		author = "Elastic Security"
		id = "f07b3cb4-a1c5-42c3-a992-d6d9a48bc7a0"
		fingerprint = "8687fa6f540ccebab6000c0c93be4931d874cd04b0692c6934148938bac0026e"
		creation_date = "2023-05-03"
		last_modified = "2023-06-13"
		threat_name = "Windows.Trojan.RedLineStealer"
		reference_sample = "5e491625475fc25c465fc7f6db98def189c15a133af7d0ac1ecbc8d887c4feb6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_RedLineStealer.yar"
		repository = "elastic/protections-artifacts"
		source_url = "https://github.com/elastic/protections-artifacts/blob/3bbef930abab9814b2fdb4704be075ab1daf2ea0/yara/rules/Windows_Trojan_RedLineStealer.yar"
		score = 75

	strings:
		$a1 = { 3C 65 6E 63 72 79 70 74 65 64 5F 6B 65 79 3E 6B 5F 5F 42 61 63 6B 69 6E 67 46 69 65 6C 64 }
		$a2 = { 45 42 37 45 46 31 39 37 33 43 44 43 32 39 35 42 37 42 30 38 46 45 36 44 38 32 42 39 45 43 44 41 44 31 31 30 36 41 46 32 }

	condition:
		all of them
}

rule Windows_Trojan_RedLineStealer_4df4bcb6 : hardened
{
	meta:
		author = "Elastic Security"
		id = "4df4bcb6-a492-4407-8d8f-bbb835322c98"
		fingerprint = "a9e08bf28e8915615f9b39ab814a46c092b5714ef9133f740a1f1f876bfda2d9"
		creation_date = "2023-05-04"
		last_modified = "2023-06-13"
		threat_name = "Windows.Trojan.RedLineStealer"
		reference_sample = "9389475bd26c1d3fd04a083557f2797d0ee89dfdd1f7de67775fcd19e61dfbb3"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_RedLineStealer.yar"
		repository = "elastic/protections-artifacts"
		source_url = "https://github.com/elastic/protections-artifacts/blob/3bbef930abab9814b2fdb4704be075ab1daf2ea0/yara/rules/Windows_Trojan_RedLineStealer.yar"
		score = 75

	strings:
		$a1 = { 34 42 30 35 43 45 42 44 37 44 37 30 46 31 36 30 37 44 34 37 34 43 41 45 31 37 36 46 45 41 45 42 37 34 33 39 37 39 35 46 }

	condition:
		all of them
}

rule Windows_Trojan_RedLineStealer_15ee6903 : hardened
{
	meta:
		author = "Elastic Security"
		id = "15ee6903-757f-462b-8e1c-1ed8ca667910"
		fingerprint = "d3a380f68477b98b3f5adc11cc597042aa95636cfec0b0a5f2e51c201aa61227"
		creation_date = "2023-05-04"
		last_modified = "2023-06-13"
		threat_name = "Windows.Trojan.RedLineStealer"
		reference_sample = "46b506cafb2460ca2969f69bcb0ee0af63b6d65e6b2a6249ef7faa21bde1a6bd"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_RedLineStealer.yar"
		repository = "elastic/protections-artifacts"
		source_url = "https://github.com/elastic/protections-artifacts/blob/3bbef930abab9814b2fdb4704be075ab1daf2ea0/yara/rules/Windows_Trojan_RedLineStealer.yar"
		score = 75

	strings:
		$a1 = { 53 65 65 6E 42 65 66 6F 72 65 33 }
		$a2 = { 73 65 74 5F 53 63 61 6E 47 65 63 6B 6F 42 72 6F 77 73 65 72 73 50 61 74 68 73 }

	condition:
		all of them
}

rule Windows_Trojan_RedLineStealer_6dfafd7b : hardened
{
	meta:
		author = "Elastic Security"
		id = "6dfafd7b-5188-4ec7-9ba4-58b8f05458e5"
		fingerprint = "b7770492fc26ada1e5cb5581221f59b1426332e57eb5e04922f65c25b92ad860"
		creation_date = "2024-01-05"
		last_modified = "2024-01-12"
		threat_name = "Windows.Trojan.RedLineStealer"
		reference_sample = "809e303ba26b894f006b8f2d3983ff697aef13b67c36957d98c56aae9afd8852"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_RedLineStealer.yar"
		repository = "elastic/protections-artifacts"
		source_url = "https://github.com/elastic/protections-artifacts/blob/3bbef930abab9814b2fdb4704be075ab1daf2ea0/yara/rules/Windows_Trojan_RedLineStealer.yar"
		score = 75

	strings:
		$a = { 33 38 46 34 33 31 41 35 34 39 34 31 31 41 45 42 33 32 38 31 30 30 36 38 41 34 43 38 33 32 35 30 42 32 44 33 31 45 31 35 }

	condition:
		all of them
}

rule Windows_Trojan_RedLineStealer_983cd7a7 : hardened
{
	meta:
		author = "Elastic Security"
		id = "983cd7a7-4e7b-413f-b859-b5cbfbf14ae6"
		fingerprint = "6dd74c3b67501506ee43340c07b53ddb94e919d27ad96f55eb4eff3de1470699"
		creation_date = "2024-03-27"
		last_modified = "2024-05-08"
		threat_name = "Windows.Trojan.RedLineStealer"
		reference_sample = "7aa20c57b8815dd63c8ae951e1819c75b5d2deec5aae0597feec878272772f35"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_RedLineStealer.yar"
		repository = "elastic/protections-artifacts"
		source_url = "https://github.com/elastic/protections-artifacts/blob/3bbef930abab9814b2fdb4704be075ab1daf2ea0/yara/rules/Windows_Trojan_RedLineStealer.yar"
		score = 75

	strings:
		$decrypt_config_bytes = { 72 ?? ?? ?? 70 80 ?? ?? ?? 04 72 ?? ?? ?? 70 80 ?? ?? ?? 04 72 ?? ?? ?? 70 80 ?? ?? ?? 04 72 ?? ?? ?? 70 80 ?? ?? ?? 04 [0-6] 2A }
		$str1 = {6e 00 65 00 74 00 2e 00 74 00 63 00 70 00 3a 00 2f 00 2f 00}
		$str2 = {5c 00 44 00 69 00 73 00 63 00 6f 00 72 00 64 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 20 00 53 00 74 00 6f 00 72 00 61 00 67 00 65 00 5c 00 6c 00 65 00 76 00 65 00 6c 00 64 00 62 00}

	condition:
		all of them
}

rule win_redline_loader_dec_2023 : hardened
{
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/12/24"
		description = "Patterns observed in redline loader"
		sha_256 = ""
		ruleset = "win_redline_loader_dec_2023.yar"
		repository = "embee-research/Yara-detection-rules"
		source_url = "https://github.com/embee-research/Yara-detection-rules/blob/ac56d6f6fd2a30c8cb6e5c0455d6519210a8b0f4/Rules/win_redline_loader_dec_2023.yar"
		score = 75

	strings:
		$s1 = {8b ?? ?? 0c 30 04 31 46 3b f7 7c ?? 5d 5b 5e 83 ?? ?? 75}
		$s2 = {57 72 69 74 65 50 72 69 76 61 74 65 50 72 6f 66 69 6c 65 53 74 72 69 6e 67 41}
		$s3 = {53 65 74 46 69 6c 65 53 68 6f 72 74 4e 61 6d 65 41}
		$s4 = {2d 20 41 74 74 65 6d 70 74 20 74 6f 20 75 73 65 20 4d 53 49 4c 20 63 6f 64 65 20 66 72 6f 6d 20 74 68 69 73 20 61 73 73 65 6d 62 6c 79 20 64 75 72 69 6e 67 20 6e 61 74 69 76 65 20 63 6f 64 65 20 69 6e 69 74 69 61 6c 69 7a 61 74 69 6f 6e}

	condition:
		all of them
}

rule RedLineDropperAHK : hardened
{
	meta:
		author = "ditekshen"
		description = "RedLine infostealer payload"
		cape_type = "RedLine Payload"
		ruleset = "RedLine.yar"
		repository = "CAPESandbox/community"
		source_url = "https://github.com/CAPESandbox/community/blob/30a130d01407ba0f0637fb44e8159131a0c4e1e5/data/yara/CAPE/RedLine.yar"
		score = 75

	strings:
		$s1 = {2e 53 65 74 52 65 71 75 65 73 74 48 65 61 64 65 72 28 22 55 73 65 72 2d 41 67 65 6e 74 22 2c 22 20 28 20 22 20 4f 53 4e 61 6d 65 20 22 20 7c 20 22 20 62 69 74 20 22 20 7c 20 22 20 43 50 55 4e 41 6d 65 20 22 22}
		$s2 = {3a 3d 20 22 20 7c 20 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 22}
		$s3 = {57 00 69 00 6e 00 64 00 6f 00 77 00 53 00 70 00 79 00 2e 00 61 00 68 00 6b 00}

	condition:
		uint16( 0 ) == 0x5a4d and all of them
}

import "pe"

rule RedLineDropperEXE : hardened limited
{
	meta:
		author = "ditekSHen"
		description = "Detects executables dropping RedLine infostealer"
		cape_type = "RedLineDropperEXE Payload"
		ruleset = "RedLine.yar"
		repository = "CAPESandbox/community"
		source_url = "https://github.com/CAPESandbox/community/blob/30a130d01407ba0f0637fb44e8159131a0c4e1e5/data/yara/CAPE/RedLine.yar"
		score = 75

	strings:
		$s1 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 57 00 69 00 7a 00 75 00 74 00 65 00 7a 00 69 00 6e 00 6f 00 64 00 20 00 74 00 6f 00 67 00 65 00 74 00 6f 00 30 00 52 00 6f 00 77 00 61 00 64 00 75 00 66 00 65 00 76 00 6f 00 6d 00 75 00 6b 00 69 00 20 00 66 00 75 00 74 00 65 00 6e 00 75 00 6a 00 69 00 6c 00 61 00 7a 00 65 00 6d 00 20 00 6a 00 69 00 63 00 20 00 6c 00 65 00 66 00 6f 00 67 00 61 00 74 00 65 00 6e 00 65 00 7a 00 69 00 6e 00 6f 00 72 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s2 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 36 00 54 00 61 00 74 00 61 00 66 00 61 00 6d 00 6f 00 62 00 65 00 76 00 6f 00 66 00 61 00 6a 00 20 00 62 00 69 00 7a 00 61 00 66 00 6f 00 6a 00 75 00 20 00 70 00 65 00 79 00 6f 00 76 00 61 00 76 00 61 00 63 00 6f 00 63 00 6f 00 20 00 6c 00 69 00 7a 00 69 00 6e 00 65 00 20 00 6b 00 65 00 7a 00 61 00 6b 00 61 00 6a 00 75 00 6a 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s3 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 4c 00 61 00 77 00 75 00 68 00 65 00 72 00 75 00 73 00 6f 00 7a 00 65 00 72 00 75 00 20 00 6b 00 75 00 63 00 75 00 20 00 7a 00 61 00 6d 00 30 00 5a 00 6f 00 72 00 69 00 7a 00 65 00 79 00 75 00 6b 00 20 00 6c 00 65 00 70 00 61 00 70 00 6f 00 73 00 75 00 70 00 75 00 20 00 67 00 61 00 6c 00 61 00 20 00 6b 00 69 00 6e 00 61 00 72 00 75 00 73 00 6f 00 74 00 20 00 72 00 75 00 76 00 61 00 73 00 61 00 78 00 65 00 68 00 75 00 77 00 6f 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s4 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 43 6c 65 61 72 45 76 65 6e 74 4c 6f 67 57 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s5 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 69 00 6f 00 6e 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s6 = {56 00 61 00 73 00 75 00 6b 00 6f 00 29 00 59 00 75 00 67 00 65 00 6e 00 69 00 7a 00 75 00 67 00 69 00 6c 00 6f 00 62 00 6f 00 20 00 74 00 6f 00 78 00 6f 00 63 00 69 00 76 00 6f 00 72 00 69 00 79 00 65 00 20 00 79 00 65 00 78 00 6f 00 7a 00 6f 00 79 00 6f 00 68 00 75 00 7a 00 65 00 62 00}
		$s7 = {59 00 69 00 6b 00 65 00 7a 00 65 00 76 00 61 00 76 00 75 00 7a 00 75 00 73 00 20 00 67 00 75 00 63 00 61 00 6a 00 61 00 6e 00 65 00 73 00 61 00 6e 00 23 00 52 00 6f 00 6c 00 61 00 70 00 75 00 63 00 65 00 64 00 65 00 64 00 6f 00 78 00 75 00 20 00 78 00 65 00 77 00 75 00 6c 00 65 00 70 00 20 00 66 00 75 00 77 00 65 00 68 00 6f 00 66 00 69 00 77 00 69 00 66 00 69 00}

	condition:
		uint16( 0 ) == 0x5a4d and ( pe.exports ( "_fgeek@8" ) and 2 of them ) or ( 2 of them and for any i in ( 0 .. pe.number_of_sections ) : ( ( pe.sections [ i ] . name == ".rig" ) ) )
}

rule RedLine_1 : hardened limited
{
	meta:
		author = "ditekSHen"
		description = "Detects RedLine infostealer"
		cape_type = "RedLine Payload"
		original_yara_name = "RedLine"
		ruleset = "RedLine.yar"
		repository = "CAPESandbox/community"
		source_url = "https://github.com/CAPESandbox/community/blob/30a130d01407ba0f0637fb44e8159131a0c4e1e5/data/yara/CAPE/RedLine.yar"
		score = 75

	strings:
		$s1 = { 23 00 2b 00 33 00 3b 00 43 00 53 00 63 00 73 00 }
		$s2 = { 68 10 84 2d 2c 71 ea 7e 2c 71 ea 7e 2c 71 ea 7e
                32 23 7f 7e 3f 71 ea 7e 0b b7 91 7e 2b 71 ea 7e
                2c 71 eb 7e 5c 71 ea 7e 32 23 6e 7e 1c 71 ea 7e
                32 23 69 7e a2 71 ea 7e 32 23 7b 7e 2d 71 ea 7e }
		$s3 = { 83 ec 38 53 b0 ?? 88 44 24 2b 88 44 24 2f b0 ??
                88 44 24 30 88 44 24 31 88 44 24 33 55 56 8b f1
                b8 0c 00 fe ff 2b c6 89 44 24 14 b8 0d 00 fe ff
                2b c6 89 44 24 1c b8 02 00 fe ff 2b c6 89 44 24
                18 b3 32 b8 0e 00 fe ff 2b c6 88 5c 24 32 88 5c
                24 41 89 44 24 28 57 b1 ?? bb 0b 00 fe ff b8 03
                00 fe ff 2b de 2b c6 bf 00 00 fe ff b2 ?? 2b fe
                88 4c 24 38 88 4c 24 42 88 4c 24 47 c6 44 24 34
                78 c6 44 24 35 61 88 54 24 3a c6 44 24 3e 66 c6
                44 24 41 33 c6 44 24 43 ?? c6 44 24 44 74 88 54
                24 46 c6 44 24 40 ?? c6 44 24 39 62 c7 44 24 10 }
		$s4 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 42 00 7c 00 42 00 78 00 42 00 74 00 42 00 70 00 42 00 6c 00 42 00 68 00 42 00 64 00 42 00 60 00 42 00 5c 00 42 00 58 00 42 00 54 00 42 00 50 00 42 00 4c 00 42 00 48 00 42 00 44 00 42 00 40 00 42 00 3c 00 42 00 38 00 42 00 34 00 42 00 30 00 42 00 2c 00 42 00 28 00 42 00 24 00 42 00 20 00 42 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s5 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 20 64 65 6c 65 74 65 5b 5d (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s6 = {63 6f 6e 73 74 72 75 63 74 6f 72 20 6f 72 20 66 72 6f 6d 20 44 6c 6c 4d 61 69 6e 2e}
		$x1 = {52 65 64 4c 69 6e 65 2e 52 65 62 75 72 6e}
		$x2 = {52 65 64 4c 69 6e 65 2e 43 6c 69 65 6e 74 2e}
		$x3 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 68 00 6f 00 73 00 74 00 49 00 52 00 65 00 6d 00 6f 00 74 00 65 00 50 00 61 00 6e 00 65 00 6c 00 2c 00 20 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 4c 00 69 00 6e 00 65 00 3a 00 20 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$u1 = {3c 50 61 72 73 65 43 6f 69 6e 6f 6d 69 3e}
		$u2 = {3c 50 61 72 73 65 42 72 6f 77 73 65 72 73 3e}
		$u3 = {3c 47 72 61 62 53 63 72 65 65 6e 73 68 6f 74 3e}
		$u4 = {55 73 65 72 4c 6f 67}
		$u5 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 46 69 6e 67 65 72 50 72 69 6e 74 54 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$u6 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 49 6e 73 74 61 6c 6c 65 64 42 72 6f 77 73 65 72 49 6e 66 6f 54 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$u7 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 52 75 6e 50 45 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$u8 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 44 6f 77 6e 6c 6f 61 64 41 6e 64 45 78 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$u9 = {2e 44 61 74 61 2e 41 70 70 6c 69 63 61 74 69 6f 6e 73 2e 57 61 6c 6c 65 74 73}
		$u10 = {2e 44 61 74 61 2e 42 72 6f 77 73 65 72 73}
		$u11 = {2e 4d 6f 64 65 6c 73 2e 57 4d 49}
		$u12 = {44 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 53 00 75 00 63 00 6b 00 73 00}
		$pat1 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 28 00 28 00 28 00 28 00 5b 00 30 00 2d 00 39 00 2e 00 5d 00 29 00 5c 00 64 00 29 00 2b 00 29 00 7b 00 31 00 7d 00 29 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$pat2 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 5e 00 28 00 3f 00 3a 00 32 00 31 00 33 00 31 00 7c 00 31 00 38 00 30 00 30 00 7c 00 33 00 35 00 5c 00 5c 00 64 00 7b 00 33 00 7d 00 29 00 5c 00 5c 00 64 00 7b 00 31 00 31 00 7d 00 24 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$pat3 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 36 00 28 00 3f 00 3a 00 30 00 31 00 31 00 7c 00 35 00 5b 00 30 00 2d 00 39 00 5d 00 7b 00 32 00 7d 00 29 00 5b 00 30 00 2d 00 39 00 5d 00 7b 00 31 00 32 00 7d 00 24 00 2f 00 43 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$pat4 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 54 00 65 00 6c 00 65 00 67 00 72 00 61 00 6d 00 70 00 72 00 6f 00 66 00 69 00 6c 00 65 00 73 00 5e 00 28 00 36 00 33 00 30 00 34 00 7c 00 36 00 37 00 30 00 36 00 7c 00 36 00 37 00 30 00 39 00 7c 00 36 00 37 00 37 00 31 00 29 00 5b 00 30 00 2d 00 39 00 5d 00 7b 00 31 00 32 00 2c 00 31 00 35 00 7d 00 24 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$pat5 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 68 00 6f 00 73 00 74 00 5f 00 6b 00 65 00 79 00 5e 00 28 00 3f 00 3a 00 34 00 5b 00 30 00 2d 00 39 00 5d 00 7b 00 31 00 32 00 7d 00 28 00 3f 00 3a 00 5b 00 30 00 2d 00 39 00 5d 00 7b 00 33 00 7d 00 29 00 3f 00 7c 00 35 00 5b 00 31 00 2d 00 35 00 5d 00 5b 00 30 00 2d 00 39 00 5d 00 7b 00 31 00 34 00 7d 00 29 00 24 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$pat6 = {5e 00 33 00 28 00 3f 00 3a 00 30 00 5b 00 30 00 2d 00 35 00 5d 00 7c 00 5b 00 36 00 38 00 5d 00 5b 00 30 00 2d 00 39 00 5d 00 29 00 5b 00 30 00 2d 00 39 00 5d 00 7b 00 31 00 31 00 7d 00 24 00}
		$pat7 = {73 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 70 00 72 00 6f 00 74 00 6f 00 63 00 6f 00 6c 00 5e 00 28 00 35 00 30 00 31 00 38 00 7c 00 35 00 30 00 32 00 30 00 7c 00 35 00 30 00 33 00 38 00 7c 00 36 00 33 00 30 00 34 00 7c 00 36 00 37 00 35 00 39 00 7c 00 36 00 37 00 36 00 31 00 7c 00 36 00 37 00 36 00 33 00 29 00 5b 00 30 00 2d 00 39 00 5d 00 7b 00 38 00 2c 00 31 00 35 00 7d 00 24 00}
		$pat8 = {4f 00 70 00 65 00 72 00 61 00 20 00 47 00 58 00 34 00 5b 00 30 00 2d 00 39 00 5d 00 7b 00 31 00 32 00 7d 00 28 00 3f 00 3a 00 5b 00 30 00 2d 00 39 00 5d 00 7b 00 33 00 7d 00 29 00 3f 00 24 00 63 00 6f 00 6f 00 6b 00 69 00 65 00 73 00}
		$pat9 = {5e 00 39 00 5b 00 30 00 2d 00 39 00 5d 00 7b 00 31 00 35 00 7d 00 24 00 43 00 6f 00 69 00 6e 00 6f 00 6d 00 69 00}
		$pat10 = {77 00 61 00 6c 00 6c 00 65 00 74 00 73 00 5e 00 28 00 36 00 32 00 5b 00 30 00 2d 00 39 00 5d 00 7b 00 31 00 34 00 2c 00 31 00 37 00 7d 00 29 00 24 00}
		$pat11 = {68 00 6f 00 73 00 74 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 55 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 5f 00 76 00 61 00 6c 00 75 00 65 00}
		$pat12 = {63 00 72 00 65 00 64 00 69 00 74 00 5f 00 63 00 61 00 72 00 64 00 73 00 5e 00 33 00 38 00 39 00 5b 00 30 00 2d 00 39 00 5d 00 7b 00 31 00 31 00 7d 00 24 00}
		$pat13 = {4e 00 57 00 69 00 6e 00 6f 00 72 00 64 00 56 00 57 00 69 00 6e 00 70 00 6e 00 2e 00 65 00 57 00 69 00 6e 00 78 00 65 00 2a 00 57 00 69 00 6e 00 68 00 6f 00 73 00 74 00 55 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 5f 00 76 00 61 00 6c 00 75 00 65 00}
		$pat14 = /(\/|,\s)CommandLine:/ wide
		$v2_1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 4c 69 73 74 4f 66 50 72 6f 63 65 73 73 65 73 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$v2_2 = /get_Scan(ned)?(Browsers|ChromeBrowsersPaths|Discord|FTP|GeckoBrowsersPaths|Screen|Steam|Telegram|VPN|Wallets)/ fullword ascii
		$v2_3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 47 65 74 41 72 67 75 6d 65 6e 74 73 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$v2_4 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 56 65 72 69 66 79 55 70 64 61 74 65 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$v2_5 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 56 65 72 69 66 79 53 63 61 6e 52 65 71 75 65 73 74 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$v2_6 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 47 65 74 55 70 64 61 74 65 73 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$v3_1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 6c 6f 63 61 6c 68 6f 73 74 2e 49 55 73 65 72 53 65 72 76 69 63 65 75 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$v3_2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 50 61 72 73 65 4e 65 74 77 6f 72 6b 49 6e 74 65 72 66 61 63 65 73 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$v3_3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 52 65 70 6c 79 41 63 74 69 6f 6e 30 68 74 74 70 3a 2f 2f 74 65 6d 70 75 72 69 2e 6f 72 67 2f 49 55 73 65 72 53 65 72 76 69 63 65 2f 47 65 74 55 73 65 72 73 52 65 73 70 6f 6e 73 65 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$v3_4 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 41 63 74 69 6f 6e 28 68 74 74 70 3a 2f 2f 74 65 6d 70 75 72 69 2e 6f 72 67 2f 49 55 73 65 72 53 65 72 76 69 63 65 2f 47 65 74 55 73 65 72 73 54 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$v3_5 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 62 00 61 00 73 00 69 00 63 00 43 00 66 00 67 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$vx4_1 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 43 00 3a 00 5c 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 5c 00 76 00 34 00 2e 00 30 00 2e 00 33 00 30 00 33 00 31 00 39 00 5c 00 5c 00 41 00 64 00 64 00 49 00 6e 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 33 00 32 00 2e 00 65 00 78 00 65 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$v4_2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 69 73 57 6f 77 36 34 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$v4_3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 62 61 73 65 36 34 73 74 72 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$v4_4 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 73 74 72 69 6e 67 4b 65 79 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$v4_5 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 42 79 74 65 73 54 6f 53 74 72 69 6e 67 43 6f 6e 76 65 72 74 65 64 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$v4_6 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 46 72 6f 6d 42 61 73 65 36 34 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$v4_7 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 78 6f 72 65 64 53 74 72 69 6e 67 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$v4_8 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 70 72 6f 63 4e 61 6d 65 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$v4_9 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 62 61 73 65 36 34 45 6e 63 6f 64 65 64 44 61 74 61 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$v5_1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 44 6f 77 6e 6c 6f 61 64 41 6e 64 45 78 65 63 75 74 65 55 70 64 61 74 65 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$v5_2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 49 54 61 73 6b 50 72 6f 63 65 73 73 6f 72 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$v5_3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 43 6f 6d 6d 61 6e 64 4c 69 6e 65 55 70 64 61 74 65 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$v5_4 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 44 6f 77 6e 6c 6f 61 64 55 70 64 61 74 65 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$v5_5 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 46 69 6c 65 53 63 61 6e 6e 69 6e 67 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$v5_6 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 47 65 74 4c 65 6e 54 6f 50 6f 73 53 74 61 74 65 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$v5_7 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 52 65 63 6f 72 64 48 65 61 64 65 72 46 69 65 6c 64 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$v5_8 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 45 6e 64 70 6f 69 6e 74 43 6f 6e 6e 65 63 74 69 6f 6e (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$v5_9 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 42 43 52 59 50 54 5f 4b 45 59 5f 4c 45 4e 47 54 48 53 5f 53 54 52 55 43 54 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$v6_1 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 25 00 6c 00 6f 00 63 00 61 00 6c 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 25 00 5c 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$v6_2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 47 65 74 44 65 63 6f 64 65 64 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$v6_3 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 2f 00 2f 00 73 00 65 00 74 00 74 00 69 00 6e 00 53 00 74 00 72 00 69 00 6e 00 67 00 2e 00 52 00 65 00 6d 00 6f 00 76 00 65 00 67 00 5b 00 40 00 6e 00 61 00 6d 00 65 00 3d 00 5c 00 50 00 61 00 73 00 73 00 77 00 53 00 74 00 72 00 69 00 6e 00 67 00 2e 00 52 00 65 00 6d 00 6f 00 76 00 65 00 6f 00 72 00 64 00 5c 00 5d 00 2f 00 76 00 61 00 6c 00 75 00 53 00 74 00 72 00 69 00 6e 00 67 00 2e 00 52 00 65 00 6d 00 6f 00 76 00 65 00 65 00 52 00 4f 00 4f 00 54 00 5c 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 43 00 65 00 6e 00 74 00 65 00 72 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$v6_4 = {41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 52 00 6f 00 61 00 6d 00 69 00 6e 00 67 00 5c 00 20 00 2f 00 2f 00 73 00 65 00 74 00 74 00 53 00 74 00 72 00 69 00 6e 00 67 00 2e 00 52 00 65 00 70 00 6c 00 61 00 63 00 65 00 69 00 6e 00 67 00 5b 00 40 00 6e 00 61 00 6d 00 65 00 3d 00 5c 00 55 00 53 00 74 00 72 00 69 00 6e 00 67 00 2e 00 52 00 65 00 70 00 6c 00 61 00 63 00 65 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 5c 00 5d 00 2f 00 76 00 61 00 53 00 74 00 72 00 69 00 6e 00 67 00 2e 00 52 00 65 00 70 00 6c 00 61 00 63 00 65 00 6c 00 75 00 65 00 6d 00 6f 00 7a 00 5f 00 63 00 6f 00 6f 00 6b 00 69 00 65 00 73 00}
		$v6_5 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 3c 47 65 74 57 69 6e 64 6f 77 73 56 65 72 73 69 6f 6e 3e 67 5f 5f 48 4b 4c 4d 5f 47 65 74 53 74 72 69 6e 67 7c 31 31 5f 30 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$v6_6 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 6e 00 65 00 74 00 2e 00 74 00 63 00 70 00 3a 00 2f 00 2f 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}

	condition:
		( uint16( 0 ) == 0x5a4d and ( all of ( $s* ) or 2 of ( $x* ) or 7 of ( $u* ) or 7 of ( $pat* ) or ( 1 of ( $x* ) and ( 5 of ( $u* ) or 2 of ( $pat* ) ) ) or 5 of ( $v2* ) or 4 of ( $v3* ) or ( 3 of ( $v2* ) and ( 2 of ( $pat* ) or 2 of ( $u* ) ) or ( 1 of ( $vx4* ) and 5 of ( $v4* ) ) or 5 of ( $v4* ) or 6 of ( $v5* ) ) or 5 of ( $v6* ) or ( 4 of ( $v6* ) and 3 of them ) ) ) or ( ( all of ( $x* ) and 4 of ( $s* ) ) or ( 4 of ( $v6* ) and 4 of them ) )
}

rule Win32_Trojan_Packed_RedLineStealer : hardened
{
	meta:
		description = "Identifies a loader used to deploy RedLine Stealer"
		author = "Netskope Threat Labs"
		reference = "4d77e265722624b5d4d1841d45c7c677"
		ruleset = "Win32_Trojan_RedLineStealer.yar"
		repository = "netskopeoss/NetskopeThreatLabsIOCs"
		source_url = "https://github.com/netskopeoss/NetskopeThreatLabsIOCs/blob/52c780db6106d0c0e8deb04653e036cdd4408e56/Malware/RedLine%20Stealer/Yara/Win32_Trojan_RedLineStealer.yar"
		license = "MIT License"
		score = 75

	strings:
		$str00 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 76 00 34 00 2e 00 30 00 2e 00 33 00 30 00 33 00 31 00 39 00 5c 00 52 00 65 00 67 00 53 00 76 00 63 00 73 00 2e 00 65 00 78 00 65 00}
		$str01 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 76 00 34 00 2e 00 30 00 2e 00 33 00 30 00 33 00 31 00 39 00 5c 00 41 00 70 00 70 00 4c 00 61 00 75 00 6e 00 63 00 68 00 2e 00 65 00 78 00 65 00}
		$api01 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74}
		$api02 = {53 65 6e 64 4d 65 73 73 61 67 65 41}
		$api03 = {50 6f 73 74 4d 65 73 73 61 67 65 41}
		$asm00 = { 8a 8? ?? ?? ?? ?? 30 04 ?e 46 }
		$asm01 = { 8a 8? ?? ?? ?? ?? 30 04 3e e8 }

	condition:
		uint16( 0 ) == 0x5a4d and 1 of ( $str* ) and 2 of ( $api* ) and 1 of ( $asm* )
}

rule Mal_Stealer_NET_Redline_Aug_2020_1 : hardened limited
{
	meta:
		description = "Detect Redline Stealer (August 2020)"
		author = "Arkbird_SOLG"
		reference = "https://twitter.com/JAMESWT_MHT/status/1297878628450152448"
		date = "2020-08-24"
		hash1 = "4195430d95ac1ede9bc986728fc4211a1e000a9ba05a3e968dd302c36ab0aca0"
		ruleset = "Mal_Stealer_NET_Redline_Aug_2020_1.yar"
		repository = "StrangerealIntel/DailyIOC"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-08-24/Redline/Mal_Stealer_NET_Redline_Aug_2020_1.yar"
		score = 75

	strings:
		$s1 = { 53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 57 00 68 00 65 00 72 00 65 00 20 00 53 00 65 00 73 00 73 00 69 00 6f 00 6e 00 49 00 64 00 3d 00 27 00 7b 00 30 00 7d }
		$s2 = { 28 00 28 00 28 00 28 00 5b 00 30 00 2d 00 39 00 2e 00 5d 00 29 00 5c 00 64 00 29 00 2b 00 29 00 7b 00 31 00 7d 00 29 }
		$s3 = { 7b 00 30 00 7d 00 5c 00 46 00 69 00 6c 00 65 00 5a 00 69 00 6c 00 6c 00 61 00 5c 00 72 00 65 00 63 00 65 00 6e 00 74 00 73 00 65 00 72 00 76 00 65 00 72 00 73 00 2e 00 78 00 6d 00 6c }
		$s4 = { 7b 00 30 00 7d 00 5c 00 46 00 69 00 6c 00 65 00 5a 00 69 00 6c 00 6c 00 61 00 5c 00 73 00 69 00 74 00 65 00 6d 00 61 00 6e 00 61 00 67 00 65 00 72 00 2e 00 78 00 6d 00 6c }
		$s5 = { 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 61 00 72 00 74 00 69 00 6e 00 20 00 50 00 72 00 69 00 6b 00 72 00 79 00 6c 00 5c 00 57 00 69 00 6e 00 53 00 43 00 50 00 20 00 32 00 5c 00 53 00 65 00 73 00 73 00 69 00 6f 00 6e 00 73 }
		$s6 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 3c 65 6e 63 72 79 70 74 65 64 5f 6b 65 79 3e 6b 5f 5f 42 61 63 6b 69 6e 67 46 69 65 6c 64 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s7 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 73 65 74 5f 65 6e 63 72 79 70 74 65 64 5f 6b 65 79 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s8 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 55 73 65 72 41 67 65 6e 74 44 65 74 65 63 74 6f 72 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s9 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 73 65 74 5f 65 6e 63 72 79 70 74 65 64 5f 6b 65 79 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s10 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 73 65 74 5f 46 74 70 43 6f 6e 6e 65 63 74 69 6f 6e 73 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s11 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 73 65 74 5f 49 73 50 72 6f 63 65 73 73 45 6c 65 76 61 74 65 64 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s12 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 53 00 45 00 4c 00 45 00 43 00 54 00 20 00 45 00 78 00 65 00 63 00 75 00 74 00 61 00 62 00 6c 00 65 00 50 00 61 00 74 00 68 00 2c 00 20 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 49 00 44 00 20 00 46 00 52 00 4f 00 4d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s13 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 3c 49 73 50 72 6f 63 65 73 73 45 6c 65 76 61 74 65 64 3e 6b 5f 5f 42 61 63 6b 69 6e 67 46 69 65 6c 64 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s14 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 53 79 73 74 65 6d 2e 43 6f 6c 6c 65 63 74 69 6f 6e 73 2e 47 65 6e 65 72 69 63 2e 49 45 6e 75 6d 65 72 61 62 6c 65 3c 52 65 64 4c 69 6e 65 2e 4c 6f 67 69 63 2e 4a 73 6f 6e 2e 4a 73 6f 6e 56 61 6c 75 65 3e 2e 47 65 74 45 6e 75 6d 65 72 61 74 6f 72 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s15 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 53 79 73 74 65 6d 2e 43 6f 6c 6c 65 63 74 69 6f 6e 73 2e 47 65 6e 65 72 69 63 2e 49 45 6e 75 6d 65 72 61 74 6f 72 3c 52 65 64 4c 69 6e 65 2e 4c 6f 67 69 63 2e 4a 73 6f 6e 2e 4a 73 6f 6e 56 61 6c 75 65 3e 2e 67 65 74 5f 43 75 72 72 65 6e 74 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s16 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 48 00 4b 00 45 00 59 00 5f 00 43 00 55 00 52 00 52 00 45 00 4e 00 54 00 5f 00 55 00 53 00 45 00 52 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 41 00 70 00 70 00 20 00 50 00 61 00 74 00 68 00 73 00 5c 00 62 00 72 00 6f 00 77 00 73 00 65 00 72 00 2e 00 65 00 78 00 65 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s17 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 50 72 6f 63 65 73 73 45 78 65 63 75 74 61 62 6c 65 50 61 74 68 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s18 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 49 73 50 72 6f 63 65 73 73 45 6c 65 76 61 74 65 64 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s19 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 48 00 4b 00 45 00 59 00 5f 00 43 00 55 00 52 00 52 00 45 00 4e 00 54 00 5f 00 55 00 53 00 45 00 52 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 41 00 70 00 70 00 20 00 50 00 61 00 74 00 68 00 73 00 5c 00 66 00 69 00 72 00 65 00 66 00 6f 00 78 00 2e 00 65 00 78 00 65 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s20 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 67 65 74 5f 65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 90KB and 15 of them
}

rule Windows_Trojan_RedLineStealer_d25e974b : hardened
{
	meta:
		author = "Elastic Security"
		id = "d25e974b-7cf0-4c0e-bf57-056cbb90d77e"
		fingerprint = "f936511802dcce39dfed9ec898f3ab0c4b822fd38bac4e84d60966c7b791688c"
		creation_date = "2022-02-17"
		last_modified = "2022-04-12"
		threat_name = "Windows.Trojan.RedLineStealer"
		reference_sample = "a91c1d3965f11509d1c1125210166b824a79650f29ea203983fffb5f8900858c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_RedLineStealer.yar"
		repository = "RoomaSec/RmTools"
		source_url = "https://github.com/RoomaSec/RmTools/blob/fc4e0b5491bc699117804268d023467b0d047e87/yara_scanner/yara_rules/es_rules/Windows_Trojan_RedLineStealer.yar"
		score = 75

	strings:
		$a = { 48 43 3F FF 48 42 3F FF 48 42 3F FF 48 42 3E FF 48 42 3E FF }

	condition:
		all of them
}

rule Windows_Trojan_RedLineStealer_ed346e4c : hardened
{
	meta:
		author = "Elastic Security"
		id = "ed346e4c-7890-41ee-8648-f512682fe20e"
		fingerprint = "834c13b2e0497787e552bb1318664496d286e7cf57b4661e5e07bf1cffe61b82"
		creation_date = "2022-02-17"
		last_modified = "2022-04-12"
		threat_name = "Windows.Trojan.RedLineStealer"
		reference_sample = "a91c1d3965f11509d1c1125210166b824a79650f29ea203983fffb5f8900858c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_RedLineStealer.yar"
		repository = "RoomaSec/RmTools"
		source_url = "https://github.com/RoomaSec/RmTools/blob/fc4e0b5491bc699117804268d023467b0d047e87/yara_scanner/yara_rules/es_rules/Windows_Trojan_RedLineStealer.yar"
		score = 75

	strings:
		$a = { 55 8B EC 8B 45 14 56 57 8B 7D 08 33 F6 89 47 0C 39 75 10 76 15 8B }

	condition:
		all of them
}

rule win_redline_payload_dec_2023 : hardened
{
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/12/24"
		description = "Patterns observed in redline"
		sha_256 = "5790aead07ce0b9b508392b9a2f363ef77055ae16c44231773849c87a1dd15a4"
		ruleset = "win_redline_payload_dec_2023.yar"
		repository = "embee-research/Yara-detection-rules"
		source_url = "https://github.com/embee-research/Yara-detection-rules/blob/ac56d6f6fd2a30c8cb6e5c0455d6519210a8b0f4/Rules/win_redline_payload_dec_2023.yar"
		score = 75

	strings:
		$s1 = {16 72 ?? ?? ?? 70 A2 7E ?? ?? ?? 04 17 72 ?? ?? ?? 70 7E ?? ?? ?? 04 16 9A 28 ?? ?? ?? 06 A2 7E ?? ?? ?? 04 18 72 ?? ?? ?? 70 }

	condition:
		all of them
}

rule RedLine_b : hardened
{
	meta:
		id = "6Ds02SHJ9xqDC5ehVb5PEZ"
		fingerprint = "5ecb15004061205cdea7bcbb6f28455b6801d82395506fd43769d591476c539e"
		version = "1.0"
		creation_date = "2021-10-01"
		first_imported = "2021-12-30"
		last_modified = "2021-12-30"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		source = "BARTBLAZE"
		author = "@bartblaze"
		description = "Identifies RedLine stealer."
		category = "MALWARE"
		ruleset = "RedLine.yar"
		repository = "bartblaze/Yara-rules"
		source_url = "https://github.com/bartblaze/Yara-rules/blob/2df95022135637808d2a1ff9a49043ffd7f58c5d/rules/crimeware/RedLine.yar"
		license = "MIT License"
		score = 75

	strings:
		$ = {((41 63 63 6f 75 6e 74) | (41 00 63 00 63 00 6f 00 75 00 6e 00 74 00))}
		$ = {((41 6c 6c 57 61 6c 6c 65 74 73) | (41 00 6c 00 6c 00 57 00 61 00 6c 00 6c 00 65 00 74 00 73 00))}
		$ = {((41 75 74 6f 66 69 6c 6c) | (41 00 75 00 74 00 6f 00 66 00 69 00 6c 00 6c 00))}
		$ = {((42 72 6f 77 73 65 72) | (42 00 72 00 6f 00 77 00 73 00 65 00 72 00))}
		$ = {((42 72 6f 77 73 65 72 56 65 72 73 69 6f 6e) | (42 00 72 00 6f 00 77 00 73 00 65 00 72 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00))}
		$ = {((43 68 72 5f 30 5f 4d 5f 65) | (43 00 68 00 72 00 5f 00 30 00 5f 00 4d 00 5f 00 65 00))}
		$ = {((43 6f 6d 6d 61 6e 64 4c 69 6e 65 55 70 64 61 74 65) | (43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 4c 00 69 00 6e 00 65 00 55 00 70 00 64 00 61 00 74 00 65 00))}
		$ = {((43 6f 6e 66 69 67 52 65 61 64 65 72) | (43 00 6f 00 6e 00 66 00 69 00 67 00 52 00 65 00 61 00 64 00 65 00 72 00))}
		$ = {((44 65 73 6b 74 6f 70 4d 65 73 73 61 6e 67 65 72) | (44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 4d 00 65 00 73 00 73 00 61 00 6e 00 67 00 65 00 72 00))}
		$ = {((44 69 73 63 6f 72 64) | (44 00 69 00 73 00 63 00 6f 00 72 00 64 00))}
		$ = {((44 6f 77 6e 6c 6f 61 64 41 6e 64 45 78 65 63 75 74 65 55 70 64 61 74 65) | (44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 41 00 6e 00 64 00 45 00 78 00 65 00 63 00 75 00 74 00 65 00 55 00 70 00 64 00 61 00 74 00 65 00))}
		$ = {((44 6f 77 6e 6c 6f 61 64 55 70 64 61 74 65) | (44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 55 00 70 00 64 00 61 00 74 00 65 00))}
		$ = {((45 6e 64 70 6f 69 6e 74 43 6f 6e 6e 65 63 74 69 6f 6e) | (45 00 6e 00 64 00 70 00 6f 00 69 00 6e 00 74 00 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6f 00 6e 00))}
		$ = {((45 78 74 65 6e 73 69 6f 6e 73) | (45 00 78 00 74 00 65 00 6e 00 73 00 69 00 6f 00 6e 00 73 00))}
		$ = {((46 69 6c 65 43 6f 70 69 65 72) | (46 00 69 00 6c 00 65 00 43 00 6f 00 70 00 69 00 65 00 72 00))}
		$ = {((46 69 6c 65 53 63 61 6e 6e 65 72) | (46 00 69 00 6c 00 65 00 53 00 63 00 61 00 6e 00 6e 00 65 00 72 00))}
		$ = {((46 69 6c 65 53 63 61 6e 6e 65 72 41 72 67) | (46 00 69 00 6c 00 65 00 53 00 63 00 61 00 6e 00 6e 00 65 00 72 00 41 00 72 00 67 00))}
		$ = {((46 69 6c 65 53 63 61 6e 6e 69 6e 67) | (46 00 69 00 6c 00 65 00 53 00 63 00 61 00 6e 00 6e 00 69 00 6e 00 67 00))}
		$ = {((46 69 6c 65 53 65 61 72 63 68 65 72) | (46 00 69 00 6c 00 65 00 53 00 65 00 61 00 72 00 63 00 68 00 65 00 72 00))}
		$ = {((46 69 6c 65 5a 69 6c 6c 61) | (46 00 69 00 6c 00 65 00 5a 00 69 00 6c 00 6c 00 61 00))}
		$ = {((46 75 6c 6c 49 6e 66 6f 53 65 6e 64 65 72) | (46 00 75 00 6c 00 6c 00 49 00 6e 00 66 00 6f 00 53 00 65 00 6e 00 64 00 65 00 72 00))}
		$ = {((47 61 6d 65 4c 61 75 6e 63 68 65 72) | (47 00 61 00 6d 00 65 00 4c 00 61 00 75 00 6e 00 63 00 68 00 65 00 72 00))}
		$ = {((47 64 69 48 65 6c 70 65 72) | (47 00 64 00 69 00 48 00 65 00 6c 00 70 00 65 00 72 00))}
		$ = {((47 65 6f 49 6e 66 6f) | (47 00 65 00 6f 00 49 00 6e 00 66 00 6f 00))}
		$ = {((47 65 6f 50 6c 75 67 69 6e) | (47 00 65 00 6f 00 50 00 6c 00 75 00 67 00 69 00 6e 00))}
		$ = {((48 61 72 64 77 61 72 65 54 79 70 65) | (48 00 61 00 72 00 64 00 77 00 61 00 72 00 65 00 54 00 79 00 70 00 65 00))}
		$ = {((49 43 6f 6e 74 72 61 63 74) | (49 00 43 00 6f 00 6e 00 74 00 72 00 61 00 63 00 74 00))}
		$ = {((49 54 61 73 6b 50 72 6f 63 65 73 73 6f 72) | (49 00 54 00 61 00 73 00 6b 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 6f 00 72 00))}
		$ = {((49 64 65 6e 74 69 74 79 53 65 6e 64 65 72 42 61 73 65) | (49 00 64 00 65 00 6e 00 74 00 69 00 74 00 79 00 53 00 65 00 6e 00 64 00 65 00 72 00 42 00 61 00 73 00 65 00))}
		$ = {((4c 6f 63 61 6c 53 74 61 74 65) | (4c 00 6f 00 63 00 61 00 6c 00 53 00 74 00 61 00 74 00 65 00))}
		$ = {((4c 6f 63 61 74 6f 72 41 50 49) | (4c 00 6f 00 63 00 61 00 74 00 6f 00 72 00 41 00 50 00 49 00))}
		$ = {((4e 61 74 69 76 65 48 65 6c 70 65 72) | (4e 00 61 00 74 00 69 00 76 00 65 00 48 00 65 00 6c 00 70 00 65 00 72 00))}
		$ = {((4e 6f 72 64 41 70 70) | (4e 00 6f 00 72 00 64 00 41 00 70 00 70 00))}
		$ = {((4f 70 65 6e 55 70 64 61 74 65) | (4f 00 70 00 65 00 6e 00 55 00 70 00 64 00 61 00 74 00 65 00))}
		$ = {((4f 70 65 6e 56 50 4e) | (4f 00 70 00 65 00 6e 00 56 00 50 00 4e 00))}
		$ = {((4f 73 43 72 79 70 74) | (4f 00 73 00 43 00 72 00 79 00 70 00 74 00))}
		$ = {((50 61 72 73 53 74) | (50 00 61 00 72 00 73 00 53 00 74 00))}
		$ = {((50 61 72 74 73 53 65 6e 64 65 72) | (50 00 61 00 72 00 74 00 73 00 53 00 65 00 6e 00 64 00 65 00 72 00))}
		$ = {((52 65 63 6f 72 64 48 65 61 64 65 72 46 69 65 6c 64) | (52 00 65 00 63 00 6f 00 72 00 64 00 48 00 65 00 61 00 64 00 65 00 72 00 46 00 69 00 65 00 6c 00 64 00))}
		$ = {((53 63 61 6e 44 65 74 61 69 6c 73) | (53 00 63 00 61 00 6e 00 44 00 65 00 74 00 61 00 69 00 6c 00 73 00))}
		$ = {((53 63 61 6e 52 65 73 75 6c 74) | (53 00 63 00 61 00 6e 00 52 00 65 00 73 00 75 00 6c 00 74 00))}
		$ = {((53 63 61 6e 6e 65 64 43 6f 6f 6b 69 65) | (53 00 63 00 61 00 6e 00 6e 00 65 00 64 00 43 00 6f 00 6f 00 6b 00 69 00 65 00))}
		$ = {((53 63 61 6e 6e 65 64 46 69 6c 65) | (53 00 63 00 61 00 6e 00 6e 00 65 00 64 00 46 00 69 00 6c 00 65 00))}
		$ = {((53 63 61 6e 6e 69 6e 67 41 72 67 73) | (53 00 63 00 61 00 6e 00 6e 00 69 00 6e 00 67 00 41 00 72 00 67 00 73 00))}
		$ = {((53 65 6e 64 65 72 46 61 63 74 6f 72 79) | (53 00 65 00 6e 00 64 00 65 00 72 00 46 00 61 00 63 00 74 00 6f 00 72 00 79 00))}
		$ = {((53 71 6c 69 74 65 4d 61 73 74 65 72 45 6e 74 72 79) | (53 00 71 00 6c 00 69 00 74 00 65 00 4d 00 61 00 73 00 74 00 65 00 72 00 45 00 6e 00 74 00 72 00 79 00))}
		$ = {((53 74 72 69 6e 67 44 65 63 72 79 70 74) | (53 00 74 00 72 00 69 00 6e 00 67 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00))}
		$ = {((53 79 73 74 65 6d 48 61 72 64 77 61 72 65) | (53 00 79 00 73 00 74 00 65 00 6d 00 48 00 61 00 72 00 64 00 77 00 61 00 72 00 65 00))}
		$ = {((53 79 73 74 65 6d 49 6e 66 6f 48 65 6c 70 65 72) | (53 00 79 00 73 00 74 00 65 00 6d 00 49 00 6e 00 66 00 6f 00 48 00 65 00 6c 00 70 00 65 00 72 00))}
		$ = {((54 61 62 6c 65 45 6e 74 72 79) | (54 00 61 00 62 00 6c 00 65 00 45 00 6e 00 74 00 72 00 79 00))}
		$ = {((54 61 73 6b 52 65 73 6f 6c 76 65 72) | (54 00 61 00 73 00 6b 00 52 00 65 00 73 00 6f 00 6c 00 76 00 65 00 72 00))}
		$ = {((55 70 64 61 74 65 41 63 74 69 6f 6e) | (55 00 70 00 64 00 61 00 74 00 65 00 41 00 63 00 74 00 69 00 6f 00 6e 00))}
		$ = {((55 70 64 61 74 65 54 61 73 6b) | (55 00 70 00 64 00 61 00 74 00 65 00 54 00 61 00 73 00 6b 00))}
		$ = {((57 61 6c 6c 65 74 43 6f 6e 66 69 67) | (57 00 61 00 6c 00 6c 00 65 00 74 00 43 00 6f 00 6e 00 66 00 69 00 67 00))}

	condition:
		45 of them
}

rule fsRedline : hardened
{
	meta:
		description = "FsYARA - Malware Trends"
		vetted_family = "redline"
		score = 75

	condition:
		RedLine or redline_payload or Windows_Trojan_RedLineStealer_17ee6a17 or Windows_Trojan_RedLineStealer_f54632eb or Windows_Trojan_RedLineStealer_3d9371fd or Windows_Trojan_RedLineStealer_63e7e006 or Windows_Trojan_RedLineStealer_f07b3cb4 or Windows_Trojan_RedLineStealer_4df4bcb6 or Windows_Trojan_RedLineStealer_15ee6903 or Windows_Trojan_RedLineStealer_6dfafd7b or Windows_Trojan_RedLineStealer_983cd7a7 or win_redline_loader_dec_2023 or RedLineDropperAHK or RedLineDropperEXE or RedLine_1 or Win32_Trojan_Packed_RedLineStealer or Mal_Stealer_NET_Redline_Aug_2020_1 or Windows_Trojan_RedLineStealer_d25e974b or Windows_Trojan_RedLineStealer_ed346e4c or win_redline_payload_dec_2023 or RedLine_b
}

