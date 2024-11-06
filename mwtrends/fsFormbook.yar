rule Formbook
{
	meta:
		author = "kevoreilly"
		description = "Formbook Payload"
		cape_type = "Formbook Payload"
		packed = "9e38c0c3c516583da526016c4c6a671c53333d3d156562717db79eac63587522"
		packed = "2379a4e1ccdd7849ad7ea9e11ee55b2052e58dda4628cd4e28c3378de503de23"
		ruleset = "Formbook.yar"
		repository = "kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/9c8d6da44b595f8140a5cd76edd8101f6812c3b0/data/yara/CAPE/Formbook.yar"
		license = "Other"
		score = 75

	strings:
		$remap_ntdll = {33 56 0? 8D 86 [2] 00 00 68 F0 00 00 00 50 89 56 ?? E8 [4] 8B [1-5] 6A 00 6A 04 8D 4D ?? 51 6A 07 52 56 E8 [4] 8B 45 ?? 83 C4 20 3B}
		$rc4dec = {F7 E9 C1 FA 03 8B C2 C1 E8 1F 03 C2 8D 04 80 03 C0 03 C0 8B D1 2B D0 8A 04 3A 88 8C 0D [4] 88 84 0D [4] 41 81 F9 00 01 00 00 7C}
		$decrypt = {8A 50 01 28 10 48 49 75 F7 83 FE 01 76 14 8B C7 8D 4E FF 8D 9B 00 00 00 00 8A 50 01 28 10 40 49 75 F7}
		$string = {33 C0 66 39 01 74 0B 8D 49 00 40 66 83 3C 41 00 75 F8 8B 55 0C 8D 44 00 02 50 52 51 E8}
		$mutant = {64 A1 18 00 00 00 8B 40 ?? 89 45 ?? 8B 45 ?? 8B 40 ?? 8B E5 5D C3}
		$postmsg = {8B 7D 0C 6A 00 6A 00 68 11 01 00 00 57 FF D6 85 C0 75 ?? 50}

	condition:
		2 of them
}

rule Windows_Trojan_Formbook_1112e116
{
	meta:
		author = "Elastic Security"
		id = "1112e116-dee0-4818-a41f-ca5c1c41b4b8"
		fingerprint = "b8b88451ad8c66b54e21455d835a5d435e52173c86e9b813ffab09451aff7134"
		creation_date = "2021-06-14"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.Formbook"
		reference = "https://www.elastic.co/security-labs/formbook-adopts-cab-less-approach"
		reference_sample = "6246f3b89f0e4913abd88ae535ae3597865270f58201dc7f8ec0c87f15ff370a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_Formbook.yar"
		repository = "elastic/protections-artifacts"
		source_url = "https://github.com/elastic/protections-artifacts/blob/3bbef930abab9814b2fdb4704be075ab1daf2ea0/yara/rules/Windows_Trojan_Formbook.yar"
		score = 75

	strings:
		$a1 = { 3C 30 50 4F 53 54 74 09 40 }
		$a2 = { 74 0A 4E 0F B6 08 8D 44 08 01 75 F6 8D 70 01 0F B6 00 8D 55 }
		$a3 = { 1A D2 80 E2 AF 80 C2 7E EB 2A 80 FA 2F 75 11 8A D0 80 E2 01 }
		$a4 = { 04 83 C4 0C 83 06 07 5B 5F 5E 8B E5 5D C3 8B 17 03 55 0C 6A 01 83 }

	condition:
		any of them
}

rule Windows_Trojan_Formbook_772cc62d
{
	meta:
		author = "Elastic Security"
		id = "772cc62d-345c-42d8-97ab-f67e447ddca4"
		fingerprint = "3d732c989df085aefa1a93b38a3c078f9f0c3ee214292f6c1e31a9fc1c9ae50e"
		creation_date = "2022-05-23"
		last_modified = "2022-07-18"
		threat_name = "Windows.Trojan.Formbook"
		reference = "https://www.elastic.co/security-labs/formbook-adopts-cab-less-approach"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_Formbook.yar"
		repository = "elastic/protections-artifacts"
		source_url = "https://github.com/elastic/protections-artifacts/blob/3bbef930abab9814b2fdb4704be075ab1daf2ea0/yara/rules/Windows_Trojan_Formbook.yar"
		score = 75

	strings:
		$a1 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; Trident/7.0; rv:11.0) like Gecko"
		$a2 = "signin"
		$a3 = "persistent"
		$r1 = /.\:\\Users\\[^\\]{1,50}\\AppData\\Roaming\\[a-zA-Z0-9]{8}\\[a-zA-Z0-9]{3}log\.ini/ wide

	condition:
		2 of ($a*) and 
		$r1
}

rule Windows_Trojan_Formbook_5799d1f2
{
	meta:
		author = "Elastic Security"
		id = "5799d1f2-4d4f-49d6-b010-67d2fbc04824"
		fingerprint = "b262c4223e90c539c73831f7f833d25fe938eaecb77ca6d2e93add6f93e7d75d"
		creation_date = "2022-06-08"
		last_modified = "2022-09-29"
		threat_name = "Windows.Trojan.Formbook"
		reference = "https://www.elastic.co/security-labs/formbook-adopts-cab-less-approach"
		reference_sample = "8555a6d313cb17f958fc2e08d6c042aaff9ceda967f8598ac65ab6333d14efd9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_Formbook.yar"
		repository = "elastic/protections-artifacts"
		source_url = "https://github.com/elastic/protections-artifacts/blob/3bbef930abab9814b2fdb4704be075ab1daf2ea0/yara/rules/Windows_Trojan_Formbook.yar"
		score = 75

	strings:
		$a = { E9 C5 9C FF FF C3 E8 00 00 00 00 58 C3 68 }

	condition:
		all of them
}

rule malware_Formbook_strings
{
	meta:
		description = "detect Formbook in memory"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "memory scan"
		reference = "internal research"
		ruleset = "formbook.yara"
		repository = "JPCERTCC/jpcert-yara"
		source_url = "https://github.com/JPCERTCC/jpcert-yara/blob/0722a9365ec6bc969c517c623cd166743d1bc473/other/formbook.yara"
		license = "Other"
		score = 75

	strings:
		$sqlite3step = { 68 34 1c 7b e1 }
		$sqlite3text = { 68 38 2a 90 c5 }
		$sqlite3blob = { 68 53 d8 7f 8c }

	condition:
		all of them
}

rule win_formbook_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.formbook."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.formbook"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		ruleset = "win.formbook_auto.yar"
		repository = "malpedia/signator-rules"
		source_url = "https://github.com/malpedia/signator-rules/blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.formbook_auto.yar"
		score = 75

	strings:
		$sequence_0 = { 5b 5f 5e 8be5 5d c3 8d0476 }
		$sequence_1 = { 6a0d 8d8500fcffff 50 56 e8???????? 8d8d00fcffff 51 }
		$sequence_2 = { 56 e8???????? 8d4df4 51 56 e8???????? 8d55e4 }
		$sequence_3 = { c3 3c04 752b 8b7518 8b0e 8b5510 8b7d14 }
		$sequence_4 = { 56 e8???????? 83c418 395df8 0f85a0000000 8b7d18 395f10 }
		$sequence_5 = { c745fc01000000 e8???????? 6a14 8d4dec 51 50 }
		$sequence_6 = { e8???????? 83c428 8906 85c0 75a8 5f 33c0 }
		$sequence_7 = { 56 e8???????? 6a03 ba5c000000 57 56 66891446 }
		$sequence_8 = { 3b75d0 72c0 8d55f8 52 e8???????? }
		$sequence_9 = { 8d8df6f7ffff 51 c745fc00000000 668985f4f7ffff e8???????? 8b7508 }

	condition:
		7 of them and 
		filesize <371712
}

rule Formbook_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2018-11-23"
		version = "1"
		description = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator 0.1a"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.formbook"
		malpedia_version = "20180607"
		malpedia_license = "CC BY-NC-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		cape_type = "Formbook Payload"
		original_yara_name = "Formbook"
		ruleset = "Formbook.yar"
		repository = "ctxis/CAPE"
		source_url = "https://github.com/ctxis/CAPE/blob/dae9fa6a254ecdbabeb7eb0d2389fa63722c1e82/data/yara/CAPE/Formbook.yar"
		score = 75

	strings:
		$sequence_0 = { 03c8 0f31 2bc1 8945fc }
		$sequence_1 = { 3c24 0f8476ffffff 3c25 7494 }
		$sequence_2 = { 3b4f14 7395 85c9 7491 }
		$sequence_3 = { 3c69 7544 8b7d18 8b0f }
		$sequence_4 = { 5d c3 8d507c 80fa07 }
		$sequence_5 = { 0fbe5c0e01 0fb6540e02 83e30f c1ea06 }
		$sequence_6 = { 57 8945fc 8945f4 8945f8 }
		$sequence_7 = { 66890c02 5b 8be5 5d }
		$sequence_8 = { 3c54 7404 3c74 75f4 }
		$sequence_9 = { 56 6803010000 8d8595feffff 6a00 }

	condition:
		7 of them
}

rule Windows_Trojan_Formbook : FormBook_malware
{
	meta:
		author = "@malgamy12"
		date = "2022-11-8"
		license = "DRL 1.1"
		sample1 = "9fc57307d1cce6f6d8946a7dae41447b"
		sample2 = "0f4a7fa6e654b48c0334b8b88410eaed"
		sample3 = "0a25d588340300461738a677d0b53cd2"
		sample4 = "57d7bd215e4c4d03d73addec72936334"
		sample5 = "c943e31f7927683dc1b628f0972e801b"
		sample6 = "db87f238bb4e972ef8c0b94779798fa9"
		sample7 = "8ba1449ee35200556ecd88f23a35863a"
		sample8 = "8ca20642318337816d5db9666e004172"
		sample9 = "280f7c87c98346102980c514d2dd25c8"
		ruleset = "formbook.yara"
		repository = "MalGamy/YARA_Rules"
		source_url = "https://github.com/MalGamy/YARA_Rules/blob/1f538fcd5fe6d8aeec6c8a8394a785b69872b7a7/formbook.yara"
		score = 75

	strings:
		$a1 = { 8B 45 ?? BA ?? [3] 8B CF D3 E2 84 14 03 74 ?? 8B 4D ?? 31 0E 8B 55 ?? 31 56 ?? 8B 4D ?? 8B 55 ?? 31 4E ?? 31 56 ?? }
		$a2 = { 0F B6 3A 8B C8 C1 E9 ?? 33 CF 81 E1 [4] C1 E0 ?? 33 84 8D [4] 42 4E }
		$a3 = { 1A D2 80 E2 ?? 80 C2 ?? EB ?? 80 FA ?? 75 ?? 8A D0 80 E2 ?? }
		$a4 = { 80 E2 ?? F6 DA 1A D2 80 E2 ?? 80 C2 ?? }

	condition:
		3 of them
}

rule fsFormbook
{
	meta:
		description = "FsYARA - Malware Trends"
		vetted_family = "formbook"
		score = 75

	condition:
		Formbook or 
		Windows_Trojan_Formbook_1112e116 or 
		Windows_Trojan_Formbook_772cc62d or 
		Windows_Trojan_Formbook_5799d1f2 or 
		malware_Formbook_strings or 
		win_formbook_auto or 
		Formbook_1 or 
		Windows_Trojan_Formbook
}

