rule Amadey
{
	meta:
		author = "kevoreilly"
		description = "Amadey Payload"
		cape_type = "Amadey Payload"
		hash = "988258716d5296c1323303e8fe4efd7f4642c87bfdbe970fe9a3bb3f410f70a4"
		ruleset = "Amadey.yar"
		repository = "kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/9c8d6da44b595f8140a5cd76edd8101f6812c3b0/data/yara/CAPE/Amadey.yar"
		license = "Other"
		score = 75

	strings:
		$decode1 = {8B D1 B8 FF FF FF 7F D1 EA 2B C2 3B C8 76 07 BB FF FF FF 7F EB 08 8D 04 0A 3B D8 0F 42 D8}
		$decode2 = {33 D2 8B 4D ?? 8B C7 F7 F6 8A 84 3B [4] 2A 44 0A 01 88 87 [4] 47 8B 45 ?? 8D 50 01}
		$decode3 = {8A 04 02 88 04 0F 41 8B 7D ?? 8D 42 01 3B CB 7C}

	condition:
		uint16(0)==0x5A4D and 
		2 of them
}

rule Windows_Trojan_Amadey_7abb059b
{
	meta:
		author = "Elastic Security"
		id = "7abb059b-4001-4eec-8185-1e0497e15062"
		fingerprint = "686ae7cf62941d7db051fa8c45f0f7a27440fa0fdc5f0919c9667dfeca46ca1f"
		creation_date = "2021-06-28"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.Amadey"
		reference_sample = "33e6b58ce9571ca7208d1c98610005acd439f3e37d2329dae8eb871a2c4c297e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_Amadey.yar"
		repository = "elastic/protections-artifacts"
		source_url = "https://github.com/elastic/protections-artifacts/blob/3bbef930abab9814b2fdb4704be075ab1daf2ea0/yara/rules/Windows_Trojan_Amadey.yar"
		score = 75

	strings:
		$a = { 18 83 78 14 10 72 02 8B 00 6A 01 6A 00 6A 00 6A 00 6A 00 56 }

	condition:
		all of them
}

rule Windows_Trojan_Amadey_c4df8d4a
{
	meta:
		author = "Elastic Security"
		id = "c4df8d4a-01f4-466f-8225-7c7f462b29e7"
		fingerprint = "4623c591ea465e23f041db77dc68ddfd45034a8bde0f20fd5fbcec060851200c"
		creation_date = "2021-06-28"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.Amadey"
		reference_sample = "9039d31d0bd88d0c15ee9074a84f8d14e13f5447439ba80dd759bf937ed20bf2"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_Amadey.yar"
		repository = "elastic/protections-artifacts"
		source_url = "https://github.com/elastic/protections-artifacts/blob/3bbef930abab9814b2fdb4704be075ab1daf2ea0/yara/rules/Windows_Trojan_Amadey.yar"
		score = 75

	strings:
		$a1 = "D:\\Mktmp\\NL1\\Release\\NL1.pdb" fullword

	condition:
		all of them
}

rule win_amadey_a9f4
{
	meta:
		author = "Johannes Bader"
		date = "2022-11-17"
		description = "matches unpacked Amadey samples"
		hash_md5 = "25cfcfdb6d73d9cfd88a5247d4038727"
		hash_sha1 = "912d1ef61750bc622ee069cdeed2adbfe208c54d"
		hash_sha256 = "03effd3f94517b08061db014de12f8bf01166a04e93adc2f240a6616bb3bd29a"
		malpedia_family = "win.amadey"
		tlp = "TLP:WHITE"
		version = "v1.0"
		yarahub_author_email = "yara@bin.re"
		yarahub_author_twitter = "@viql"
		yarahub_license = "CC BY-SA 4.0"
		yarahub_reference_md5 = "25cfcfdb6d73d9cfd88a5247d4038727"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_uuid = "a9f41cd4-3f67-42fc-b310-e9b251c95fe4"
		ruleset = "win_amadey_a9f4.yara"
		repository = "CYB3RMX/Qu1cksc0pe"
		source_url = "https://github.com/CYB3RMX/Qu1cksc0pe/blob/8d74a4116951b46b9284102850f28f1082c17c04/Systems/Windows/YaraRules_Windows/win_amadey_a9f4.yara"
		license = "GNU General Public License v3.0"
		score = 75

	strings:
		$pdb = "\\Amadey\\Release\\Amadey.pdb"
		$keys = /stoi argument out of range\x00\x00[a-f0-9]{32}\x00{1,16}[a-f0-9]{32}\x00{1,4}[a-f0-9]{6}\x00{1,4}[a-f0-9]{32}\x00/

	condition:
		uint16(0)==0x5A4D and 
		($pdb or 
			$keys)
}

rule win_amadey_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.amadey."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.amadey"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		ruleset = "win.amadey_auto.yar"
		repository = "malpedia/signator-rules"
		source_url = "https://github.com/malpedia/signator-rules/blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.amadey_auto.yar"
		score = 75

	strings:
		$sequence_0 = { ebb0 b8???????? 83c410 5b }
		$sequence_1 = { e8???????? 89c2 8b45f4 89d1 ba00000000 f7f1 }
		$sequence_2 = { c744240805000000 c744240402000000 890424 e8???????? }
		$sequence_3 = { c9 c3 55 89e5 81ecc8010000 }
		$sequence_4 = { c70424???????? e8???????? 8b45fc 89442408 c7442404???????? 8b4508 890424 }
		$sequence_5 = { c744240800020000 8d85f8fdffff 89442404 891424 e8???????? 83ec20 }
		$sequence_6 = { c70424???????? e8???????? 890424 e8???????? 84c0 7407 c745fc05000000 }
		$sequence_7 = { 83ec04 8945f4 837df400 7454 8b4508 890424 }
		$sequence_8 = { 83fa10 722f 8b8d78feffff 42 }
		$sequence_9 = { 8b8d78feffff 42 8bc1 81fa00100000 7214 8b49fc }
		$sequence_10 = { 68???????? e8???????? 8d4dcc e8???????? 83c418 }
		$sequence_11 = { 68???????? e8???????? 8d4db4 e8???????? 83c418 }
		$sequence_12 = { 52 6a02 6a00 51 ff75f8 ff15???????? ff75f8 }
		$sequence_13 = { 8bce e8???????? e8???????? 83c418 e8???????? e9???????? 52 }
		$sequence_14 = { c705????????0c000000 eb31 c705????????0d000000 eb25 83f901 750c }
		$sequence_15 = { 50 68???????? 83ec18 8bcc 68???????? e8???????? }
		$sequence_16 = { 8bcc 68???????? e8???????? 8d8d78feffff e8???????? 83c418 }
		$sequence_17 = { c78584fdffff0f000000 c68570fdffff00 83fa10 722f 8b8d58fdffff 42 }
		$sequence_18 = { c78520fdffff00000000 c78524fdffff0f000000 c68510fdffff00 83fa10 722f }
		$sequence_19 = { 51 e8???????? 83c408 8b950cfdffff c78520fdffff00000000 c78524fdffff0f000000 }

	condition:
		7 of them and 
		filesize <529408
}

rule win_amadey_bytecodes_oct_2023
{
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/10/15"
		description = "Detects bytecodes present in Amadey Bot malware"
		sha256 = "4165190e60ad5abd437c7768174b12748d391b8b97c874b5bdf8d025c5e17f43"
		ruleset = "win_amadey_bytecodes_oct_2023.yar"
		repository = "embee-research/Yara-detection-rules"
		source_url = "https://github.com/embee-research/Yara-detection-rules/blob/ac56d6f6fd2a30c8cb6e5c0455d6519210a8b0f4/Rules/win_amadey_bytecodes_oct_2023.yar"
		score = 75

	strings:
		$s1 = {8b ?? fc 83 c1 23 2b c2 83 c0 fc 83 f8 1f 77}
		$s2 = {80 ?? ?? ?? 3d 75 }
		$s3 = {8b c1 c1 f8 10 88 ?? ?? 8b c1 c1 f8 08}

	condition:
		$s1 and 
		$s2 and 
		$s3
}

rule fsAmadey
{
	meta:
		description = "FsYARA - Malware Trends"
		vetted_family = "amadey"

	condition:
		Amadey or 
		Windows_Trojan_Amadey_7abb059b or 
		Windows_Trojan_Amadey_c4df8d4a or 
		win_amadey_a9f4 or 
		win_amadey_auto or 
		win_amadey_bytecodes_oct_2023
}

