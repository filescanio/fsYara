rule Latrodectus
{
	meta:
		author = "enzok"
		description = "Latrodectus Payload"
		cape_type = "Latrodectus Payload"
		hash = "a547cff9991a713535e5c128a0711ca68acf9298cc2220c4ea0685d580f36811"
		ruleset = "Latrodectus.yar"
		repository = "kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/3c6d7d4f232e43db68ca2dd711f5e9d8e9e033cb/data/yara/CAPE/Latrodectus.yar"
		license = "Other"
		score = 75

	strings:
		$fnvhash1 = {C7 04 24 C5 9D 1C 81 48 8B 44 24 20 48 89 44 24 08}
		$fnvhash2 = {8B 0C 24 33 C8 8B C1 89 04 24 69 04 24 93 01 00 01}
		$procchk1 = {E8 [3] FF 85 C0 74 [2] FF FF FF FF E9 [4] E8 [4] 89 44 24 ?? E8 [4] 83 F8 4B 73 ?? 83 [3] 06}
		$procchk2 = {72 [2] FF FF FF FF E9 [4] E8 [4] 83 F8 32 73 ?? 83 [3] 06}

	condition:
		all of them
}

rule Windows_Trojan_Latrodectus_841ff697
{
	meta:
		author = "Elastic Security"
		id = "841ff697-f389-497a-b813-3b9e19cba26e"
		fingerprint = "e52d8706aeeedb09d5e4e223af74d8de2f136a20db96c0a823c1e8b3af379e19"
		creation_date = "2024-03-13"
		last_modified = "2024-03-21"
		threat_name = "Windows.Trojan.Latrodectus"
		reference_sample = "aee22a35cbdac3f16c3ed742c0b1bfe9739a13469cf43b36fb2c63565111028c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_Latrodectus.yar"
		repository = "elastic/protections-artifacts"
		source_url = "https://github.com/elastic/protections-artifacts/blob/f98777756fcfbe5ab05a296388044a2dbb962557/yara/rules/Windows_Trojan_Latrodectus.yar"
		score = 75

	strings:
		$Str1 = { 48 83 EC 38 C6 44 24 20 73 C6 44 24 21 63 C6 44 24 22 75 C6 44 24 23 62 C6 44 24 24 }
		$Str2 = { 48 89 44 24 40 EB 02 EB 90 48 8B 4C 24 20 E8 1B D7 FF FF 48 8B 44 24 40 48 81 C4 E8 02 00 00 C3 CC CC 48 81 EC B8 00 00 00 }
		$Str3 = { 44 24 68 BA 03 00 00 00 48 8B 4C 24 48 FF 15 ED D1 00 00 85 C0 75 14 48 8B 4C 24 50 E8 73 3E 00 00 B8 FF FF FF FF E9 A6 00 }

	condition:
		any of them
}

rule latrodectus_dll_str_decrypt
{
	meta:
		author = "0x0d4y"
		description = "This rule detects the Latrodectus DLL Decrypt String Algorithm."
		date = "2024-04-30"
		score = 75
		yarahub_reference_link = "https://0x0d4y.blog/latrodectus-technical-analysis-of-the-new-icedid/"
		yarahub_uuid = "2b40216b-25f4-48b7-9948-fe1bcd2f9f1e"
		yarahub_reference_md5 = "277c879bba623c8829090015437e002b"
		yarahub_license = "CC BY 4.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		malpedia_family = "win.unidentified_111"
		ruleset = "latrodectus_dll_str_decrypt.yara"
		repository = "Icaro-Cesar/OCEK"
		source_url = "https://github.com/Icaro-Cesar/OCEK/blob/f6a2e421b3f361c144ebfdc34f9fe15b59b4bace/yara_rules/latrodectus_dll_str_decrypt.yara"
		license = "MIT License"

	strings:
		$str_decrypt = {
      ?? ?? ?? ?? ?? 0f b7 44 ?? ?? 48 8b 4c 24 40 8a 04 01 88 44 24 20 0f b7 44 ?? ?? 48 8b 4c 24 40 8a 04 01 88 44 24 21 0f b6 44 24 20 0f b6 4c 24 21 8d 44 01 0a 88 44 24 21 8b 4c 24 2c ?? ?? ?? ?? ?? 89 44 24 2c 0f b7 44 ?? ?? 0f b6 4c 24 20 48 8b 54 24 48 0f b6 04 02 8d 44 08 0a 0f b7 4c ?? ?? 48 8b 54 24 48 88 04 0a 0f b6 44 24 20 0f b6 4c 24 2c 33 c1 0f b7 4c ?? ?? 48 8b 54 24 48 88 04 0a ?? ?? ?? ?? ??
      }

	condition:
		uint16(0)==0x5a4d and 
		$str_decrypt
}

rule Latrodectus_1
{
	meta:
		author = "kevoreilly"
		description = "Latrodectus export selection"
		cape_options = "export=$export"
		hash = "378d220bc863a527c2bca204daba36f10358e058df49ef088f8b1045604d9d05"
		original_yara_name = "Latrodectus"
		ruleset = "Latrodectus.yar"
		repository = "kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/3c6d7d4f232e43db68ca2dd711f5e9d8e9e033cb/analyzer/windows/data/yara/Latrodectus.yar"
		license = "Other"
		score = 75

	strings:
		$export = {48 8B C4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20 41 56 48 83 EC 30 4C 8B 05 [4] 33 D2 C7 40 [5] 88 50 ?? 49 63 40 3C 42 8B 8C 00 88 00 00 00 85 C9 0F 84}

	condition:
		uint16(0)==0x5A4D and 
		all of them
}

rule fsLatrodectus
{
	meta:
		description = "FsYARA - Malware Trends"
		vetted_family = "latrodectus"
		score = 75

	condition:
		Latrodectus or 
		Windows_Trojan_Latrodectus_841ff697 or 
		latrodectus_dll_str_decrypt or 
		Latrodectus_1
}

