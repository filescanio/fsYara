rule Njrat : RAT
{
	meta:
		description = "Njrat"
		author = "botherder https://github.com/botherder"
		ruleset = "RAT_Njrat.yar"
		repository = "Yara-Rules/rules"
		source_url = "https://github.com/Yara-Rules/rules/blob/0f93570194a80d2f2032869055808b0ddcdfb360/malware/RAT_Njrat.yar"
		license = "GNU General Public License v2.0"
		score = 75

	strings:
		$string1 = /(F)romBase64String/
		$string2 = /(B)ase64String/
		$string3 = /(C)onnected/ wide ascii
		$string4 = /(R)eceive/
		$string5 = /(S)end/ wide ascii
		$string6 = /(D)ownloadData/ wide ascii
		$string7 = /(D)eleteSubKey/ wide ascii
		$string8 = /(g)et_MachineName/
		$string9 = /(g)et_UserName/
		$string10 = /(g)et_LastWriteTime/
		$string11 = /(G)etVolumeInformation/
		$string12 = /(O)SFullName/ wide ascii
		$string13 = /(n)etsh firewall/ wide
		$string14 = /(c)md\.exe \/k ping 0 & del/ wide
		$string15 = /(c)md\.exe \/c ping 127\.0\.0\.1 & del/ wide
		$string16 = /(c)md\.exe \/c ping 0 -n 2 & del/ wide
		$string17 = {7C 00 27 00 7C 00 27 00 7C}

	condition:
		10 of them
}

rule njrat1 : RAT
{
	meta:
		author = "Brian Wallace @botnet_hunter"
		author_email = "bwall@ballastsecurity.net"
		date = "2015-05-27"
		description = "Identify njRat"
		ruleset = "RAT_Njrat.yar"
		repository = "Yara-Rules/rules"
		source_url = "https://github.com/Yara-Rules/rules/blob/0f93570194a80d2f2032869055808b0ddcdfb360/malware/RAT_Njrat.yar"
		license = "GNU General Public License v2.0"
		score = 75

	strings:
		$a1 = "netsh firewall add allowedprogram " wide
		$a2 = "SEE_MASK_NOZONECHECKS" wide
		$b1 = "[TAP]" wide
		$b2 = " & exit" wide
		$c1 = "md.exe /k ping 0 & del " wide
		$c2 = "cmd.exe /c ping 127.0.0.1 & del" wide
		$c3 = "cmd.exe /c ping" wide

	condition:
		1 of ($a*) and 
		1 of ($b*) and 
		1 of ($c*)
}

rule win_exe_njRAT
{
	meta:
		author = "info@fidelissecurity.com"
		descripion = "njRAT - Remote Access Trojan"
		comment = "Variants have also been observed obfuscated with .NET Reactor"
		filetype = "pe"
		date = "2013-07-15"
		version = "1.0"
		hash1 = "92ee1fb5df21d8cfafa2b02b6a25bd3b"
		hash2 = "3576d40ce18bb0349f9dfa42b8911c3a"
		hash3 = "24cc5b811a7f9591e7f2cb9a818be104"
		hash4 = "3ad5fded9d7fdf1c2f6102f4874b2d52"
		hash5 = "a98b4c99f64315aac9dd992593830f35"
		hash6 = "5fcb5282da1a2a0f053051c8da1686ef"
		hash7 = "a669c0da6309a930af16381b18ba2f9d"
		hash8 = "79dce17498e1997264346b162b09bde8"
		hash9 = "fc96a7e27b1d3dab715b2732d5c86f80"
		ref1 = "http://bit.ly/19tlf4s"
		ref2 = "http://www.fidelissecurity.com/threatadvisory"
		ref3 = "http://www.threatgeek.com/2013/06/fidelis-threat-advisory-1009-njratuncovered.html"
		ref4 = "http://threatgeek.typepad.com/files/fta-1009---njrat-uncovered.pdf"
		ruleset = "RAT_Njrat.yar"
		repository = "Yara-Rules/rules"
		source_url = "https://github.com/Yara-Rules/rules/blob/0f93570194a80d2f2032869055808b0ddcdfb360/malware/RAT_Njrat.yar"
		license = "GNU General Public License v2.0"
		score = 75

	strings:
		$magic = "MZ"
		$string_setA_1 = "FromBase64String"
		$string_setA_2 = "Base64String"
		$string_setA_3 = "Connected" wide ascii
		$string_setA_4 = "Receive"
		$string_setA_5 = "DeleteSubKey" wide ascii
		$string_setA_6 = "get_MachineName"
		$string_setA_7 = "get_UserName"
		$string_setA_8 = "get_LastWriteTime"
		$string_setA_9 = "GetVolumeInformation"
		$string_setB_1 = "OSFullName" wide ascii
		$string_setB_2 = "Send" wide ascii
		$string_setB_3 = "Connected" wide ascii
		$string_setB_4 = "DownloadData" wide ascii
		$string_setB_5 = "netsh firewall" wide
		$string_setB_6 = "cmd.exe /k ping 0 & del" wide

	condition:
		($magic at 0) and 
		( all of ($string_setA*) or 
			all of ($string_setB*))
}

rule njRat
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/njRat"
		maltype = "Remote Access Trojan"
		filetype = "exe"
		ruleset = "njRat.yar"
		repository = "kevthehermit/RATDecoders"
		source_url = "https://github.com/kevthehermit/RATDecoders/blob/d675ba1c06e6dd8365149c9ee8a8db1a6e5e508e/malwareconfig/yaraRules/njRat.yar"
		license = "MIT License"
		score = 75

	strings:
		$s1 = {7C 00 27 00 7C 00 27 00 7C}
		$s2 = "netsh firewall add allowedprogram" wide
		$s3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide
		$s4 = "yy-MM-dd" wide
		$v1 = "cmd.exe /k ping 0 & del" wide
		$v2 = "cmd.exe /c ping 127.0.0.1 & del" wide
		$v3 = "cmd.exe /c ping 0 -n 2 & del" wide

	condition:
		all of ($s*) and 
		any of ($v*)
}

rule Windows_Trojan_Njrat_30f3c220
{
	meta:
		author = "Elastic Security"
		id = "30f3c220-b8dc-45a1-bcf0-027c2f76fa63"
		fingerprint = "d15e131bca6beddcaecb20fffaff1784ad8a33a25e7ce90f7450d1a362908cc4"
		creation_date = "2021-06-13"
		last_modified = "2021-10-04"
		threat_name = "Windows.Trojan.Njrat"
		reference_sample = "741a0f3954499c11f9eddc8df7c31e7c59ca41f1a7005646735b8b1d53438c1b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_Njrat.yar"
		repository = "elastic/protections-artifacts"
		source_url = "https://github.com/elastic/protections-artifacts/blob/3bbef930abab9814b2fdb4704be075ab1daf2ea0/yara/rules/Windows_Trojan_Njrat.yar"
		score = 75

	strings:
		$a1 = "get_Registry" ascii fullword
		$a2 = "SEE_MASK_NOZONECHECKS" wide fullword
		$a3 = "Download ERROR" wide fullword
		$a4 = "cmd.exe /c ping 0 -n 2 & del \"" wide fullword
		$a5 = "netsh firewall delete allowedprogram \"" wide fullword
		$a6 = "[+] System : " wide fullword

	condition:
		3 of them
}

rule Windows_Trojan_Njrat_eb2698d2
{
	meta:
		author = "Elastic Security"
		id = "eb2698d2-c9fa-4b0b-900f-1c4c149cca4b"
		fingerprint = "8eedcdabf459de87e895b142cd1a1b8c0e403ad8ec6466bc6ca493dd5daa823b"
		creation_date = "2023-05-04"
		last_modified = "2023-06-13"
		threat_name = "Windows.Trojan.Njrat"
		reference_sample = "d537397bc41f0a1cb964fa7be6658add5fe58d929ac91500fc7770c116d49608"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_Njrat.yar"
		repository = "elastic/protections-artifacts"
		source_url = "https://github.com/elastic/protections-artifacts/blob/3bbef930abab9814b2fdb4704be075ab1daf2ea0/yara/rules/Windows_Trojan_Njrat.yar"
		score = 75

	strings:
		$a1 = { 24 65 66 65 39 65 61 64 63 2D 64 34 61 65 2D 34 62 39 65 2D 62 38 61 62 2D 37 65 34 37 66 38 64 62 36 61 63 39 }

	condition:
		all of them
}

rule malware_Njrat_strings
{
	meta:
		description = "detect njRAT in memory"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "memory scan"
		hash1 = "d5f63213ce11798879520b0e9b0d1b68d55f7727758ec8c120e370699a41379d"
		ruleset = "njrat.yara"
		repository = "JPCERTCC/jpcert-yara"
		source_url = "https://github.com/JPCERTCC/jpcert-yara/blob/0722a9365ec6bc969c517c623cd166743d1bc473/other/njrat.yara"
		license = "Other"
		score = 75

	strings:
		$reg = "SEE_MASK_NOZONECHECKS" wide fullword
		$msg = "Execute ERROR" wide fullword
		$ping = "cmd.exe /c ping 0 -n 2 & del" wide fullword

	condition:
		all of them
}

rule njRat_1
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/njRat"
		maltype = "Remote Access Trojan"
		filetype = "exe"
		family = "njrat"
		tags = "rat, njrat"
		original_yara_name = "njRat"
		ruleset = "rats.yara"
		repository = "opensourcesec/CIRTKit"
		source_url = "https://github.com/opensourcesec/CIRTKit/blob/58b8793ada69320ffdbdd4ecdc04a3bb2fa83c37/data/yara/rats.yara"
		license = "MIT License"
		score = 75

	strings:
		$s1 = {7C 00 27 00 7C 00 27 00 7C}
		$s2 = "netsh firewall add allowedprogram" wide
		$s3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide
		$s4 = "yyyy-MM-dd" wide
		$v1 = "cmd.exe /k ping 0 & del" wide
		$v2 = "cmd.exe /c ping 127.0.0.1 & del" wide
		$v3 = "cmd.exe /c ping 0 -n 2 & del" wide

	condition:
		all of ($s*) and 
		any of ($v*)
}

rule Njrat_1
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net> & ditekSHen"
		ref = "http://malwareconfig.com/stats/njRat"
		maltype = "Remote Access Trojan"
		filetype = "exe"
		cape_type = "Njrat Payload"
		original_yara_name = "Njrat"
		ruleset = "Njrat.yar"
		repository = "CAPESandbox/community"
		source_url = "https://github.com/CAPESandbox/community/blob/30a130d01407ba0f0637fb44e8159131a0c4e1e5/data/yara/CAPE/Njrat.yar"
		score = 75

	strings:
		$s1 = {7C 00 27 00 7C 00 27 00 7C}
		$s2 = "netsh firewall add allowedprogram" wide
		$s3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide
		$s4 = "yyyy-MM-dd" wide
		$v1 = "cmd.exe /k ping 0 & del" wide
		$v2 = "cmd.exe /c ping 127.0.0.1 & del" wide
		$v3 = "cmd.exe /c ping 0 -n 2 & del" wide
		$x1 = "netsh firewall delete allowedprogram" wide
		$x2 = "netsh firewall add allowedprogram" wide
		$x3 = { 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 (63|6b) 00 20 00 70 00 69 00 6e 00 67 }
		$x4 = "Execute ERROR" wide
		$x5 = "Download ERROR" wide
		$x6 = "[kl]" fullword wide

	condition:
		( all of ($s*) and 
			any of ($v*)) or 
		( uint16(0)==0x5a4d and 
			4 of ($x*))
}

rule njrat : rat
{
	meta:
		rule_group = "implant"
		implant = "njrat"
		description = "tested against NjRat versions 0.3.6 - 0.7d"
		organisation = "CSE"
		poc = "malware_dev@cse"
		rule_id = "CSE_900013"
		rule_version = "1"
		yara_version = "3.4"
		al_configdumper = "al_services.alsvc_configdecoder.dumpers.njRat.getConfig"
		al_configparser = "GenericParser"
		al_imported_by = "malware_dev"
		al_state_change_date = "2017-11-17"
		al_state_change_user = "stevegaron-cse"
		al_status = "DEPLOYED"
		author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
		classification = "U"
		creation_date = "2017-02-27T18:32:28.956448Z"
		date = "2015-11-18"
		last_saved_by = "malware_dev"
		sample = "unpacked: 2b96518a66d251fedb39264e668f588c (0.7d)"
		type = "info"
		updated = "2015-11-18"
		version = "1"
		ruleset = "sample_rules.yar"
		repository = "CybercentreCanada/assemblyline-base"
		source_url = "https://github.com/CybercentreCanada/assemblyline-base/blob/ecfbf3c5b391196e90687421031b44352febdf58/assemblyline/odm/random_data/sample_rules.yar"
		license = "MIT License"
		score = 75

	strings:
		$cnc_traffic_0 = {7C 00 27 00 7C 00 27 00 7C}
		$rights_0 = "netsh firewall add allowedprogram \"" wide
		$rights_1 = "netsh firewall delete allowedprogram \"" wide

	condition:
		( all of ($cnc_traffic_*)) and 
		( all of ($rights_*))
}

rule Windows_Trojan_Njrat_30f3c220_1
{
	meta:
		id = "30f3c220-b8dc-45a1-bcf0-027c2f76fa63"
		fingerprint = "2abd38871cb87838b94f359caa2f888ac350a2a753db55f4c919a426af0fb5fd"
		creation_date = "2021-06-13"
		last_modified = "2021-07-22"
		os = "Windows"
		arch = "x86"
		category_type = "Trojan"
		family = "Njrat"
		threat_name = "Windows.Trojan.Njrat"
		source = "Manual"
		maturity = "Diagnostic"
		reference_sample = "741a0f3954499c11f9eddc8df7c31e7c59ca41f1a7005646735b8b1d53438c1b"
		scan_type = "File, Memory"
		severity = 100
		original_yara_name = "Windows_Trojan_Njrat_30f3c220"
		ruleset = "elastic-agent-rules.yara"
		repository = "SpecterOps/Nemesis"
		source_url = "https://github.com/SpecterOps/Nemesis/blob/84d5986f759161f60dc2e5b538ec88d95b289e43/cmd/enrichment/enrichment/lib/public_yara/elastic-agent-rules.yara"
		license = "Other"
		score = 75

	strings:
		$a1 = "get_Registry" ascii fullword
		$a2 = "netsh firewall delete allowedprogram \"" wide fullword
		$a3 = "cmd.exe /c ping 0 -n 2 & del \"" wide fullword
		$a4 = "SEE_MASK_NOZONECHECKS" wide fullword
		$a5 = "Download ERROR" wide fullword

	condition:
		all of them
}

rule win_njrat
{
	meta:
		author = "CERT Polska"
		date = "2020-07-20"
		hash = "998b6ed5494b22e18d353fdd96226db3"
		description = "Detects unpacked NjRAT malware."
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.njrat"

	strings:
		$str_cmd1 = "md.exe /k ping 0 & del " wide
		$str_cmd2 = "cmd.exe /c ping 127.0.0.1 & del" wide
		$str_cmd3 = "cmd.exe /c ping" wide
		$str_cmd4 = "cmd.exe /C Y /N /D Y /T 1 & Del" wide
		$str_kl1 = "[kl]" wide
		$str_kl2 = "[TAP]" wide
		$str_kl3 = "[ENTER]" wide
		$op_config_07d = { 46 69 78 00 6B 00 57 52 4B 00 6D 61 69 6E 00 00 00 }
		$op_config_07d_indirect = { 54 00 45 00 4d 00 50 00 00 [1] 65 00 78 00 65 }
		$op_config_07nc = { 63 00 6C 00 65 00 61 00 72 00 00 }

	condition:
		1 of ($str_cmd*) and 
		1 of ($str_kl*) and 
		1 of ($op_config*)
}

rule fsnjRAT
{
	meta:
		description = "FsYARA - Malware Trends"
		vetted_family = "njrat"
		score = 75

	condition:
		Njrat or 
		njrat1 or 
		win_exe_njRAT or 
		njRat or 
		Windows_Trojan_Njrat_30f3c220 or 
		Windows_Trojan_Njrat_eb2698d2 or 
		malware_Njrat_strings or 
		njRat_1 or 
		Njrat_1 or 
		njrat or 
		Windows_Trojan_Njrat_30f3c220_1 or 
		win_njrat
}

