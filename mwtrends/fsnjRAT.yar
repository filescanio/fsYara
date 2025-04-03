rule Njrat : RAT hardened
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

rule njrat1 : RAT hardened
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
		$a1 = {6e 00 65 00 74 00 73 00 68 00 20 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 20 00 61 00 64 00 64 00 20 00 61 00 6c 00 6c 00 6f 00 77 00 65 00 64 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00}
		$a2 = {53 00 45 00 45 00 5f 00 4d 00 41 00 53 00 4b 00 5f 00 4e 00 4f 00 5a 00 4f 00 4e 00 45 00 43 00 48 00 45 00 43 00 4b 00 53 00}
		$b1 = {5b 00 54 00 41 00 50 00 5d 00}
		$b2 = {20 00 26 00 20 00 65 00 78 00 69 00 74 00}
		$c1 = {6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 6b 00 20 00 70 00 69 00 6e 00 67 00 20 00 30 00 20 00 26 00 20 00 64 00 65 00 6c 00 20 00}
		$c2 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 70 00 69 00 6e 00 67 00 20 00 31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 20 00 26 00 20 00 64 00 65 00 6c 00}
		$c3 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 70 00 69 00 6e 00 67 00}

	condition:
		1 of ( $a* ) and 1 of ( $b* ) and 1 of ( $c* )
}

rule win_exe_njRAT : hardened
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
		$magic = {4d 5a}
		$string_setA_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67}
		$string_setA_2 = {42 61 73 65 36 34 53 74 72 69 6e 67}
		$string_setA_3 = {((43 6f 6e 6e 65 63 74 65 64) | (43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 65 00 64 00))}
		$string_setA_4 = {52 65 63 65 69 76 65}
		$string_setA_5 = {((44 65 6c 65 74 65 53 75 62 4b 65 79) | (44 00 65 00 6c 00 65 00 74 00 65 00 53 00 75 00 62 00 4b 00 65 00 79 00))}
		$string_setA_6 = {67 65 74 5f 4d 61 63 68 69 6e 65 4e 61 6d 65}
		$string_setA_7 = {67 65 74 5f 55 73 65 72 4e 61 6d 65}
		$string_setA_8 = {67 65 74 5f 4c 61 73 74 57 72 69 74 65 54 69 6d 65}
		$string_setA_9 = {47 65 74 56 6f 6c 75 6d 65 49 6e 66 6f 72 6d 61 74 69 6f 6e}
		$string_setB_1 = {((4f 53 46 75 6c 6c 4e 61 6d 65) | (4f 00 53 00 46 00 75 00 6c 00 6c 00 4e 00 61 00 6d 00 65 00))}
		$string_setB_2 = {((53 65 6e 64) | (53 00 65 00 6e 00 64 00))}
		$string_setB_3 = {((43 6f 6e 6e 65 63 74 65 64) | (43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 65 00 64 00))}
		$string_setB_4 = {((44 6f 77 6e 6c 6f 61 64 44 61 74 61) | (44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 44 00 61 00 74 00 61 00))}
		$string_setB_5 = {6e 00 65 00 74 00 73 00 68 00 20 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00}
		$string_setB_6 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 6b 00 20 00 70 00 69 00 6e 00 67 00 20 00 30 00 20 00 26 00 20 00 64 00 65 00 6c 00}

	condition:
		($magic at 0 ) and ( all of ( $string_setA* ) or all of ( $string_setB* ) )
}

rule njRat : hardened
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
		$s2 = {6e 00 65 00 74 00 73 00 68 00 20 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 20 00 61 00 64 00 64 00 20 00 61 00 6c 00 6c 00 6f 00 77 00 65 00 64 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00}
		$s3 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00}
		$s4 = {79 00 79 00 2d 00 4d 00 4d 00 2d 00 64 00 64 00}
		$v1 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 6b 00 20 00 70 00 69 00 6e 00 67 00 20 00 30 00 20 00 26 00 20 00 64 00 65 00 6c 00}
		$v2 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 70 00 69 00 6e 00 67 00 20 00 31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 20 00 26 00 20 00 64 00 65 00 6c 00}
		$v3 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 70 00 69 00 6e 00 67 00 20 00 30 00 20 00 2d 00 6e 00 20 00 32 00 20 00 26 00 20 00 64 00 65 00 6c 00}

	condition:
		all of ( $s* ) and any of ( $v* )
}

rule Windows_Trojan_Njrat_30f3c220 : hardened limited
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
		$a1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 67 65 74 5f 52 65 67 69 73 74 72 79 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$a2 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 53 00 45 00 45 00 5f 00 4d 00 41 00 53 00 4b 00 5f 00 4e 00 4f 00 5a 00 4f 00 4e 00 45 00 43 00 48 00 45 00 43 00 4b 00 53 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$a3 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 20 00 45 00 52 00 52 00 4f 00 52 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$a4 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 70 00 69 00 6e 00 67 00 20 00 30 00 20 00 2d 00 6e 00 20 00 32 00 20 00 26 00 20 00 64 00 65 00 6c 00 20 00 22 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$a5 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 6e 00 65 00 74 00 73 00 68 00 20 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 61 00 6c 00 6c 00 6f 00 77 00 65 00 64 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 22 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$a6 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 5b 00 2b 00 5d 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00 20 00 3a 00 20 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}

	condition:
		3 of them
}

rule Windows_Trojan_Njrat_eb2698d2 : hardened
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

rule malware_Njrat_strings : hardened limited
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
		$reg = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 53 00 45 00 45 00 5f 00 4d 00 41 00 53 00 4b 00 5f 00 4e 00 4f 00 5a 00 4f 00 4e 00 45 00 43 00 48 00 45 00 43 00 4b 00 53 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$msg = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 45 00 78 00 65 00 63 00 75 00 74 00 65 00 20 00 45 00 52 00 52 00 4f 00 52 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$ping = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 70 00 69 00 6e 00 67 00 20 00 30 00 20 00 2d 00 6e 00 20 00 32 00 20 00 26 00 20 00 64 00 65 00 6c 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}

	condition:
		all of them
}

rule njRat_1 : hardened
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
		$s2 = {6e 00 65 00 74 00 73 00 68 00 20 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 20 00 61 00 64 00 64 00 20 00 61 00 6c 00 6c 00 6f 00 77 00 65 00 64 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00}
		$s3 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00}
		$s4 = {79 00 79 00 79 00 79 00 2d 00 4d 00 4d 00 2d 00 64 00 64 00}
		$v1 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 6b 00 20 00 70 00 69 00 6e 00 67 00 20 00 30 00 20 00 26 00 20 00 64 00 65 00 6c 00}
		$v2 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 70 00 69 00 6e 00 67 00 20 00 31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 20 00 26 00 20 00 64 00 65 00 6c 00}
		$v3 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 70 00 69 00 6e 00 67 00 20 00 30 00 20 00 2d 00 6e 00 20 00 32 00 20 00 26 00 20 00 64 00 65 00 6c 00}

	condition:
		all of ( $s* ) and any of ( $v* )
}

rule Njrat_1 : hardened limited
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
		$s2 = {6e 00 65 00 74 00 73 00 68 00 20 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 20 00 61 00 64 00 64 00 20 00 61 00 6c 00 6c 00 6f 00 77 00 65 00 64 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00}
		$s3 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00}
		$s4 = {79 00 79 00 79 00 79 00 2d 00 4d 00 4d 00 2d 00 64 00 64 00}
		$v1 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 6b 00 20 00 70 00 69 00 6e 00 67 00 20 00 30 00 20 00 26 00 20 00 64 00 65 00 6c 00}
		$v2 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 70 00 69 00 6e 00 67 00 20 00 31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 20 00 26 00 20 00 64 00 65 00 6c 00}
		$v3 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 70 00 69 00 6e 00 67 00 20 00 30 00 20 00 2d 00 6e 00 20 00 32 00 20 00 26 00 20 00 64 00 65 00 6c 00}
		$x1 = {6e 00 65 00 74 00 73 00 68 00 20 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 61 00 6c 00 6c 00 6f 00 77 00 65 00 64 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00}
		$x2 = {6e 00 65 00 74 00 73 00 68 00 20 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 20 00 61 00 64 00 64 00 20 00 61 00 6c 00 6c 00 6f 00 77 00 65 00 64 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00}
		$x3 = { 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 (63|6b) 00 20 00 70 00 69 00 6e 00 67 }
		$x4 = {45 00 78 00 65 00 63 00 75 00 74 00 65 00 20 00 45 00 52 00 52 00 4f 00 52 00}
		$x5 = {44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 20 00 45 00 52 00 52 00 4f 00 52 00}
		$x6 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 5b 00 6b 00 6c 00 5d 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}

	condition:
		( all of ( $s* ) and any of ( $v* ) ) or ( uint16( 0 ) == 0x5a4d and 4 of ( $x* ) )
}

rule njrat : rat hardened
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
		$rights_0 = {6e 00 65 00 74 00 73 00 68 00 20 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 20 00 61 00 64 00 64 00 20 00 61 00 6c 00 6c 00 6f 00 77 00 65 00 64 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 22 00}
		$rights_1 = {6e 00 65 00 74 00 73 00 68 00 20 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 61 00 6c 00 6c 00 6f 00 77 00 65 00 64 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 22 00}

	condition:
		( all of ( $cnc_traffic_* ) ) and ( all of ( $rights_* ) )
}

rule Windows_Trojan_Njrat_30f3c220_1 : hardened limited
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
		$a1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 67 65 74 5f 52 65 67 69 73 74 72 79 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$a2 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 6e 00 65 00 74 00 73 00 68 00 20 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 61 00 6c 00 6c 00 6f 00 77 00 65 00 64 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 22 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$a3 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 70 00 69 00 6e 00 67 00 20 00 30 00 20 00 2d 00 6e 00 20 00 32 00 20 00 26 00 20 00 64 00 65 00 6c 00 20 00 22 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$a4 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 53 00 45 00 45 00 5f 00 4d 00 41 00 53 00 4b 00 5f 00 4e 00 4f 00 5a 00 4f 00 4e 00 45 00 43 00 48 00 45 00 43 00 4b 00 53 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$a5 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 20 00 45 00 52 00 52 00 4f 00 52 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}

	condition:
		all of them
}

rule win_njrat : hardened
{
	meta:
		author = "CERT Polska"
		date = "2020-07-20"
		hash = "998b6ed5494b22e18d353fdd96226db3"
		description = "Detects unpacked NjRAT malware."
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.njrat"

	strings:
		$str_cmd1 = {6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 6b 00 20 00 70 00 69 00 6e 00 67 00 20 00 30 00 20 00 26 00 20 00 64 00 65 00 6c 00 20 00}
		$str_cmd2 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 70 00 69 00 6e 00 67 00 20 00 31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 20 00 26 00 20 00 64 00 65 00 6c 00}
		$str_cmd3 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 70 00 69 00 6e 00 67 00}
		$str_cmd4 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 43 00 20 00 59 00 20 00 2f 00 4e 00 20 00 2f 00 44 00 20 00 59 00 20 00 2f 00 54 00 20 00 31 00 20 00 26 00 20 00 44 00 65 00 6c 00}
		$str_kl1 = {5b 00 6b 00 6c 00 5d 00}
		$str_kl2 = {5b 00 54 00 41 00 50 00 5d 00}
		$str_kl3 = {5b 00 45 00 4e 00 54 00 45 00 52 00 5d 00}
		$op_config_07d = { 46 69 78 00 6B 00 57 52 4B 00 6D 61 69 6E 00 00 00 }
		$op_config_07d_indirect = { 54 00 45 00 4d 00 50 00 00 [1] 65 00 78 00 65 }
		$op_config_07nc = { 63 00 6C 00 65 00 61 00 72 00 00 }

	condition:
		1 of ( $str_cmd* ) and 1 of ( $str_kl* ) and 1 of ( $op_config* )
}

rule fsnjRAT : hardened
{
	meta:
		description = "FsYARA - Malware Trends"
		vetted_family = "njrat"
		score = 75

	condition:
		Njrat or njrat1 or win_exe_njRAT or njRat or Windows_Trojan_Njrat_30f3c220 or Windows_Trojan_Njrat_eb2698d2 or malware_Njrat_strings or njRat_1 or Njrat_1 or njrat or Windows_Trojan_Njrat_30f3c220_1 or win_njrat
}

