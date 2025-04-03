rule Stealc : hardened
{
	meta:
		author = "kevoreilly"
		description = "Stealc Payload"
		cape_type = "Stealc Payload"
		hash = "77d6f1914af6caf909fa2a246fcec05f500f79dd56e5d0d466d55924695c702d"

	strings:
		$nugget1 = {68 04 01 00 00 6A 00 FF 15 [4] 50 FF 15}
		$nugget2 = {64 A1 30 00 00 00 8B 40 0C 8B 40 0C 8B 00 8B 00 8B 40 18 89 45 FC}

	condition:
		uint16( 0 ) == 0x5A4D and all of them
}

rule StealcAnti : hardened
{
	meta:
		author = "kevoreilly"
		description = "Stealc detonation bypass"
		cape_options = "bp0=$anti+17,action0=skip,count=1"
		hash = "77d6f1914af6caf909fa2a246fcec05f500f79dd56e5d0d466d55924695c702d"

	strings:
		$anti = {53 57 57 57 FF 15 [4] 8B F0 74 03 75 01 B8 E8 [4] 74 03 75 01 B8}
		$decode = {6A 03 33 D2 8B F8 59 F7 F1 8B C7 85 D2 74 04 2B C2 03 C1 6A 06 C1 E0 03 33 D2 59 F7 F1}

	condition:
		uint16( 0 ) == 0x5A4D and all of them
}

rule StealcStrings : hardened
{
	meta:
		author = "kevoreilly"
		description = "Stealc string decryption"
		cape_options = "bp0=$decode+17,action0=string:edx,count=1,typestring=Stealc Strings"
		packed = "d0c824e886f14b8c411940a07dc133012b9eed74901b156233ac4cac23378add"

	strings:
		$decode = {51 8B 15 [4] 52 8B 45 ?? 50 E8 [4] 83 C4 0C 6A 04 6A 00 8D 4D ?? 51 FF 15 [4] 83 C4 0C 8B 45 ?? 8B E5 5D C3}

	condition:
		uint16( 0 ) == 0x5A4D and any of them
}

rule win_stealc_w0 : hardened
{
	meta:
		malware = "Stealc"
		description = "Find standalone Stealc sample based on decryption routine or characteristic strings"
		source = "SEKOIA.IO"
		reference = "https://blog.sekoia.io/stealc-a-copycat-of-vidar-and-raccoon-infostealers-gaining-in-popularity-part-1/"
		classification = "TLP:CLEAR"
		hash = "77d6f1914af6caf909fa2a246fcec05f500f79dd56e5d0d466d55924695c702d"
		author = "crep1x"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.stealc"
		malpedia_version = "20230221"
		malpedia_license = "CC BY-NC-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		malpedia_rule_date = "20230221"
		malpedia_hash = ""

	strings:
		$dec = { 55 8b ec 8b 4d ?? 83 ec 0c 56 57 e8 ?? ?? ?? ?? 6a 03 33 d2 8b f8 59 f7 f1 8b c7 85 d2 74 04 }
		$str01 = {2d 2d 2d 2d 2d 2d}
		$str02 = {4e 65 74 77 6f 72 6b 20 49 6e 66 6f 3a}
		$str03 = {2d 20 49 50 3a 20 49 50 3f}
		$str04 = {2d 20 43 6f 75 6e 74 72 79 3a 20 49 53 4f 3f}
		$str05 = {2d 20 44 69 73 70 6c 61 79 20 52 65 73 6f 6c 75 74 69 6f 6e 3a}
		$str06 = {55 73 65 72 20 41 67 65 6e 74 73 3a}
		$str07 = {25 73 5c 25 73 5c 25 73}

	condition:
		uint16( 0 ) == 0x5A4D and ( $dec or 5 of ( $str* ) )
}

rule malware_Stealc_str : hardened
{
	meta:
		description = "Stealc infostealer"
		author = "JPCERT/CC Incident Response Group"
		hash = "c9bcdc77108fd94f32851543d38be6982f3bb611c3a1115fc90013f965ed0b66"

	strings:
		$decode_code = {
          68 D0 07 00 00
          6A 00
          8D 85 ?? ?? ?? ??
          50
          FF 15 ?? ?? ?? ??
          83 C4 0C
          C7 85 ?? ?? ?? ?? 00 00 00 00
          EB ??
          8B 8D ?? ?? ?? ??
          83 C1 01
          89 8D ?? ?? ?? ??
          81 BD ?? ?? ?? ?? 00 01 00 00
        }
		$anti_code1 = {6A 04 68 00 30 00 00 68 C0 41 C8 17 6A 00 FF 15}
		$anti_code2 = {90 8A C0 68 C0 9E E6 05 8B 45 ?? 50 E8}
		$s1 = {2d 20 49 50 3a 20 49 50 3f}
		$s2 = {2d 20 43 6f 75 6e 74 72 79 3a 20 49 53 4f 3f}
		$s3 = {2d 20 44 69 73 70 6c 61 79 20 52 65 73 6f 6c 75 74 69 6f 6e 3a}

	condition:
		uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3c ) ) == 0x00004550 and ( $decode_code or all of ( $anti_code* ) or all of ( $s* ) )
}

rule Windows_Trojan_Stealc_b8ab9ab5 : hardened limited
{
	meta:
		author = "Elastic Security"
		id = "b8ab9ab5-5731-4651-b982-03ad8fe347fb"
		fingerprint = "49253b1d1e39ba25b2d3b622d00633b9629715e65e1537071b0f3b0318b7db12"
		creation_date = "2024-03-13"
		last_modified = "2024-03-21"
		threat_name = "Windows.Trojan.Stealc"
		reference_sample = "0d1c07c84c54348db1637e21260dbed09bd6b7e675ef58e003d0fe8f017fd2c8"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$seq_str_decrypt = { 55 8B EC 83 EC ?? 8D 4D ?? E8 ?? ?? ?? ?? 8B 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 50 8D 4D ?? E8 ?? ?? ?? ?? 83 C0 ?? 50 }
		$seq_lang_check = { 81 E9 19 04 00 00 89 4D ?? 83 7D ?? ?? 77 ?? 8B 55 ?? 0F B6 82 ?? ?? ?? ?? FF 24 85 ?? ?? ?? ?? }
		$seq_mem_check_constant = { 72 09 81 7D F8 57 04 00 00 73 08 }
		$seq_hwid_algo = { 8B 08 69 C9 0B A3 14 00 81 E9 51 75 42 69 8B 55 08 }
		$str1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 2d 20 43 6f 75 6e 74 72 79 3a 20 49 53 4f 3f (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$str2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 25 64 2f 25 64 2f 25 64 20 25 64 3a 25 64 3a 25 64 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$str3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 25 30 38 6c 58 25 30 34 6c 58 25 6c 75 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$str4 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 5c 4f 75 74 6c 6f 6f 6b 5c 61 63 63 6f 75 6e 74 73 2e 74 78 74 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$str5 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 2f 63 20 74 69 6d 65 6f 75 74 20 2f 74 20 35 20 26 20 64 65 6c 20 2f 66 20 2f 71 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		(2 of ( $seq* ) or 4 of ( $str* ) )
}

rule Windows_Trojan_Stealc_a2b71dc4 : hardened
{
	meta:
		author = "Elastic Security"
		id = "a2b71dc4-4041-4c1f-b546-a2b6947702d1"
		fingerprint = "9eeb13fededae39b8a531fa5d07eaf839b56a1c828ecd11322c604962e8b1aec"
		creation_date = "2024-03-13"
		last_modified = "2024-03-21"
		threat_name = "Windows.Trojan.Stealc"
		reference_sample = "0d1c07c84c54348db1637e21260dbed09bd6b7e675ef58e003d0fe8f017fd2c8"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$seq_1 = { 8B C6 C1 E8 02 33 C6 D1 E8 33 C6 C1 E8 02 33 C6 83 E0 01 A3 D4 35 61 00 C1 E0 0F 66 D1 E9 66 0B C8 }
		$seq_2 = { FF D3 8B 4D ?? E8 [4] 6A ?? 33 D2 5F 8B C8 F7 F7 85 D2 74 ?? }
		$seq_3 = { 33 D2 8B F8 59 F7 F1 8B C7 3B D3 76 04 2B C2 03 C1 }
		$seq_4 = { 6A 7C 58 66 89 45 FC 8D 45 F0 50 8D 45 FC 50 FF 75 08 C7 45 F8 01 }

	condition:
		2 of ( $seq* )
}

rule Windows_Trojan_Stealc_5d3f297c : hardened
{
	meta:
		author = "Elastic Security"
		id = "5d3f297c-b812-401a-8671-2e00369cd6f2"
		fingerprint = "ff90bfcb28bb3164fb11da5f35f289af679805f7e4047e48d97ae89e5b820dcd"
		creation_date = "2024-03-05"
		last_modified = "2024-06-13"
		threat_name = "Windows.Trojan.Stealc"
		reference_sample = "885c8cd8f7ad93f0fd43ba4fb7f14d94dfdee3d223715da34a6e2fbb4d25b9f4"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 83 EC 08 C7 45 F8 00 00 00 00 83 7D 08 00 74 4A 83 7D 0C 00 74 44 8B 45 0C 83 C0 01 50 6A 40 ?? ?? ?? ?? ?? ?? 89 45 F8 83 7D F8 00 74 2C C7 45 FC 00 00 00 00 EB 09 8B 4D FC 83 C1 01 }

	condition:
		all of them
}

rule win_stealc_bytecodes_oct_2023 : hardened
{
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/08/27"
		description = "Bytecodes present in Stealc decoding routine"
		sha_256 = "74ff68245745b9d4cec9ef3c539d8da15295bdc70caa6fdb0632acdd9be4130a"
		sha_256 = "9f44a4cbc30e7a05d7eb00b531a9b3a4ada5d49ecf585b48892643a189358526"

	strings:
		$s1 = {8b 4d f0 89 4d f8 8b 45 f8 c1 e0 03 33 d2 b9 06 00 00 00 f7 f1 8b e5 5d c2 04 00}

	condition:
		( all of ( $s* ) )
}

rule Stealer_Stealc : hardened
{
	meta:
		author = "Still"
		component_name = "N/A"
		date = "2024-10-04"
		description = "attempts to match instructions/strings found in Stealc"
		malpedia_family = "win.stealc"
		yarahub_author_twitter = "@AzakaSekai_"
		yarahub_license = "CC BY-NC 4.0"
		yarahub_reference_md5 = "2E84B07EA9D624E7D3DBE3F95C6DD8BA"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_uuid = "858820c6-ce4e-41c8-9a5b-9098dd2a4746"

	strings:
		$str_1 = {2d 6e 6f 70 20 2d 63 20 22 69 65 78 28 4e 65 77 2d 4f 62 6a 65 63 74 20 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 28 27}
		$str_2 = {53 45 4c 45 43 54 20 73 65 72 76 69 63 65 2c 20 65 6e 63 72 79 70 74 65 64 5f 74 6f 6b 65 6e 20 46 52 4f 4d 20 74 6f 6b 65 6e 5f 73 65 72 76 69 63 65}
		$str_3 = {62 72 6f 77 73 65 72 3a 20 46 69 6c 65 5a 69 6c 6c 61 0a}
		$str_4 = {43 68 72 6f 6d 65 46 75 63 6b 4e 65 77 43 6f 6f 6b 69 65 73}
		$str_5 = {2f 63 20 74 69 6d 65 6f 75 74 20 2f 74 20 31 30 20 26 20 64 65 6c 20 2f 66 20 2f 71 20 22}
		$inst_low_match_peb = {
			55
			8B EC
			51
			C7 45 ?? 00 00 00 00
			64 A1 ?? ?? ?? ??
			8B 40 ??
			8B 40 ??
			8B 00
			8B 00
			8B 40 ??
			89 45 ??
			8B 45 ??
			8B E5
			5D
			C3
		}
		$inst_low_match_str_decode = {
			03 4D ??
			0F BE 19
			8B 55 ??
			52
			FF 15 ?? ?? ?? ??
			83 C4 04
			8B C8
			8B 45 ??
			33 D2
		}

	condition:
		3 of ( $str_* ) or all of ( $inst_low_match_* )
}

rule CT_Stealc : hardened limited
{
	meta:
		description = "Identifies Stealc malware"
		author = "Cipher Tech Solutions"
		hashes = "0d049f764a22e16933f8c3f1704d4e50"
		reference = "https://blog.sekoia.io/stealc-a-copycat-of-vidar-and-raccoon-infostealers-gaining-in-popularity-part-1/"
		mwcp = "osacce:Stealc"

	strings:
		$rc4_skipkey = {
            39 18       // cmp     [eax], ebx
            75 08       // jnz     short loc_40304D
            8b 45 fc    // mov     eax, [ebp+var_4]
            88 0c 10    // mov     [eax+edx], cl
            eb 0a       // jmp     short loc_403057
            8a 00       // mov     al, [eax]
            32 c1       // xor     al, cl
            8b 4d fc    // mov     ecx, [ebp+var_4]
            88 04 11    // mov     [ecx+edx], al
		}
		$str_ip = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 09 2d 20 49 50 3a 20 49 50 3f (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$str_iso = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 09 2d 20 43 6f 75 6e 74 72 79 3a 20 49 53 4f 3f (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$str_disp = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 09 2d 20 44 69 73 70 6c 61 79 20 52 65 73 6f 6c 75 74 69 6f 6e 3a 20 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$str_uas = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 55 73 65 72 20 41 67 65 6e 74 73 3a (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		uint16be( 0 ) == 0x4d5a and ( $rc4_skipkey or all of ( $str_* ) )
}

rule MALPEDIA_Win_Stealc_Auto : FILE hardened
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "539cf538-cfac-56e1-8a82-eaf8270c6c0b"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.stealc"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.stealc_auto.yar#L1-L108"
		license_url = "N/A"
		logic_hash = "6bf18991e2a395daac8cbfec9f407668e110581410c7e2de7aedba9cee95d9f0"
		score = 75
		quality = 75
		tags = "FILE"
		version = "1"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"

	strings:
		$sequence_0 = { ff15???????? 85c0 7507 c685e0feffff43 }
		$sequence_1 = { 68???????? e8???????? e8???????? 83c474 }
		$sequence_2 = { 50 e8???????? e8???????? 83c474 }
		$sequence_3 = { e8???????? e8???????? 81c480000000 e9???????? }
		$sequence_4 = { 50 e8???????? e8???????? 81c484000000 }
		$sequence_5 = { e8???????? 83c460 e8???????? 83c40c }
		$sequence_6 = { e8???????? e8???????? 83c418 6a3c }
		$sequence_7 = { ff15???????? 50 ff15???????? 8b5508 8902 }
		$sequence_8 = { 50 ff15???????? 8b5508 8902 }
		$sequence_9 = { 7405 394104 7d07 8b4908 3bca 75f0 8bf9 }

	condition:
		7 of them and filesize < 4891648
}

rule fsstealc : hardened
{
	meta:
		description = "FsYARA - Malware Trends"
		vetted_family = "stealc"

	condition:
		Stealc or StealcAnti or StealcStrings or win_stealc_w0 or malware_Stealc_str or Windows_Trojan_Stealc_b8ab9ab5 or Windows_Trojan_Stealc_a2b71dc4 or Windows_Trojan_Stealc_5d3f297c or win_stealc_bytecodes_oct_2023 or Stealer_Stealc or CT_Stealc or MALPEDIA_Win_Stealc_Auto
}

