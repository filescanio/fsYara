rule HackTool_MSIL_Rubeus_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public Rubeus project."
		md5 = "66e0681a500c726ed52e5ea9423d2654"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "0ca140ea-2b9f-5904-a4c0-8615229626f0"

	strings:
		$typelibguid = {((36 35 38 43 38 42 37 46 2d 33 36 36 34 2d 34 41 39 35 2d 39 35 37 32 2d 41 33 45 35 38 37 31 44 46 43 30 36) | (36 00 35 00 38 00 43 00 38 00 42 00 37 00 46 00 2d 00 33 00 36 00 36 00 34 00 2d 00 34 00 41 00 39 00 35 00 2d 00 39 00 35 00 37 00 32 00 2d 00 41 00 33 00 45 00 35 00 38 00 37 00 31 00 44 00 46 00 43 00 30 00 36 00))}

	condition:
		uint16( 0 ) == 0x5A4D and $typelibguid
}

rule Trojan_Raw_Generic_4 : hardened
{
	meta:
		date = "2020-12-02"
		modified = "2020-12-02"
		md5 = "f41074be5b423afb02a74bc74222e35d"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "9092f9bb-cab6-55c0-9452-70a6407db93a"

	strings:
		$s0 = { 83 ?? 02 [1-16] 40 [1-16] F3 A4 [1-16] 40 [1-16] E8 [4-32] FF ( D? | 5? | 1? ) }
		$s1 = { 0F B? [1-16] 4D 5A [1-32] 3C [16-64] 50 45 [8-32] C3 }

	condition:
		uint16( 0 ) != 0x5A4D and all of them
}

rule HackTool_Win32_AndrewSpecial_1 : hardened
{
	meta:
		date = "2020-11-25"
		modified = "2020-11-25"
		md5 = "e89efa88e3fda86be48c0cc8f2ef7230"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "69e27e92-d68e-5543-bada-170e32733dbb"

	strings:
		$dump = { 6A 00 68 FF FF 1F 00 FF 15 [4] 89 45 ?? 83 [2] 00 [1-50] 6A 00 68 80 00 00 00 6A 02 6A 00 6A 00 68 00 00 00 10 68 [4] FF 15 [4] 89 45 [10-70] 6A 00 6A 00 6A 00 6A 02 8B [2-4] 5? 8B [2-4] 5? 8B [2-4] 5? E8 [4-20] FF 15 }
		$shellcode_x86 = { B8 3C 00 00 00 33 C9 8D 54 24 04 64 FF 15 C0 00 00 00 83 C4 04 C2 14 00 }
		$shellcode_x86_inline = { C6 45 ?? B8 C6 45 ?? 3C C6 45 ?? 00 C6 45 ?? 00 C6 45 ?? 00 C6 45 ?? 33 C6 45 ?? C9 C6 45 ?? 8D C6 45 ?? 54 C6 45 ?? 24 C6 45 ?? 04 C6 45 ?? 64 C6 45 ?? FF C6 45 ?? 15 C6 45 ?? C0 C6 45 ?? 00 C6 45 ?? 00 C6 45 ?? 00 C6 45 ?? 83 C6 45 ?? C4 C6 45 ?? 04 C6 45 ?? C2 C6 45 ?? 14 C6 45 ?? 00 }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x010B ) and $dump and any of ( $shellcode* )
}

rule APT_Backdoor_Win_GORAT_3 : hardened limited
{
	meta:
		description = "This rule uses the same logic as FE_APT_Trojan_Win_GORAT_1_FEBeta with the addition of one check, to look for strings that are known to be in the Gorat implant when a certain cleaning script is not run against it."
		md5 = "995120b35db9d2f36d7d0ae0bfc9c10d"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "94c195b5-b8e8-56a7-bc11-dbbe2f969b06"

	strings:
		$dirty1 = {((66 69 72 65 65 79 65) | (66 00 69 00 72 00 65 00 65 00 79 00 65 00))}
		$dirty2 = {((6b 75 6c 69 6e 61 63 73) | (6b 00 75 00 6c 00 69 00 6e 00 61 00 63 00 73 00))}
		$dirty3 = {((52 65 64 46 6c 61 72 65) | (52 00 65 00 64 00 46 00 6c 00 61 00 72 00 65 00))}
		$dirty4 = {((67 6f 72 61 74) | (67 00 6f 00 72 00 61 00 74 00))}
		$dirty5 = {((66 6c 61 72 65) | (66 00 6c 00 61 00 72 00 65 00))}
		$go1 = {((67 6f 2e 62 75 69 6c 64 69 64) | (67 00 6f 00 2e 00 62 00 75 00 69 00 6c 00 64 00 69 00 64 00))}
		$go2 = {((47 6f 20 62 75 69 6c 64 20 49 44 3a) | (47 00 6f 00 20 00 62 00 75 00 69 00 6c 00 64 00 20 00 49 00 44 00 3a 00))}
		$json1 = {((6a 73 6f 6e 3a 22 70 69 64 22) | (6a 00 73 00 6f 00 6e 00 3a 00 22 00 70 00 69 00 64 00 22 00))}
		$json2 = {((6a 73 6f 6e 3a 22 6b 65 79 22) | (6a 00 73 00 6f 00 6e 00 3a 00 22 00 6b 00 65 00 79 00 22 00))}
		$json3 = {((6a 73 6f 6e 3a 22 61 67 65 6e 74 5f 74 69 6d 65 22) | (6a 00 73 00 6f 00 6e 00 3a 00 22 00 61 00 67 00 65 00 6e 00 74 00 5f 00 74 00 69 00 6d 00 65 00 22 00))}
		$json4 = {((6a 73 6f 6e 3a 22 72 69 64 22) | (6a 00 73 00 6f 00 6e 00 3a 00 22 00 72 00 69 00 64 00 22 00))}
		$json5 = {((6a 73 6f 6e 3a 22 70 6f 72 74 73 22) | (6a 00 73 00 6f 00 6e 00 3a 00 22 00 70 00 6f 00 72 00 74 00 73 00 22 00))}
		$json6 = {((6a 73 6f 6e 3a 22 61 67 65 6e 74 5f 70 6c 61 74 66 6f 72 6d 22) | (6a 00 73 00 6f 00 6e 00 3a 00 22 00 61 00 67 00 65 00 6e 00 74 00 5f 00 70 00 6c 00 61 00 74 00 66 00 6f 00 72 00 6d 00 22 00))}
		$rat = {((72 61 74) | (72 00 61 00 74 00))}
		$str1 = {((68 61 6e 64 6c 65 43 6f 6d 6d 61 6e 64) | (68 00 61 00 6e 00 64 00 6c 00 65 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00))}
		$str2 = {((73 65 6e 64 42 65 61 63 6f 6e) | (73 00 65 00 6e 00 64 00 42 00 65 00 61 00 63 00 6f 00 6e 00))}
		$str3 = {((72 61 74 2e 41 67 65 6e 74 56 65 72 73 69 6f 6e) | (72 00 61 00 74 00 2e 00 41 00 67 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00))}
		$str4 = {((72 61 74 2e 43 6f 72 65) | (72 00 61 00 74 00 2e 00 43 00 6f 00 72 00 65 00))}
		$str5 = {((72 61 74 2f 6c 6f 67) | (72 00 61 00 74 00 2f 00 6c 00 6f 00 67 00))}
		$str6 = {((72 61 74 2f 63 6f 6d 6d 73) | (72 00 61 00 74 00 2f 00 63 00 6f 00 6d 00 6d 00 73 00))}
		$str7 = {((72 61 74 2f 6d 6f 64 75 6c 65 73) | (72 00 61 00 74 00 2f 00 6d 00 6f 00 64 00 75 00 6c 00 65 00 73 00))}
		$str8 = {((6d 75 72 69 63 61) | (6d 00 75 00 72 00 69 00 63 00 61 00))}
		$str9 = {((6d 61 73 74 65 72 20 73 65 63 72 65 74) | (6d 00 61 00 73 00 74 00 65 00 72 00 20 00 73 00 65 00 63 00 72 00 65 00 74 00))}
		$str10 = {((54 61 73 6b 49 44) | (54 00 61 00 73 00 6b 00 49 00 44 00))}
		$str11 = {((72 61 74 2e 4e 65 77) | (72 00 61 00 74 00 2e 00 4e 00 65 00 77 00))}

	condition:
		uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 and filesize < 10MB and all of ( $go* ) and all of ( $json* ) and all of ( $str* ) and #rat > 1000 and any of ( $dirty* )
}

rule CredTheft_Win_EXCAVATOR_1 : hardened
{
	meta:
		description = "This rule looks for the binary signature of the 'Inject' method found in the main Excavator PE."
		md5 = "f7d9961463b5110a3d70ee2e97842ed3"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "7cabc230-e55b-5096-996a-b6a8c9693bdc"

	strings:
		$bytes1 = { 48 89 74 24 10 48 89 7C 24 18 4C 89 74 24 20 55 48 8D 6C 24 E0 48 81 EC 20 01 00 00 48 8B 05 75 BF 01 00 48 33 C4 48 89 45 10 0F 57 C0 45 33 F6 8B F1 4C 89 74 24 60 48 8D 0D 12 A1 01 00 4C 89 74 24 68 0F 11 45 A0 41 8B FE 4C 89 74 24 70 0F 11 45 B0 0F 11 45 C0 0F 11 45 D0 0F 11 45 E0 0F 11 45 F0 0F 11 45 00 FF 15 CB 1F 01 00 48 85 C0 75 1B FF 15 80 1F 01 00 8B D0 48 8D 0D DF A0 01 00 E8 1A FF FF FF 33 C0 E9 B4 02 00 00 48 8D 15 D4 A0 01 00 48 89 9C 24 30 01 00 00 48 8B C8 FF 15 4B 1F 01 00 48 8B D8 48 85 C0 75 19 FF 15 45 1F 01 00 8B D0 48 8D 0D A4 A0 01 00 E8 DF FE FF FF E9 71 02 00 00 48 8B 4C 24 60 48 8D 44 24 60 45 33 C9 48 89 44 24 20 45 33 C0 BA 00 00 00 02 FF D3 85 C0 75 45 66 66 0F 1F 84 00 00 00 00 00 48 8B 4C 24 60 FF 15 4D 1F 01 00 3B C6 74 22 48 8B 4C 24 60 48 8D 44 24 60 45 33 C9 48 89 44 24 20 45 33 C0 BA 00 00 00 02 FF D3 85 C0 74 D1 EB 0A 48 8B 44 24 60 48 89 44 24 70 66 0F 6F 15 6D A0 01 00 48 8D 05 A6 C8 01 00 B9 C8 05 00 00 90 F3 0F 6F 40 F0 48 8D 40 40 66 0F 6F CA 66 0F EF C8 F3 0F 7F 48 B0 66 0F 6F CA F3 0F 6F 40 C0 66 0F EF C8 F3 0F 7F 48 C0 66 0F 6F CA F3 0F 6F 40 D0 66 0F EF C8 F3 0F 7F 48 D0 F3 0F 6F 40 E0 66 0F EF C2 F3 0F 7F 40 E0 48 83 E9 01 75 B2 FF 15 CC 1E 01 00 4C 8D 44 24 78 BA 0A 00 00 00 48 8B C8 FF 15 01 1E 01 00 85 C0 0F 84 66 01 00 00 48 8B 4C 24 78 48 8D 45 80 41 B9 02 00 00 00 48 89 44 24 28 45 33 C0 C7 44 24 20 02 00 00 00 41 8D 51 09 FF 15 D8 1D 01 00 85 C0 0F 84 35 01 00 00 45 33 C0 4C 8D 4C 24 68 33 C9 41 8D 50 01 FF 15 5C 1E 01 00 FF 15 06 1E 01 00 4C 8B 44 24 68 33 D2 48 8B C8 FF 15 DE 1D 01 00 48 8B F8 48 85 C0 0F 84 FF 00 00 00 45 33 C0 4C 8D 4C 24 68 48 8B C8 41 8D 50 01 FF 15 25 1E 01 00 85 C0 0F 84 E2 00 00 00 4C 89 74 24 30 4C 8D 4C 24 70 4C 89 74 24 28 33 D2 41 B8 00 00 02 00 48 C7 44 24 20 08 00 00 00 48 8B CF FF 15 6C 1D 01 00 85 C0 0F 84 B1 00 00 00 48 8B 4D 80 48 8D 45 88 48 89 44 24 50 4C 8D 05 58 39 03 00 48 8D 45 A0 48 89 7D 08 48 89 44 24 48 45 33 C9 4C 89 74 24 40 33 D2 4C 89 74 24 38 C7 44 24 30 04 00 08 00 44 89 74 24 28 4C 89 74 24 20 FF 15 0C 1D 01 00 85 C0 74 65 48 8B 4C 24 70 8B 5D 98 FF 15 1A 1D 01 00 48 8B 4D 88 FF 15 10 1D 01 00 48 8B 4D 90 FF 15 06 1D 01 00 44 8B C3 33 D2 B9 3A 04 00 00 FF 15 4E 1D 01 00 48 8B D8 48 85 C0 74 2B 48 8B C8 E8 4E 06 00 00 48 85 C0 74 1E BA FF FF FF FF 48 8B C8 FF 15 3B 1D 01 00 48 8B CB FF 15 CA 1C 01 00 B8 01 00 00 00 EB 24 FF 15 DD 1C 01 00 8B D0 48 8D 0D 58 9E 01 00 E8 77 FC FF FF 48 85 FF 74 09 48 8B CF FF 15 A9 1C 01 00 33 C0 48 8B 9C 24 30 01 00 00 48 8B 4D 10 48 33 CC E8 03 07 00 00 4C 8D 9C 24 20 01 00 00 49 8B 73 18 49 8B 7B 20 4D 8B 73 28 49 8B E3 5D C3 }
		$bytes2 = { 48 89 74 24 10 48 89 7C 24 18 4C 89 74 24 20 55 48 8D 6C 24 E0 48 81 EC 2? ?1 ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 33 C4 48 89 45 10 0F 57 C0 45 33 F6 8B F1 4C 89 74 24 60 48 ?? ?? ?? ?? ?? ?? 4C 89 74 24 68 0F 11 45 A0 41 8B FE 4C 89 74 24 70 0F 11 45 B0 0F 11 45 C0 0F 11 45 D0 0F 11 45 E0 0F 11 45 F0 0F 11 45 ?? FF ?? ?? ?? ?? ?? 48 85 C0 75 ?? FF ?? ?? ?? ?? ?? 8B D0 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 E9 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 89 9C 24 3? ?1 ?? ?? 48 8B C8 FF ?? ?? ?? ?? ?? 48 8B D8 48 85 C0 75 ?? FF ?? ?? ?? ?? ?? 8B D0 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 8B 4C 24 60 48 8D 44 24 60 45 33 C9 48 89 44 24 20 45 33 C0 BA ?? ?? ?? ?? FF D3 85 C0 75 ?? 66 66 0F 1F 84 ?? ?? ?? ?? ?? 48 8B 4C 24 60 FF ?? ?? ?? ?? ?? 3B C6 74 ?? 48 8B 4C 24 60 48 8D 44 24 60 45 33 C9 48 89 44 24 20 45 33 C0 BA ?? ?? ?? ?? FF D3 85 C0 74 ?? EB ?? 48 8B 44 24 60 48 89 44 24 70 66 0F 6F 15 6D A? ?1 ?? 48 ?? ?? ?? ?? ?? ?? B9 ?? ?? ?? ?? 90 F3 0F 6F 40 F0 48 8D 40 40 66 0F 6F CA 66 0F EF C8 F3 0F 7F 48 B0 66 0F 6F CA F3 0F 6F 40 C0 66 0F EF C8 F3 0F 7F 48 C0 66 0F 6F CA F3 0F 6F 40 D0 66 0F EF C8 F3 0F 7F 48 D0 F3 0F 6F 40 E0 66 0F EF C2 F3 0F 7F 40 E0 48 83 E9 01 75 ?? FF ?? ?? ?? ?? ?? 4C 8D 44 24 78 BA 0A ?? ?? ?? 48 8B C8 FF ?? ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8B 4C 24 78 48 8D 45 80 41 B9 02 ?? ?? ?? 48 89 44 24 28 45 33 C0 C7 44 24 2? ?2 ?? ?? ?? 41 8D 51 09 FF ?? ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 45 33 C0 4C 8D 4C 24 68 33 C9 41 8D 5? ?1 FF ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 4C 8B 44 24 68 33 D2 48 8B C8 FF ?? ?? ?? ?? ?? 48 8B F8 48 85 C0 0F 84 ?? ?? ?? ?? 45 33 C0 4C 8D 4C 24 68 48 8B C8 41 8D 5? ?1 FF ?? ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 4C 89 74 24 30 4C 8D 4C 24 70 4C 89 74 24 28 33 D2 41 ?? ?? ?? ?? ?? 48 C7 44 24 2? ?8 ?? ?? ?? 48 8B CF FF ?? ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8B 4D 80 48 8D 45 88 48 89 44 24 50 4C ?? ?? ?? ?? ?? ?? 48 8D 45 A0 48 89 7D 08 48 89 44 24 48 45 33 C9 4C 89 74 24 40 33 D2 4C 89 74 24 38 C7 ?? ?? ?? ?? ?? ?? ?? 44 89 74 24 28 4C 89 74 24 20 FF ?? ?? ?? ?? ?? 85 C0 74 ?? 48 8B 4C 24 70 8B 5D 98 FF ?? ?? ?? ?? ?? 48 8B 4D 88 FF ?? ?? ?? ?? ?? 48 8B 4D 90 FF ?? ?? ?? ?? ?? 44 8B C3 33 D2 B9 ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 48 8B D8 48 85 C0 74 ?? 48 8B C8 E8 ?? ?? ?? ?? 48 85 C0 74 ?? BA ?? ?? ?? ?? 48 8B C8 FF ?? ?? ?? ?? ?? 48 8B CB FF ?? ?? ?? ?? ?? B8 01 ?? ?? ?? EB ?? FF ?? ?? ?? ?? ?? 8B D0 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 FF 74 ?? 48 8B CF FF ?? ?? ?? ?? ?? 33 C0 48 8B 9C 24 3? ?1 ?? ?? 48 8B 4D 10 48 33 CC E8 ?? ?? ?? ?? 4C 8D 9C 24 2? ?1 ?? ?? 49 8B 73 18 49 8B 7B 20 4D 8B 73 28 49 8B E3 5D C3 }
		$bytes3 = { 48 89 74 24 10 48 89 7C 24 18 4C 89 74 24 20 55 48 8D 6C 24 E0 48 81 EC 2? ?1 ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 33 C4 48 89 45 10 0F 57 C0 45 33 F6 8B F1 4C 89 74 24 60 48 ?? ?? ?? ?? ?? ?? 4C 89 74 24 68 0F 11 45 A0 41 8B FE 4C 89 74 24 70 0F 11 45 B0 0F 11 45 C0 0F 11 45 D0 0F 11 45 E0 0F 11 45 F0 0F 11 45 ?? FF ?? ?? ?? ?? ?? 48 85 C0 75 ?? FF ?? ?? ?? ?? ?? 8B D0 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 E9 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 89 9C 24 3? ?1 ?? ?? 48 8B C8 FF ?? ?? ?? ?? ?? 48 8B D8 48 85 C0 75 ?? FF ?? ?? ?? ?? ?? 8B D0 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 8B 4C 24 60 48 8D 44 24 60 45 33 C9 48 89 44 24 20 45 33 C0 BA ?? ?? ?? ?? FF D3 85 C0 75 ?? 66 66 0F 1F 84 ?? ?? ?? ?? ?? 48 8B 4C 24 60 FF ?? ?? ?? ?? ?? 3B C6 74 ?? 48 8B 4C 24 60 48 8D 44 24 60 45 33 C9 48 89 44 24 20 45 33 C0 BA ?? ?? ?? ?? FF D3 85 C0 74 ?? EB ?? 48 8B 44 24 60 48 89 44 24 70 66 0F 6F 15 6D A? ?1 ?? 48 ?? ?? ?? ?? ?? ?? B9 ?? ?? ?? ?? 90 F3 0F 6F 40 F0 48 8D 40 40 66 0F 6F CA 66 0F EF C8 F3 0F 7F 48 B0 66 0F 6F CA F3 0F 6F 40 C0 66 0F EF C8 F3 0F 7F 48 C0 66 0F 6F CA F3 0F 6F 40 D0 66 0F EF C8 F3 0F 7F 48 D0 F3 0F 6F 40 E0 66 0F EF C2 F3 0F 7F 40 E0 48 83 E9 01 75 ?? FF ?? ?? ?? ?? ?? 4C 8D 44 24 78 BA 0A ?? ?? ?? 48 8B C8 FF ?? ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8B 4C 24 78 48 8D 45 80 41 B9 02 ?? ?? ?? 48 89 44 24 28 45 33 C0 C7 44 24 2? ?2 ?? ?? ?? 41 8D 51 09 FF ?? ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 45 33 C0 4C 8D 4C 24 68 33 C9 41 8D 5? ?1 FF ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 4C 8B 44 24 68 33 D2 48 8B C8 FF ?? ?? ?? ?? ?? 48 8B F8 48 85 C0 0F 84 ?? ?? ?? ?? 45 33 C0 4C 8D 4C 24 68 48 8B C8 41 8D 5? ?1 FF ?? ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 4C 89 74 24 30 4C 8D 4C 24 70 4C 89 74 24 28 33 D2 41 ?? ?? ?? ?? ?? 48 C7 44 24 2? ?8 ?? ?? ?? 48 8B CF FF ?? ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8B 4D 80 48 8D 45 88 48 89 44 24 50 4C ?? ?? ?? ?? ?? ?? 48 8D 45 A0 48 89 7D 08 48 89 44 24 48 45 33 C9 4C 89 74 24 40 33 D2 4C 89 74 24 38 C7 ?? ?? ?? ?? ?? ?? ?? 44 89 74 24 28 4C 89 74 24 20 FF ?? ?? ?? ?? ?? 85 C0 74 ?? 48 8B 4C 24 70 8B 5D 98 FF ?? ?? ?? ?? ?? 48 8B 4D 88 FF ?? ?? ?? ?? ?? 48 8B 4D 90 FF ?? ?? ?? ?? ?? 44 8B C3 33 D2 B9 ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 48 8B D8 48 85 C0 74 ?? 48 8B C8 E8 ?? ?? ?? ?? 48 85 C0 74 ?? BA ?? ?? ?? ?? 48 8B C8 FF ?? ?? ?? ?? ?? 48 8B CB FF ?? ?? ?? ?? ?? B8 01 ?? ?? ?? EB ?? FF ?? ?? ?? ?? ?? 8B D0 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 FF 74 ?? 48 8B CF FF ?? ?? ?? ?? ?? 33 C0 48 8B 9C 24 3? ?1 ?? ?? 48 8B 4D 10 48 33 CC E8 ?? ?? ?? ?? 4C 8D 9C 24 2? ?1 ?? ?? 49 8B 73 18 49 8B 7B 20 4D 8B 73 28 49 8B E3 5D C3 }
		$bytes4 = { 48 89 74 24 ?? 48 89 7C 24 ?? 4C 89 74 24 ?? 55 48 8D 6C 24 ?? 48 81 EC 20 01 00 00 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 45 ?? 0F 57 C0 45 33 F6 8B F1 4C 89 74 24 ?? 48 8D 0D ?? ?? ?? ?? 4C 89 74 24 ?? 0F 11 45 ?? 41 8B FE 4C 89 74 24 ?? 0F 11 45 ?? 0F 11 45 ?? 0F 11 45 ?? 0F 11 45 ?? 0F 11 45 ?? 0F 11 45 ?? FF 15 ?? ?? ?? ?? 48 85 C0 75 ?? FF 15 ?? ?? ?? ?? 8B D0 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 E9 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 89 9C 24 ?? ?? ?? ?? 48 8B C8 FF 15 ?? ?? ?? ?? 48 8B D8 48 85 C0 75 ?? FF 15 ?? ?? ?? ?? 8B D0 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 8B 4C 24 ?? 48 8D 44 24 ?? 45 33 C9 48 89 44 24 ?? 45 33 C0 BA 00 00 00 02 FF D3 85 C0 75 ?? 66 66 0F 1F 84 00 ?? ?? 00 00 48 8B 4C 24 ?? FF 15 ?? ?? ?? ?? 3B C6 74 ?? 48 8B 4C 24 ?? 48 8D 44 24 ?? 45 33 C9 48 89 44 24 ?? 45 33 C0 BA 00 00 00 02 FF D3 85 C0 74 ?? EB ?? 48 8B 44 24 ?? 48 89 44 24 ?? 66 0F 6F 15 ?? ?? 01 00 48 8D 05 ?? ?? ?? ?? B9 C8 05 00 00 90 F3 0F 6F 40 ?? 48 8D 40 ?? 66 0F 6F CA 66 0F EF C8 F3 0F 7F 48 ?? 66 0F 6F CA F3 0F 6F 40 ?? 66 0F EF C8 F3 0F 7F 48 ?? 66 0F 6F CA F3 0F 6F 40 ?? 66 0F EF C8 F3 0F 7F 48 ?? F3 0F 6F 40 ?? 66 0F EF C2 F3 0F 7F 40 ?? 48 83 E9 01 75 ?? FF 15 ?? ?? ?? ?? 4C 8D 44 24 ?? BA 0A 00 00 00 48 8B C8 FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8B 4C 24 ?? 48 8D 45 ?? 41 B9 02 00 00 00 48 89 44 24 ?? 45 33 C0 C7 44 24 ?? 02 00 00 00 41 8D 51 ?? FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 45 33 C0 4C 8D 4C 24 ?? 33 C9 41 8D 50 ?? FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 4C 8B 44 24 ?? 33 D2 48 8B C8 FF 15 ?? ?? ?? ?? 48 8B F8 48 85 C0 0F 84 ?? ?? ?? ?? 45 33 C0 4C 8D 4C 24 ?? 48 8B C8 41 8D 50 ?? FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 4C 89 74 24 ?? 4C 8D 4C 24 ?? 4C 89 74 24 ?? 33 D2 41 B8 00 00 02 00 48 C7 44 24 ?? 08 00 00 00 48 8B CF FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8B 4D ?? 48 8D 45 ?? 48 89 44 24 ?? 4C 8D 05 ?? ?? ?? ?? 48 8D 45 ?? 48 89 7D ?? 48 89 44 24 ?? 45 33 C9 4C 89 74 24 ?? 33 D2 4C 89 74 24 ?? C7 44 24 ?? 04 00 08 00 44 89 74 24 ?? 4C 89 74 24 ?? FF 15 ?? ?? ?? ?? 85 C0 74 ?? 48 8B 4C 24 ?? 8B 5D ?? FF 15 ?? ?? ?? ?? 48 8B 4D ?? FF 15 ?? ?? ?? ?? 48 8B 4D ?? FF 15 ?? ?? ?? ?? 44 8B C3 33 D2 B9 3A 04 00 00 FF 15 ?? ?? ?? ?? 48 8B D8 48 85 C0 74 ?? 48 8B C8 E8 ?? ?? ?? ?? 48 85 C0 74 ?? BA FF FF FF FF 48 8B C8 FF 15 ?? ?? ?? ?? 48 8B CB FF 15 ?? ?? ?? ?? B8 01 00 00 00 EB ?? FF 15 ?? ?? ?? ?? 8B D0 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 FF 74 ?? 48 8B CF FF 15 ?? ?? ?? ?? 33 C0 48 8B 9C 24 ?? ?? ?? ?? 48 8B 4D ?? 48 33 CC E8 ?? ?? ?? ?? 4C 8D 9C 24 ?? ?? ?? ?? 49 8B 73 ?? 49 8B 7B ?? 4D 8B 73 ?? 49 8B E3 5D C3 }

	condition:
		uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 and any of ( $bytes* )
}

rule APT_Loader_Win64_REDFLARE_1 : hardened
{
	meta:
		date = "2020-11-27"
		modified = "2020-11-27"
		md5 = "f20824fa6e5c81e3804419f108445368"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "dc162f26-66d3-5359-b1d7-ef2208b359e2"

	strings:
		$alloc_n_load = { 41 B9 40 00 00 00 41 B8 00 30 00 00 33 C9 [1-10] FF 50 [4-80] F3 A4 [30-120] 48 6B C9 28 [3-20] 48 6B C9 28 }
		$const_values = { 0F B6 ?? 83 C? 20 83 F? 6D [2-20] 83 C? 20 83 F? 7A }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) and all of them
}

rule APT_Loader_Raw64_REDFLARE_1 : hardened
{
	meta:
		date = "2020-11-27"
		modified = "2020-11-27"
		md5 = "5e14f77f85fd9a5be46e7f04b8a144f5"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "8e937f6a-404f-53bd-9de2-ed63b1cf48b2"

	strings:
		$load = { EB ?? 58 48 8B 10 4C 8B 48 ?? 48 8B C8 [1-10] 48 83 C1 ?? 48 03 D1 FF }

	condition:
		( uint16( 0 ) != 0x5A4D ) and all of them
}

rule HackTool_MSIL_SHARPZEROLOGON_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public 'sharpzerologon' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "51f22eee-fb96-55b0-8c02-1a0e9910a93e"

	strings:
		$typelibguid0 = {((31 35 63 65 39 61 33 63 2d 34 36 30 39 2d 34 31 38 34 2d 38 37 62 32 2d 65 32 39 66 63 35 65 32 62 37 37 30) | (31 00 35 00 63 00 65 00 39 00 61 00 33 00 63 00 2d 00 34 00 36 00 30 00 39 00 2d 00 34 00 31 00 38 00 34 00 2d 00 38 00 37 00 62 00 32 00 2d 00 65 00 32 00 39 00 66 00 63 00 35 00 65 00 32 00 62 00 37 00 37 00 30 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HackTool_MSIL_CoreHound_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'CoreHound' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "8c914b34-3e3d-53ae-a5e4-9dbfdff45a24"

	strings:
		$typelibguid0 = {((31 66 66 66 32 61 65 65 2d 61 35 34 30 2d 34 36 31 33 2d 39 34 65 65 2d 34 66 32 30 38 62 33 30 63 35 39 39) | (31 00 66 00 66 00 66 00 32 00 61 00 65 00 65 00 2d 00 61 00 35 00 34 00 30 00 2d 00 34 00 36 00 31 00 33 00 2d 00 39 00 34 00 65 00 65 00 2d 00 34 00 66 00 32 00 30 00 38 00 62 00 33 00 30 00 63 00 35 00 39 00 39 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule Loader_MSIL_NETAssemblyInject_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'NET-Assembly-Inject' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "62a7dc4c-678b-5f13-9661-4679eafe1c72"

	strings:
		$typelibguid0 = {((61 66 30 39 63 38 63 33 2d 62 32 37 31 2d 34 63 36 63 2d 38 66 34 38 2d 64 35 66 30 65 31 64 31 63 61 63 36) | (61 00 66 00 30 00 39 00 63 00 38 00 63 00 33 00 2d 00 62 00 32 00 37 00 31 00 2d 00 34 00 63 00 36 00 63 00 2d 00 38 00 66 00 34 00 38 00 2d 00 64 00 35 00 66 00 30 00 65 00 31 00 64 00 31 00 63 00 61 00 63 00 36 00))}
		$typelibguid1 = {((63 35 65 35 36 36 35 30 2d 64 66 62 30 2d 34 63 64 39 2d 38 64 30 36 2d 35 31 64 65 66 64 61 64 35 64 61 31) | (63 00 35 00 65 00 35 00 36 00 36 00 35 00 30 00 2d 00 64 00 66 00 62 00 30 00 2d 00 34 00 63 00 64 00 39 00 2d 00 38 00 64 00 30 00 36 00 2d 00 35 00 31 00 64 00 65 00 66 00 64 00 61 00 64 00 35 00 64 00 61 00 31 00))}
		$typelibguid2 = {((65 38 66 61 37 33 32 39 2d 38 30 37 34 2d 34 36 37 35 2d 39 35 38 38 2d 64 37 33 66 38 38 61 38 62 35 62 36) | (65 00 38 00 66 00 61 00 37 00 33 00 32 00 39 00 2d 00 38 00 30 00 37 00 34 00 2d 00 34 00 36 00 37 00 35 00 2d 00 39 00 35 00 38 00 38 00 2d 00 64 00 37 00 33 00 66 00 38 00 38 00 61 00 38 00 62 00 35 00 62 00 36 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule Hunting_GadgetToJScript_1 : hardened
{
	meta:
		description = "This rule is looking for B64 offsets of LazyNetToJscriptLoader which is a namespace specific to the internal version of the GadgetToJScript tooling."
		md5 = "7af24305a409a2b8f83ece27bb0f7900"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "76c932e0-55b3-56ef-bab6-eb6997b51ee7"

	strings:
		$s1 = {47 46 36 65 55 35 6c 64 46 52 76 53 6e 4e 6a 63 6d 6c 77 64 45 78 76 59 57 52 6c}
		$s2 = {68 65 6e 6c 4f 5a 58 52 55 62 30 70 7a 59 33 4a 70 63 48 52 4d 62 32 46 6b}
		$s3 = {59 58 70 35 54 6d 56 30 56 47 39 4b 63 32 4e 79 61 58 42 30 54 47 39 68 5a 47 56}

	condition:
		any of them
}

rule Trojan_MSIL_GORAT_Plugin_DOTNET_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'RedFlare - Plugin - .NET' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "faa73d64-4bb1-5c06-a3a5-1f1aa99ea932"

	strings:
		$typelibguid0 = {((63 64 39 34 30 37 64 30 2d 66 63 38 64 2d 34 31 65 64 2d 38 33 32 64 2d 64 61 39 34 64 61 61 33 65 30 36 34) | (63 00 64 00 39 00 34 00 30 00 37 00 64 00 30 00 2d 00 66 00 63 00 38 00 64 00 2d 00 34 00 31 00 65 00 64 00 2d 00 38 00 33 00 32 00 64 00 2d 00 64 00 61 00 39 00 34 00 64 00 61 00 61 00 33 00 65 00 30 00 36 00 34 00))}
		$typelibguid1 = {((66 63 33 64 61 65 64 66 2d 31 64 30 31 2d 34 34 39 30 2d 38 30 33 32 2d 62 39 37 38 30 37 39 64 38 63 32 64) | (66 00 63 00 33 00 64 00 61 00 65 00 64 00 66 00 2d 00 31 00 64 00 30 00 31 00 2d 00 34 00 34 00 39 00 30 00 2d 00 38 00 30 00 33 00 32 00 2d 00 62 00 39 00 37 00 38 00 30 00 37 00 39 00 64 00 38 00 63 00 32 00 64 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule APT_Dropper_Win64_MATRYOSHKA_1 : hardened
{
	meta:
		date = "2020-12-02"
		modified = "2020-12-02"
		description = "matryoshka_dropper.rs"
		md5 = "edcd58ba5b1b87705e95089002312281"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "1406aafd-6217-51ef-b3af-107ee88f9c99"

	strings:
		$sb1 = { 8D 8D [4] E8 [4] 49 89 D0 C6 [2-6] 01 C6 [2-6] 01 [0-8] C7 44 24 ?? 0E 00 00 00 4C 8D 0D [4] 48 8D 8D [4] 48 89 C2 E8 [4] C6 [2-6] 01 C6 [2-6] 01 48 89 E9 48 8D 95 [4] E8 [4] 83 [2] 01 0F 8? [4] 48 01 F3 48 29 F7 48 [2] 08 48 89 85 [4] C6 [2-6] 01 C6 [2-6] 01 C6 [2-6] 01 48 8D 8D [4] 48 89 DA 49 89 F8 E8 }
		$sb2 = { 0F 29 45 ?? 48 C7 45 ?? 00 00 00 00 0F 29 45 ?? 0F 29 45 ?? 0F 29 45 ?? 0F 29 45 ?? 0F 29 45 ?? 0F 29 45 ?? 48 C7 45 ?? 00 00 00 00 C7 45 ?? 68 00 00 00 48 8B [2] 48 8D [2] 48 89 [3] 48 89 [3] 0F 11 44 24 ?? C7 44 24 ?? 08 00 00 0C C7 44 24 ?? 00 00 00 00 31 ?? 48 89 ?? 31 ?? 45 31 ?? 45 31 ?? E8 [4] 83 F8 01 }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) and all of them
}

rule APT_HackTool_MSIL_SHARPGOPHER_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpgopher' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "cc8eb9cd-9a51-5fab-b0a4-247baaa69dd7"

	strings:
		$typelibguid0 = {((38 33 34 31 33 61 38 39 2d 37 66 35 66 2d 34 63 33 66 2d 38 30 35 64 2d 66 34 36 39 32 62 63 36 30 31 37 33) | (38 00 33 00 34 00 31 00 33 00 61 00 38 00 39 00 2d 00 37 00 66 00 35 00 66 00 2d 00 34 00 63 00 33 00 66 00 2d 00 38 00 30 00 35 00 64 00 2d 00 66 00 34 00 36 00 39 00 32 00 62 00 63 00 36 00 30 00 31 00 37 00 33 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HackTool_MSIL_KeeFarce_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'KeeFarce' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "c17add0c-e09f-5ced-a4e1-bf60afad4725"

	strings:
		$typelibguid0 = {((31 37 35 38 39 65 61 36 2d 66 63 63 39 2d 34 34 62 62 2d 39 32 61 64 2d 64 35 62 33 65 65 61 36 61 66 30 33) | (31 00 37 00 35 00 38 00 39 00 65 00 61 00 36 00 2d 00 66 00 63 00 63 00 39 00 2d 00 34 00 34 00 62 00 62 00 2d 00 39 00 32 00 61 00 64 00 2d 00 64 00 35 00 62 00 33 00 65 00 65 00 61 00 36 00 61 00 66 00 30 00 33 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule APT_Backdoor_Win_GORAT_1 : hardened
{
	meta:
		description = "This detects if a sample is less than 50KB and has a number of strings found in the Gorat shellcode (stage0 loader). The loader contains an embedded DLL (stage0.dll) that contains a number of unique strings. The 'Cookie' string found in this loader is important as this cookie is needed by the C2 server to download the Gorat implant (stage1 payload)."
		md5 = "66cdaa156e4d372cfa3dea0137850d20"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "5ac84cf1-49fb-533d-b211-b1a92239063b"

	strings:
		$s1 = {((68 74 74 70 43 6f 6d 6d 73 2e 64 6c 6c) | (68 00 74 00 74 00 70 00 43 00 6f 00 6d 00 6d 00 73 00 2e 00 64 00 6c 00 6c 00))}
		$s2 = {((43 6f 6f 6b 69 65 3a 20 53 49 44 31 3d 25 73) | (43 00 6f 00 6f 00 6b 00 69 00 65 00 3a 00 20 00 53 00 49 00 44 00 31 00 3d 00 25 00 73 00))}
		$s3 = {((47 6c 6f 62 61 6c 5c) | (47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00))}
		$s4 = {((73 74 61 67 65 30 2e 64 6c 6c) | (73 00 74 00 61 00 67 00 65 00 30 00 2e 00 64 00 6c 00 6c 00))}
		$s5 = {((72 75 6e 43 6f 6d 6d 61 6e 64) | (72 00 75 00 6e 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00))}
		$s6 = {((67 65 74 44 61 74 61) | (67 00 65 00 74 00 44 00 61 00 74 00 61 00))}
		$s7 = {((69 6e 69 74 69 61 6c 69 7a 65) | (69 00 6e 00 69 00 74 00 69 00 61 00 6c 00 69 00 7a 00 65 00))}
		$s8 = {((57 69 6e 64 6f 77 73 20 4e 54 20 25 64 2e 25 64 3b) | (57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 20 00 25 00 64 00 2e 00 25 00 64 00 3b 00))}
		$s9 = {((21 54 68 69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65 2e) | (21 00 54 00 68 00 69 00 73 00 20 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 63 00 61 00 6e 00 6e 00 6f 00 74 00 20 00 62 00 65 00 20 00 72 00 75 00 6e 00 20 00 69 00 6e 00 20 00 44 00 4f 00 53 00 20 00 6d 00 6f 00 64 00 65 00 2e 00))}

	condition:
		filesize < 50KB and all of them
}

rule APT_Dropper_Win_MATRYOSHKA_1 : hardened
{
	meta:
		date = "2020-12-02"
		modified = "2020-12-02"
		description = "matryoshka_dropper.rs"
		md5 = "edcd58ba5b1b87705e95089002312281"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "7fd305c7-0b1b-5d91-b968-7f1fb0a8ae47"

	strings:
		$s1 = {00 6d 61 74 72 79 6f 73 68 6b 61 2e 65 78 65 00}
		$s2 = {00 55 6e 61 62 6c 65 20 74 6f 20 77 72 69 74 65 20 64 61 74 61 00}
		$s3 = {00 45 72 72 6f 72 20 77 68 69 6c 65 20 73 70 61 77 6e 69 6e 67 20 70 72 6f 63 65 73 73 2e 20 4e 54 53 74 61 74 75 73 3a 20 0a 00}
		$s4 = {00 2e 65 78 65 63 6d 64 73 74 61 72 74 2f 43 66 61 69 6c 65 64 20 74 6f 20 65 78 65 63 75 74 65 20 70 72 6f 63 65 73 73 00}

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule Loader_Win_Generic_20 : hardened
{
	meta:
		date = "2020-12-02"
		modified = "2020-12-02"
		md5 = "5125979110847d35a338caac6bff2aa8"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "d1d3eff8-d12e-53f6-8c30-06ecedaf3f49"

	strings:
		$s0 = { 8B [1-16] 89 [1-16] E8 [4-32] F3 A4 [0-16] 89 [1-8] E8 }
		$s2 = { 83 EC [4-24] 00 10 00 00 [4-24] C7 44 24 ?? ?? 00 00 00 [0-8] FF 15 [4-24] 89 [1-4] 89 [1-4] 89 [1-8] FF 15 [4-16] 3? ?? 7? [4-24] 20 00 00 00 [4-24] FF 15 [4-32] F3 A5 }
		$si1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74}
		$si2 = {6d 61 6c 6c 6f 63}

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule APT_Loader_Win32_PGF_2 : hardened
{
	meta:
		date = "2020-11-25"
		modified = "2020-11-25"
		description = "base dlls: /lib/payload/techniques/dllmain/"
		md5 = "04eb45f8546e052fe348fda2425b058c"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "e11a626b-ce91-5f6c-a514-9a8a02a29cbd"

	strings:
		$sb1 = { 6A ?? FF 15 [4-16] 8A ?? 04 [0-16] 8B ?? 1C [0-64] 0F 10 ?? 66 0F EF C8 0F 11 [0-32] 30 [2] 8D [2] 4? 83 [2] 7? }
		$sb2 = { 8B ?? 08 [0-16] 6A 40 68 00 30 00 00 5? 6A 00 [0-32] FF 15 [4-32] 5? [0-16] E8 [4-64] C1 ?? 04 [0-32] 8A [2] 3? [2] 4? 3? ?? 24 ?? 7? }
		$sb3 = { 8B ?? 3C [0-16] 03 [1-64] 0F B? ?? 14 [0-32] 83 ?? 18 [0-32] 66 3? ?? 06 [4-32] 68 [4] 5? FF 15 [4-16] 85 C0 [2-32] 83 ?? 28 0F B? ?? 06 }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x010B ) and all of them
}

rule APT_HackTool_MSIL_REDTEAMMATERIALS_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'red_team_materials' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "272cd3e9-884a-566b-ae90-4a79ee726a8d"

	strings:
		$typelibguid0 = {((38 36 63 39 35 61 39 39 2d 61 32 64 36 2d 34 65 62 65 2d 61 64 35 66 2d 39 38 38 35 62 30 36 65 61 62 31 32) | (38 00 36 00 63 00 39 00 35 00 61 00 39 00 39 00 2d 00 61 00 32 00 64 00 36 00 2d 00 34 00 65 00 62 00 65 00 2d 00 61 00 64 00 35 00 66 00 2d 00 39 00 38 00 38 00 35 00 62 00 30 00 36 00 65 00 61 00 62 00 31 00 32 00))}
		$typelibguid1 = {((65 30 36 66 31 34 31 31 2d 63 37 66 38 2d 34 35 33 38 2d 62 62 62 39 2d 34 36 63 39 32 38 37 33 32 32 34 35) | (65 00 30 00 36 00 66 00 31 00 34 00 31 00 31 00 2d 00 63 00 37 00 66 00 38 00 2d 00 34 00 35 00 33 00 38 00 2d 00 62 00 62 00 62 00 39 00 2d 00 34 00 36 00 63 00 39 00 32 00 38 00 37 00 33 00 32 00 32 00 34 00 35 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule APT_Trojan_Win_REDFLARE_7 : hardened
{
	meta:
		date = "2020-12-02"
		modified = "2020-12-02"
		md5 = "e7beece34bdf67cbb8297833c5953669, 8025bcbe3cc81fc19021ad0fbc11cf9b"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "f891e477-9ff2-57be-9ca5-dd87d9baee29"

	strings:
		$1 = {69 6e 69 74 69 61 6c 69 7a 65}
		$2 = {67 65 74 44 61 74 61}
		$3 = {70 75 74 44 61 74 61}
		$4 = {66 69 6e 69}
		$5 = {4e 61 6d 65 64 50 69 70 65}
		$named_pipe = { 88 13 00 00 [1-8] E8 03 00 00 [20-60] 00 00 00 00 [1-8] 00 00 00 00 [1-40] ( 6A 00 6A 00 6A 03 6A 00 6A 00 68 | 00 00 00 00 [1-6] 00 00 00 00 [1-6] 03 00 00 00 45 33 C? 45 33 C? BA ) 00 00 00 C0 [2-10] FF 15 [4-30] FF 15 [4-7] E7 00 00 00 [4-40] FF 15 [4] 85 C0 }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule APT_Trojan_Win_REDFLARE_8 : hardened
{
	meta:
		date = "2020-12-02"
		modified = "2020-12-02"
		md5 = "9c8eb908b8c1cda46e844c24f65d9370, 9e85713d615bda23785faf660c1b872c"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "b090df60-8f4e-51ca-944c-6f9ce2d9c913"

	strings:
		$1 = {50 53 52 75 6e 6e 65 72 2e 50 53 52 75 6e 6e 65 72}
		$2 = {43 6f 72 42 69 6e 64 54 6f 52 75 6e 74 69 6d 65}
		$3 = {52 65 70 6f 72 74 45 76 65 6e 74 57}
		$4 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 50 00 53 00}
		$5 = {72 75 6e 43 6f 6d 6d 61 6e 64}
		$6 = {69 6e 69 74 69 61 6c 69 7a 65}
		$trap = { 03 40 00 80 E8 [4] CC }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule APT_Backdoor_Win_GORAT_5 : hardened
{
	meta:
		date = "2020-12-02"
		modified = "2020-12-02"
		md5 = "cdf58a48757010d9891c62940c439adb, a107850eb20a4bb3cc59dbd6861eaf0f"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "73102bd2-7b94-5c7b-b9a4-cfc9cf5e3212"

	strings:
		$1 = {63 6f 6d 6d 73 2e 42 65 61 63 6f 6e 44 61 74 61}
		$2 = {63 6f 6d 6d 73 2e 43 6f 6d 6d 61 6e 64 52 65 73 70 6f 6e 73 65}
		$3 = {72 61 74 2e 42 61 73 65 43 68 61 6e 6e 65 6c}
		$4 = {72 61 74 2e 43 6f 6e 66 69 67}
		$5 = {72 61 74 2e 43 6f 72 65}
		$6 = {70 6c 61 74 66 6f 72 6d 73 2e 41 67 65 6e 74 50 6c 61 74 66 6f 72 6d}
		$7 = {47 65 74 48 6f 73 74 49 44}
		$8 = {2f 72 61 74 2f 63 6d 64 2f 67 6f 72 61 74 5f 73 68 61 72 65 64 2f 64 6c 6c 6d 61 69 6e 2e 67 6f}

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule APT_HackTool_MSIL_GPOHUNT_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'gpohunt' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "e4325f11-103c-5893-8978-9a72f7ca6105"

	strings:
		$typelibguid0 = {((37 35 31 61 39 32 37 30 2d 32 64 65 30 2d 34 63 38 31 2d 39 65 32 39 2d 38 37 32 63 64 36 33 37 38 33 30 33) | (37 00 35 00 31 00 61 00 39 00 32 00 37 00 30 00 2d 00 32 00 64 00 65 00 30 00 2d 00 34 00 63 00 38 00 31 00 2d 00 39 00 65 00 32 00 39 00 2d 00 38 00 37 00 32 00 63 00 64 00 36 00 33 00 37 00 38 00 33 00 30 00 33 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule APT_HackTool_MSIL_JUSTASK_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'justask' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "06a03d82-db69-5b5a-a578-a8053814e917"

	strings:
		$typelibguid0 = {((61 61 35 39 62 65 35 32 2d 37 38 34 35 2d 34 66 65 64 2d 39 65 61 35 2d 31 65 61 34 39 30 38 35 64 36 37 61) | (61 00 61 00 35 00 39 00 62 00 65 00 35 00 32 00 2d 00 37 00 38 00 34 00 35 00 2d 00 34 00 66 00 65 00 64 00 2d 00 39 00 65 00 61 00 35 00 2d 00 31 00 65 00 61 00 34 00 39 00 30 00 38 00 35 00 64 00 36 00 37 00 61 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule APT_Trojan_Win_REDFLARE_4 : hardened
{
	meta:
		date = "2020-12-01"
		modified = "2020-12-01"
		md5 = "a8b5dcfea5e87bf0e95176daa243943d, 9dcb6424662941d746576e62712220aa"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "6e8621b0-a0ee-5fc7-a2b8-1973a42d6e37"

	strings:
		$s1 = {4c 6f 67 6f 6e 55 73 65 72 57}
		$s2 = {49 6d 70 65 72 73 6f 6e 61 74 65 4c 6f 67 67 65 64 4f 6e 55 73 65 72}
		$s3 = {72 75 6e 43 6f 6d 6d 61 6e 64}
		$user_logon = { 22 02 00 00 [1-10] 02 02 00 00 [0-4] E8 [4-40] ( 09 00 00 00 [1-10] 03 00 00 00 | 6A 03 6A 09 ) [4-30] FF 15 [4] 85 C0 7? }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule APT_HackTool_MSIL_TITOSPECIAL_1 : hardened
{
	meta:
		date = "2020-11-25"
		modified = "2020-11-25"
		md5 = "4bf96a7040a683bd34c618431e571e26"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "b12490ba-41f6-5469-bcbb-0d2e0055c193"

	strings:
		$ind_dump = { 1F 10 16 28 [2] 00 0A 6F [2] 00 0A [50-200] 18 19 18 73 [2] 00 0A 13 [1-4] 06 07 11 ?? 6F [2] 00 0A 18 7E [2] 00 0A 7E [2] 00 0A 7E [2] 00 0A 28 [2] 00 06 }
		$ind_s1 = {4e 00 74 00 52 00 65 00 61 00 64 00 56 00 69 00 72 00 74 00 75 00 61 00 6c 00 4d 00 65 00 6d 00 6f 00 72 00 79 00}
		$ind_s2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79}
		$shellcode_x64 = { 4C 8B D1 B8 3C 00 00 00 0F 05 C3 }
		$shellcode_x86 = { B8 3C 00 00 00 33 C9 8D 54 24 04 64 FF 15 C0 00 00 00 83 C4 04 C2 14 00 }

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of ( $ind* ) and any of ( $shellcode* )
}

rule Dropper_LNK_LNKSmasher_1 : hardened
{
	meta:
		description = "The LNKSmasher project contains a prebuilt LNK file that has pieces added based on various configuration items. Because of this, several artifacts are present in every single LNK file generated by LNKSmasher, including the Drive Serial #, the File Droid GUID, and the GUID CLSID."
		md5 = "0a86d64c3b25aa45428e94b6e0be3e08"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "1b93ddf8-9578-5e47-b479-4c9e8a40b4f4"

	strings:
		$drive_serial = { 12 F7 26 BE }
		$file_droid_guid = { BC 96 28 4F 0A 46 54 42 81 B8 9F 48 64 D7 E9 A5 }
		$guid_clsid = { E0 4F D0 20 EA 3A 69 10 A2 D8 08 00 2B 30 30 9D }
		$header = { 4C 00 00 00 01 14 02 }

	condition:
		$header at 0 and all of them
}

rule HackTool_MSIL_SharpSchtask_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'SharpSchtask' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "5c7a5dee-3bc2-54b2-a7e2-be05ba74d4a1"

	strings:
		$typelibguid0 = {((30 61 36 34 61 35 66 34 2d 62 64 62 36 2d 34 34 33 63 2d 62 64 63 37 2d 66 36 66 30 62 66 35 62 35 64 36 63) | (30 00 61 00 36 00 34 00 61 00 35 00 66 00 34 00 2d 00 62 00 64 00 62 00 36 00 2d 00 34 00 34 00 33 00 63 00 2d 00 62 00 64 00 63 00 37 00 2d 00 66 00 36 00 66 00 30 00 62 00 66 00 35 00 62 00 35 00 64 00 36 00 63 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule APT_Controller_Linux_REDFLARE_1 : hardened
{
	meta:
		date = "2020-12-02"
		modified = "2020-12-02"
		md5 = "79259451ff47b864d71fb3f94b1774f3, 82773afa0860d668d7fe40e3f22b0f3e"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "79a69740-7209-5c56-ad6f-eb4d0b29beaf"

	strings:
		$1 = {2f 52 65 64 46 6c 61 72 65 2f 67 6f 72 61 74 5f 73 65 72 76 65 72}
		$2 = {52 65 64 46 6c 61 72 65 2f 73 61 6e 64 61 6c 73}
		$3 = {67 6f 72 61 74 73 76 72 2e 43 6f 6d 6d 61 6e 64 52 65 73 70 6f 6e 73 65}
		$4 = {67 6f 72 61 74 73 76 72 2e 43 6f 6d 6d 61 6e 64 52 65 71 75 65 73 74}

	condition:
		( uint32( 0 ) == 0x464c457f ) and all of them
}

rule APT_HackTool_MSIL_WMISPY_2 : hardened
{
	meta:
		description = "wql searches"
		md5 = "3651f252d53d2f46040652788499d65a"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "474af878-a657-54bc-a063-04532df928d4"

	strings:
		$MSIL = {5f 43 6f 72 45 78 65 4d 61 69 6e}
		$str1 = {72 00 6f 00 6f 00 74 00 5c 00 63 00 69 00 6d 00 76 00 32 00}
		$str2 = {72 00 6f 00 6f 00 74 00 5c 00 73 00 74 00 61 00 6e 00 64 00 61 00 72 00 64 00 63 00 69 00 6d 00 76 00 32 00}
		$str3 = {66 00 72 00 6f 00 6d 00 20 00 4d 00 53 00 46 00 54 00 5f 00 4e 00 65 00 74 00 4e 00 65 00 69 00 67 00 68 00 62 00 6f 00 72 00}
		$str4 = {66 00 72 00 6f 00 6d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 4e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 4c 00 6f 00 67 00 69 00 6e 00 50 00 72 00 6f 00 66 00 69 00 6c 00 65 00}
		$str5 = {66 00 72 00 6f 00 6d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 49 00 50 00 34 00 52 00 6f 00 75 00 74 00 65 00 54 00 61 00 62 00 6c 00 65 00}
		$str6 = {66 00 72 00 6f 00 6d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 44 00 43 00 4f 00 4d 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00}
		$str7 = {66 00 72 00 6f 00 6d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 53 00 79 00 73 00 74 00 65 00 6d 00 44 00 72 00 69 00 76 00 65 00 72 00}
		$str8 = {66 00 72 00 6f 00 6d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 53 00 68 00 61 00 72 00 65 00}
		$str9 = {66 00 72 00 6f 00 6d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00}

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and $MSIL and all of ( $str* )
}

rule HackTool_MSIL_SharPersist_2 : hardened
{
	meta:
		md5 = "98ecf58d48a3eae43899b45cec0fc6b7"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "1b8f6c25-3a59-5b88-bc0b-750b3663488b"

	strings:
		$a1 = {53 68 61 72 50 65 72 73 69 73 74 2e 6c 69 62}
		$a2 = {53 68 61 72 50 65 72 73 69 73 74 2e 65 78 65}
		$b1 = {((45 52 52 4f 52 3a 20 49 6e 76 61 6c 69 64 20 68 6f 74 6b 65 79 20 6c 6f 63 61 74 69 6f 6e 20 6f 70 74 69 6f 6e 20 67 69 76 65 6e 2e) | (45 00 52 00 52 00 4f 00 52 00 3a 00 20 00 49 00 6e 00 76 00 61 00 6c 00 69 00 64 00 20 00 68 00 6f 00 74 00 6b 00 65 00 79 00 20 00 6c 00 6f 00 63 00 61 00 74 00 69 00 6f 00 6e 00 20 00 6f 00 70 00 74 00 69 00 6f 00 6e 00 20 00 67 00 69 00 76 00 65 00 6e 00 2e 00))}
		$b2 = {((45 52 52 4f 52 3a 20 49 6e 76 61 6c 69 64 20 68 6f 74 6b 65 79 20 67 69 76 65 6e 2e) | (45 00 52 00 52 00 4f 00 52 00 3a 00 20 00 49 00 6e 00 76 00 61 00 6c 00 69 00 64 00 20 00 68 00 6f 00 74 00 6b 00 65 00 79 00 20 00 67 00 69 00 76 00 65 00 6e 00 2e 00))}
		$b3 = {((45 52 52 4f 52 3a 20 4b 65 65 70 61 73 73 20 63 6f 6e 66 69 67 75 72 61 74 69 6f 6e 20 66 69 6c 65 20 6e 6f 74 20 66 6f 75 6e 64 2e) | (45 00 52 00 52 00 4f 00 52 00 3a 00 20 00 4b 00 65 00 65 00 70 00 61 00 73 00 73 00 20 00 63 00 6f 00 6e 00 66 00 69 00 67 00 75 00 72 00 61 00 74 00 69 00 6f 00 6e 00 20 00 66 00 69 00 6c 00 65 00 20 00 6e 00 6f 00 74 00 20 00 66 00 6f 00 75 00 6e 00 64 00 2e 00))}
		$b4 = {((45 52 52 4f 52 3a 20 4b 65 65 70 61 73 73 20 63 6f 6e 66 69 67 75 72 61 74 69 6f 6e 20 66 69 6c 65 20 77 61 73 20 6e 6f 74 20 66 6f 75 6e 64 2e) | (45 00 52 00 52 00 4f 00 52 00 3a 00 20 00 4b 00 65 00 65 00 70 00 61 00 73 00 73 00 20 00 63 00 6f 00 6e 00 66 00 69 00 67 00 75 00 72 00 61 00 74 00 69 00 6f 00 6e 00 20 00 66 00 69 00 6c 00 65 00 20 00 77 00 61 00 73 00 20 00 6e 00 6f 00 74 00 20 00 66 00 6f 00 75 00 6e 00 64 00 2e 00))}
		$b5 = {((45 52 52 4f 52 3a 20 54 68 61 74 20 76 61 6c 75 65 20 61 6c 72 65 61 64 79 20 65 78 69 73 74 73 20 69 6e 3a) | (45 00 52 00 52 00 4f 00 52 00 3a 00 20 00 54 00 68 00 61 00 74 00 20 00 76 00 61 00 6c 00 75 00 65 00 20 00 61 00 6c 00 72 00 65 00 61 00 64 00 79 00 20 00 65 00 78 00 69 00 73 00 74 00 73 00 20 00 69 00 6e 00 3a 00))}
		$b6 = {((45 52 52 4f 52 3a 20 46 61 69 6c 65 64 20 74 6f 20 64 65 6c 65 74 65 20 68 69 64 64 65 6e 20 72 65 67 69 73 74 72 79 20 6b 65 79 2e) | (45 00 52 00 52 00 4f 00 52 00 3a 00 20 00 46 00 61 00 69 00 6c 00 65 00 64 00 20 00 74 00 6f 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 68 00 69 00 64 00 64 00 65 00 6e 00 20 00 72 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 20 00 6b 00 65 00 79 00 2e 00))}
		$pdb1 = {5c 53 68 61 72 50 65 72 73 69 73 74 5c}
		$pdb2 = {5c 53 68 61 72 50 65 72 73 69 73 74 2e 70 64 62}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( ( @pdb2 [ 1 ] < @pdb1 [ 1 ] + 50 ) or ( 1 of ( $a* ) and 2 of ( $b* ) ) )
}

rule APT_Loader_Win_MATRYOSHKA_1 : hardened
{
	meta:
		date = "2020-12-02"
		modified = "2020-12-02"
		description = "matryoshka_process_hollow.rs"
		md5 = "44887551a47ae272d7873a354d24042d"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "c07fb67e-ded5-593d-b5dc-d0e2c3b5a352"

	strings:
		$s1 = {5a 77 51 75 65 72 79 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73}
		$s2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79}
		$s3 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 57}
		$s4 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79}
		$s5 = {00 49 6e 76 61 6c 69 64 20 4e 54 20 53 69 67 6e 61 74 75 72 65 21 00}
		$s6 = {00 45 72 72 6f 72 20 77 68 69 6c 65 20 63 72 65 61 74 69 6e 67 20 61 6e 64 20 6d 61 70 70 69 6e 67 20 73 65 63 74 69 6f 6e 2e 20 4e 54 53 74 61 74 75 73 3a 20}
		$s7 = {00 45 72 72 6f 72 20 6e 6f 20 70 72 6f 63 65 73 73 20 69 6e 66 6f 72 6d 61 74 69 6f 6e 20 2d 20 4e 54 53 54 41 54 55 53 3a}
		$s8 = {00 45 72 72 6f 72 20 77 68 69 6c 65 20 65 72 61 73 69 6e 67 20 70 65 20 68 65 61 64 65 72 2e 20 4e 54 53 74 61 74 75 73 3a 20}

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) and all of them
}

rule Builder_MSIL_SinfulOffice_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'SinfulOffice' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "cf020fb3-751b-5346-8c0d-dc0a552599a3"

	strings:
		$typelibguid0 = {((39 39 34 30 65 31 38 66 2d 65 33 63 37 2d 34 35 30 66 2d 38 30 31 61 2d 30 37 64 64 35 33 34 63 63 62 39 61) | (39 00 39 00 34 00 30 00 65 00 31 00 38 00 66 00 2d 00 65 00 33 00 63 00 37 00 2d 00 34 00 35 00 30 00 66 00 2d 00 38 00 30 00 31 00 61 00 2d 00 30 00 37 00 64 00 64 00 35 00 33 00 34 00 63 00 63 00 62 00 39 00 61 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule Loader_MSIL_SharPy_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'SharPy' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "7c7bda22-bacc-5901-a650-a30c9cfcdee7"

	strings:
		$typelibguid0 = {((66 36 63 66 31 64 33 62 2d 33 65 34 33 2d 34 65 63 66 2d 62 62 36 64 2d 36 37 33 31 36 31 30 62 34 38 36 36) | (66 00 36 00 63 00 66 00 31 00 64 00 33 00 62 00 2d 00 33 00 65 00 34 00 33 00 2d 00 34 00 65 00 63 00 66 00 2d 00 62 00 62 00 36 00 64 00 2d 00 36 00 37 00 33 00 31 00 36 00 31 00 30 00 62 00 34 00 38 00 36 00 36 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule APT_Loader_MSIL_WILDCHILD_1 : hardened
{
	meta:
		date = "2020-12-01"
		modified = "2020-12-01"
		md5 = "6f04a93753ae3ae043203437832363c4"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "b9e0707e-98eb-55da-ad1d-6a84bd113747"

	strings:
		$s1 = {00 51 75 65 75 65 55 73 65 72 41 50 43 00}
		$s2 = {00 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00}
		$sb1 = { 6F [2] 00 0A 28 [2] 00 0A 6F [2] 00 0A 13 ?? 28 [2] 00 0A 28 [2] 00 0A 13 ?? 11 ?? 11 ?? 28 [2] 00 0A [0-16] 7B [2] 00 04 1? 20 [4] 28 [2] 00 0A 11 ?? 28 [2] 00 0A 28 [2] 00 0A 7E [2] 00 0A 7E [2] 00 0A 28 [2] 00 06 [0-16] 14 7E [2] 00 0A 7E [2] 00 0A 1? 20 04 00 08 08 7E [2] 00 0A 14 12 ?? 12 ?? 28 [2] 00 06 [0-16] 7B [2] 00 04 7E [2] 00 0A [0-16] 8E ?? 7E [2] 00 04 7E [2] 00 04 28 [2] 00 06 [4-120] 28 [2] 00 06 [0-80] 6F [2] 00 0A 6F [2] 00 0A 28 [2] 00 06 13 ?? 11 ?? 11 ?? 7E [2] 00 0A 28 [2] 00 06 }

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule Loader_Win_Generic_18 : hardened
{
	meta:
		date = "2020-11-25"
		modified = "2020-11-25"
		md5 = "c74ebb6c238bbfaefd5b32d2bf7c7fcc"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "6f44bd64-29bd-50e2-8b61-7ba61bb1f688"

	strings:
		$s0 = { 89 [1-16] FF 15 [4-16] 89 [1-24] E8 [4-16] 89 C6 [4-24] 8D [1-8] 89 [1-4] 89 [1-4] E8 [4-16] 89 [1-8] E8 [4-24] 01 00 00 00 [1-8] 89 [1-8] E8 [4-64] 8A [1-8] 88 }
		$s2 = { 83 EC [4-24] 00 10 00 00 [4-24] C7 44 24 ?? ?? 00 00 00 [0-8] FF 15 [4-24] 89 [1-4] 89 [1-4] 89 [1-8] FF 15 [4-16] 3? ?? 7? [4-24] 20 00 00 00 [4-24] FF 15 [4-32] F3 A5 }
		$si1 = {66 72 65 61 64}
		$si2 = {66 77 72 69 74 65}

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HackTool_MSIL_HOLSTER_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the a customized version of the 'DUEDLLIGENCE' project."
		md5 = "a91bf61cc18705be2288a0f6f125068f"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "e1e8979e-2dee-5061-a11d-00dcfba476c3"

	strings:
		$typelibguid1 = {((61 38 62 64 62 62 61 34 2d 37 32 39 31 2d 34 39 64 31 2d 39 61 31 62 2d 33 37 32 64 65 34 35 61 39 64 38 38) | (61 00 38 00 62 00 64 00 62 00 62 00 61 00 34 00 2d 00 37 00 32 00 39 00 31 00 2d 00 34 00 39 00 64 00 31 00 2d 00 39 00 61 00 31 00 62 00 2d 00 33 00 37 00 32 00 64 00 65 00 34 00 35 00 61 00 39 00 64 00 38 00 38 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule APT_Loader_MSIL_TRIMBISHOP_1 : hardened
{
	meta:
		date = "2020-12-03"
		modified = "2020-12-03"
		md5 = "e91670423930cbbd3dbf5eac1f1a7cb6"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "1a3f4247-25f4-51ca-b881-209c0753b915"

	strings:
		$sb1 = { 28 [2] 00 06 0A 06 7B [2] 00 04 [12-64] 06 7B [2] 00 04 6E 28 [2] 00 06 0B 07 7B [2] 00 04 [12-64] 0? 7B [2] 00 04 0? 7B [2] 00 04 0? 7B [2] 00 04 6E 28 [2] 00 06 0? 0? 7B [2] 00 04 [12-80] 0? 7B [2] 00 04 1? 0? 7B [2] 00 04 }
		$sb2 = { 0F ?? 7C [2] 00 04 28 [2] 00 0A 8C [2] 00 01 [20-80] 28 [2] 00 06 0? 0? 7E [2] 00 0A 28 [2] 00 0A [12-80] 7E [2] 00 0A 13 ?? 0? 7B [2] 00 04 28 [2] 00 0A 0? 28 [2] 00 0A 58 28 [2] 00 0A 13 [1-32] 28 [2] 00 0A [0-32] D0 [2] 00 02 28 [2] 00 0A 28 [2] 00 0A 74 [2] 00 02 }
		$ss1 = {00 4e 74 4d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e 00}
		$ss2 = {00 4e 74 4f 70 65 6e 50 72 6f 63 65 73 73 00}
		$ss3 = {00 4e 74 41 6c 65 72 74 52 65 73 75 6d 65 54 68 72 65 61 64 00}
		$ss4 = {00 4c 64 72 47 65 74 50 72 6f 63 65 64 75 72 65 41 64 64 72 65 73 73 00}
		$tb1 = {00 44 54 72 69 6d 2e 45 78 65 63 75 74 69 6f 6e 2e 44 79 6e 61 6d 69 63 49 6e 76 6f 6b 65 00}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( @sb1 [ 1 ] < @sb2 [ 1 ] ) and ( all of ( $ss* ) ) and ( all of ( $tb* ) )
}

rule APT_Loader_MSIL_TRIMBISHOP_2 : hardened
{
	meta:
		date = "2020-12-03"
		modified = "2020-12-03"
		md5 = "c0598321d4ad4cf1219cc4f84bad4094"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "90ee2569-2e68-517b-b2d7-8c4015d92683"

	strings:
		$ss1 = {00 4e 74 4d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e 00}
		$ss2 = {00 4e 74 4f 70 65 6e 50 72 6f 63 65 73 73 00}
		$ss3 = {00 4e 74 41 6c 65 72 74 52 65 73 75 6d 65 54 68 72 65 61 64 00}
		$ss4 = {00 4c 64 72 47 65 74 50 72 6f 63 65 64 75 72 65 41 64 64 72 65 73 73 00}
		$ss5 = {2f 28 00 3f 00 69 00 29 00 28 00 2d 00 7c 00 2d 00 2d 00 7c 00 2f 00 29 00 28 00 69 00 7c 00 49 00 6e 00 6a 00 65 00 63 00 74 00 29 00 24 00}
		$ss6 = {2d 28 00 3f 00 69 00 29 00 28 00 2d 00 7c 00 2d 00 2d 00 7c 00 2f 00 29 00 28 00 63 00 7c 00 43 00 6c 00 65 00 61 00 6e 00 29 00 24 00}
		$tb1 = {00 44 54 72 69 6d 2e 45 78 65 63 75 74 69 6f 6e 2e 44 79 6e 61 6d 69 63 49 6e 76 6f 6b 65 00}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule APT_Backdoor_Win_DShell_3 : hardened
{
	meta:
		description = "This rule looks for strings specific to the D programming language in combination with sections of an integer array which contains the encoded payload found within DShell"
		md5 = "cf752e9cd2eccbda5b8e4c29ab5554b6"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "31717164-9876-58f8-af27-d27c81d20fba"

	strings:
		$dlang1 = {((43 3a 5c 44 5c 64 6d 64 32 5c 77 69 6e 64 6f 77 73 5c 62 69 6e 5c 2e 2e 5c 2e 2e 5c 73 72 63 5c 70 68 6f 62 6f 73 5c 73 74 64 5c 75 74 66 2e 64) | (43 00 3a 00 5c 00 44 00 5c 00 64 00 6d 00 64 00 32 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 62 00 69 00 6e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 73 00 72 00 63 00 5c 00 70 00 68 00 6f 00 62 00 6f 00 73 00 5c 00 73 00 74 00 64 00 5c 00 75 00 74 00 66 00 2e 00 64 00))}
		$dlang2 = {((43 3a 5c 44 5c 64 6d 64 32 5c 77 69 6e 64 6f 77 73 5c 62 69 6e 5c 2e 2e 5c 2e 2e 5c 73 72 63 5c 70 68 6f 62 6f 73 5c 73 74 64 5c 66 69 6c 65 2e 64) | (43 00 3a 00 5c 00 44 00 5c 00 64 00 6d 00 64 00 32 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 62 00 69 00 6e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 73 00 72 00 63 00 5c 00 70 00 68 00 6f 00 62 00 6f 00 73 00 5c 00 73 00 74 00 64 00 5c 00 66 00 69 00 6c 00 65 00 2e 00 64 00))}
		$dlang3 = {((43 3a 5c 44 5c 64 6d 64 32 5c 77 69 6e 64 6f 77 73 5c 62 69 6e 5c 2e 2e 5c 2e 2e 5c 73 72 63 5c 70 68 6f 62 6f 73 5c 73 74 64 5c 66 6f 72 6d 61 74 2e 64) | (43 00 3a 00 5c 00 44 00 5c 00 64 00 6d 00 64 00 32 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 62 00 69 00 6e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 73 00 72 00 63 00 5c 00 70 00 68 00 6f 00 62 00 6f 00 73 00 5c 00 73 00 74 00 64 00 5c 00 66 00 6f 00 72 00 6d 00 61 00 74 00 2e 00 64 00))}
		$dlang4 = {((43 3a 5c 44 5c 64 6d 64 32 5c 77 69 6e 64 6f 77 73 5c 62 69 6e 5c 2e 2e 5c 2e 2e 5c 73 72 63 5c 70 68 6f 62 6f 73 5c 73 74 64 5c 62 61 73 65 36 34 2e 64) | (43 00 3a 00 5c 00 44 00 5c 00 64 00 6d 00 64 00 32 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 62 00 69 00 6e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 73 00 72 00 63 00 5c 00 70 00 68 00 6f 00 62 00 6f 00 73 00 5c 00 73 00 74 00 64 00 5c 00 62 00 61 00 73 00 65 00 36 00 34 00 2e 00 64 00))}
		$dlang5 = {((43 3a 5c 44 5c 64 6d 64 32 5c 77 69 6e 64 6f 77 73 5c 62 69 6e 5c 2e 2e 5c 2e 2e 5c 73 72 63 5c 70 68 6f 62 6f 73 5c 73 74 64 5c 73 74 64 69 6f 2e 64) | (43 00 3a 00 5c 00 44 00 5c 00 64 00 6d 00 64 00 32 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 62 00 69 00 6e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 73 00 72 00 63 00 5c 00 70 00 68 00 6f 00 62 00 6f 00 73 00 5c 00 73 00 74 00 64 00 5c 00 73 00 74 00 64 00 69 00 6f 00 2e 00 64 00))}
		$dlang6 = {((5c 2e 2e 5c 2e 2e 5c 73 72 63 5c 70 68 6f 62 6f 73 5c 73 74 64 5c 75 74 66 2e 64) | (5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 73 00 72 00 63 00 5c 00 70 00 68 00 6f 00 62 00 6f 00 73 00 5c 00 73 00 74 00 64 00 5c 00 75 00 74 00 66 00 2e 00 64 00))}
		$dlang7 = {((5c 2e 2e 5c 2e 2e 5c 73 72 63 5c 70 68 6f 62 6f 73 5c 73 74 64 5c 66 69 6c 65 2e 64) | (5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 73 00 72 00 63 00 5c 00 70 00 68 00 6f 00 62 00 6f 00 73 00 5c 00 73 00 74 00 64 00 5c 00 66 00 69 00 6c 00 65 00 2e 00 64 00))}
		$dlang8 = {((5c 2e 2e 5c 2e 2e 5c 73 72 63 5c 70 68 6f 62 6f 73 5c 73 74 64 5c 66 6f 72 6d 61 74 2e 64) | (5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 73 00 72 00 63 00 5c 00 70 00 68 00 6f 00 62 00 6f 00 73 00 5c 00 73 00 74 00 64 00 5c 00 66 00 6f 00 72 00 6d 00 61 00 74 00 2e 00 64 00))}
		$dlang9 = {((5c 2e 2e 5c 2e 2e 5c 73 72 63 5c 70 68 6f 62 6f 73 5c 73 74 64 5c 62 61 73 65 36 34 2e 64) | (5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 73 00 72 00 63 00 5c 00 70 00 68 00 6f 00 62 00 6f 00 73 00 5c 00 73 00 74 00 64 00 5c 00 62 00 61 00 73 00 65 00 36 00 34 00 2e 00 64 00))}
		$dlang10 = {((5c 2e 2e 5c 2e 2e 5c 73 72 63 5c 70 68 6f 62 6f 73 5c 73 74 64 5c 73 74 64 69 6f 2e 64) | (5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 73 00 72 00 63 00 5c 00 70 00 68 00 6f 00 62 00 6f 00 73 00 5c 00 73 00 74 00 64 00 5c 00 73 00 74 00 64 00 69 00 6f 00 2e 00 64 00))}
		$dlang11 = {((55 6e 65 78 70 65 63 74 65 64 20 27 5c 6e 27 20 77 68 65 6e 20 63 6f 6e 76 65 72 74 69 6e 67 20 66 72 6f 6d 20 74 79 70 65 20 63 6f 6e 73 74 28 63 68 61 72 29 5b 5d 20 74 6f 20 74 79 70 65 20 69 6e 74) | (55 00 6e 00 65 00 78 00 70 00 65 00 63 00 74 00 65 00 64 00 20 00 27 00 5c 00 6e 00 27 00 20 00 77 00 68 00 65 00 6e 00 20 00 63 00 6f 00 6e 00 76 00 65 00 72 00 74 00 69 00 6e 00 67 00 20 00 66 00 72 00 6f 00 6d 00 20 00 74 00 79 00 70 00 65 00 20 00 63 00 6f 00 6e 00 73 00 74 00 28 00 63 00 68 00 61 00 72 00 29 00 5b 00 5d 00 20 00 74 00 6f 00 20 00 74 00 79 00 70 00 65 00 20 00 69 00 6e 00 74 00))}
		$e0 = {2c 30 2c}
		$e1 = {2c 31 2c}
		$e2 = {2c 32 2c}
		$e3 = {2c 33 2c}
		$e4 = {2c 34 2c}
		$e5 = {2c 35 2c}
		$e6 = {2c 36 2c}
		$e7 = {2c 37 2c}
		$e8 = {2c 38 2c}
		$e9 = {2c 39 2c}
		$e10 = {2c 31 30 2c}
		$e11 = {2c 31 31 2c}
		$e12 = {2c 31 32 2c}
		$e13 = {2c 31 33 2c}
		$e14 = {2c 31 34 2c}
		$e15 = {2c 31 35 2c}
		$e16 = {2c 31 36 2c}
		$e17 = {2c 31 37 2c}
		$e18 = {2c 31 38 2c}
		$e19 = {2c 31 39 2c}
		$e20 = {2c 32 30 2c}
		$e21 = {2c 32 31 2c}
		$e22 = {2c 32 32 2c}
		$e23 = {2c 32 33 2c}
		$e24 = {2c 32 34 2c}
		$e25 = {2c 32 35 2c}
		$e26 = {2c 32 36 2c}
		$e27 = {2c 32 37 2c}
		$e28 = {2c 32 38 2c}
		$e29 = {2c 32 39 2c}
		$e30 = {2c 33 30 2c}
		$e31 = {2c 33 31 2c}
		$e32 = {2c 33 32 2c}
		$e33 = {2c 33 33 2c}
		$e34 = {2c 33 34 2c}
		$e35 = {2c 33 35 2c}
		$e36 = {2c 33 36 2c}
		$e37 = {2c 33 37 2c}
		$e38 = {2c 33 38 2c}
		$e39 = {2c 33 39 2c}
		$e40 = {2c 34 30 2c}
		$e41 = {2c 34 31 2c}
		$e42 = {2c 34 32 2c}
		$e43 = {2c 34 33 2c}
		$e44 = {2c 34 34 2c}
		$e45 = {2c 34 35 2c}
		$e46 = {2c 34 36 2c}
		$e47 = {2c 34 37 2c}
		$e48 = {2c 34 38 2c}
		$e49 = {2c 34 39 2c}
		$e50 = {2c 35 30 2c}
		$e51 = {2c 35 31 2c}
		$e52 = {2c 35 32 2c}
		$e53 = {2c 35 33 2c}
		$e54 = {2c 35 34 2c}
		$e55 = {2c 35 35 2c}
		$e56 = {2c 35 36 2c}
		$e57 = {2c 35 37 2c}
		$e58 = {2c 35 38 2c}
		$e59 = {2c 35 39 2c}
		$e60 = {2c 36 30 2c}
		$e61 = {2c 36 31 2c}
		$e62 = {2c 36 32 2c}
		$e63 = {2c 36 33 2c}
		$e64 = {2c 36 34 2c}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and filesize > 500KB and filesize < 1500KB and 40 of ( $e* ) and 1 of ( $dlang* )
}

rule APT_HackTool_MSIL_SHARPSTOMP_1 : hardened limited
{
	meta:
		date = "2020-12-02"
		modified = "2020-12-02"
		md5 = "83ed748cd94576700268d35666bf3e01"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "4b4a54c8-9717-5fbb-8130-a49162bc6b07"

	strings:
		$s0 = {6d 73 63 6f 72 65 65 2e 64 6c 6c}
		$s1 = {74 69 6d 65 73 74 6f 6d 70 66 69 6c 65}
		$s2 = {73 68 61 72 70 73 74 6f 6d 70}
		$s3 = {47 65 74 4c 61 73 74 57 72 69 74 65 54 69 6d 65}
		$s4 = {53 65 74 4c 61 73 74 57 72 69 74 65 54 69 6d 65}
		$s5 = {47 65 74 43 72 65 61 74 69 6f 6e 54 69 6d 65}
		$s6 = {53 65 74 43 72 65 61 74 69 6f 6e 54 69 6d 65}
		$s7 = {47 65 74 4c 61 73 74 41 63 63 65 73 73 54 69 6d 65}
		$s8 = {53 65 74 4c 61 73 74 41 63 63 65 73 73 54 69 6d 65}

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule APT_HackTool_MSIL_SHARPPATCHCHECK_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharppatchcheck' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "dedc12b9-b9e7-5c13-ad6d-2e286aba2302"

	strings:
		$typelibguid0 = {((35 32 38 62 38 64 66 35 2d 36 65 35 65 2d 34 66 33 62 2d 62 36 31 37 2d 61 63 33 35 65 64 32 66 38 39 37 35) | (35 00 32 00 38 00 62 00 38 00 64 00 66 00 35 00 2d 00 36 00 65 00 35 00 65 00 2d 00 34 00 66 00 33 00 62 00 2d 00 62 00 36 00 31 00 37 00 2d 00 61 00 63 00 33 00 35 00 65 00 64 00 32 00 66 00 38 00 39 00 37 00 35 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HackTool_MSIL_SAFETYKATZ_4 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public SafetyKatz project."
		md5 = "45736deb14f3a68e88b038183c23e597"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "e160b75d-cc39-5e16-86e1-cba9fe64a6b6"

	strings:
		$typelibguid1 = {((38 33 34 37 45 38 31 42 2d 38 39 46 43 2d 34 32 41 39 2d 42 32 32 43 2d 46 35 39 41 36 41 35 37 32 44 45 43) | (38 00 33 00 34 00 37 00 45 00 38 00 31 00 42 00 2d 00 38 00 39 00 46 00 43 00 2d 00 34 00 32 00 41 00 39 00 2d 00 42 00 32 00 32 00 43 00 2d 00 46 00 35 00 39 00 41 00 36 00 41 00 35 00 37 00 32 00 44 00 45 00 43 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and $typelibguid1
}

rule APT_Backdoor_MacOS_GORAT_1 : hardened
{
	meta:
		description = "This rule is looking for specific strings associated with network activity found within the MacOS generated variant of GORAT"
		md5 = "68acf11f5e456744262ff31beae58526"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "4646eadb-7acf-582f-9ad6-00f012ceed8a"

	strings:
		$s1 = {((53 49 44 31 3d 25 73) | (53 00 49 00 44 00 31 00 3d 00 25 00 73 00))}
		$s2 = {((68 74 74 70 2f 68 74 74 70 2e 64 79 6c 69 62) | (68 00 74 00 74 00 70 00 2f 00 68 00 74 00 74 00 70 00 2e 00 64 00 79 00 6c 00 69 00 62 00))}
		$s3 = {((4d 6f 7a 69 6c 6c 61 2f) | (4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 2f 00))}
		$s4 = {((55 73 65 72 2d 41 67 65 6e 74) | (55 00 73 00 65 00 72 00 2d 00 41 00 67 00 65 00 6e 00 74 00))}
		$s5 = {((43 6f 6f 6b 69 65) | (43 00 6f 00 6f 00 6b 00 69 00 65 00))}

	condition:
		(( uint32( 0 ) == 0xBEBAFECA ) or ( uint32( 0 ) == 0xFEEDFACE ) or ( uint32( 0 ) == 0xFEEDFACF ) or ( uint32( 0 ) == 0xCEFAEDFE ) ) and all of them
}

rule CredTheft_MSIL_ADPassHunt_2 : hardened
{
	meta:
		md5 = "6efb58cf54d1bb45c057efcfbbd68a93"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "44ba09c3-ac0a-58e7-b98c-dedcbf208d00"

	strings:
		$pdb1 = {5c 41 44 50 61 73 73 48 75 6e 74 5c}
		$pdb2 = {5c 41 44 50 61 73 73 48 75 6e 74 2e 70 64 62}
		$s1 = {55 73 61 67 65 3a 20 2e 5c 41 44 50 61 73 73 48 75 6e 74 2e 65 78 65}
		$s2 = {5b 41 44 41 5d 20 53 65 61 72 63 68 69 6e 67 20 66 6f 72 20 61 63 63 6f 75 6e 74 73 20 77 69 74 68 20 6d 73 53 46 55 33 30 50 61 73 73 77 6f 72 64 20 61 74 74 72 69 62 75 74 65}
		$s3 = {5b 41 44 41 5d 20 53 65 61 72 63 68 69 6e 67 20 66 6f 72 20 61 63 63 6f 75 6e 74 73 20 77 69 74 68 20 75 73 65 72 70 61 73 73 77 6f 72 64 20 61 74 74 72 69 62 75 74 65}
		$s4 = {5b 47 50 50 5d 20 53 65 61 72 63 68 69 6e 67 20 66 6f 72 20 70 61 73 73 77 6f 72 64 73 20 6e 6f 77}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( @pdb2 [ 1 ] < @pdb1 [ 1 ] + 50 ) or 2 of ( $s* )
}

rule APT_Loader_Win64_PGF_4 : hardened
{
	meta:
		date = "2020-11-26"
		modified = "2020-11-26"
		md5 = "3bb34ebd93b8ab5799f4843e8cc829fa"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "4c93ba76-d3a5-568d-88b8-79a6ebc2edbb"

	strings:
		$sb1 = { 41 B9 04 00 00 00 41 B8 00 10 00 00 BA [4] B9 00 00 00 00 [0-32] FF [1-24] 7? [1-150] 8B 45 [0-32] 44 0F B? ?? 8B [2-16] B? CD CC CC CC [0-16] C1 ?? 04 [0-16] C1 ?? 02 [0-16] C1 ?? 02 [0-16] 48 8? 05 [4-32] 31 [1-4] 88 }
		$sb2 = { C? 45 ?? 48 [0-32] B8 [0-64] FF [0-32] E0 [0-32] 41 B8 40 00 00 00 BA 0C 00 00 00 48 8B [2] 48 8B [2-32] FF [1-16] 48 89 10 8B 55 ?? 89 ?? 08 48 8B [2] 48 8D ?? 02 48 8B 45 18 48 89 02 }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) and all of them
}

rule APT_Loader_Win32_PGF_4 : hardened
{
	meta:
		date = "2020-11-26"
		modified = "2020-11-26"
		md5 = "4414953fa397a41156f6fa4f9462d207"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "d46d9ae9-cb7d-5a25-9ee2-766097c14af6"

	strings:
		$sb1 = { C7 44 24 0C 04 00 00 00 C7 44 24 08 00 10 00 00 [4-32] C7 04 24 00 00 00 00 [0-32] FF [1-16] 89 45 ?? 83 7D ?? 00 [2-150] 0F B? ?? 8B [2] B? CD CC CC CC 89 ?? F7 ?? C1 ?? 04 89 ?? C1 ?? 02 [0-32] 0F B? [5-32] 3? [1-16] 88 }
		$sb2 = { C? 45 ?? B8 [0-4] C? 45 ?? 00 [0-64] FF [0-32] E0 [0-32] C7 44 24 08 40 00 00 00 [0-32] C7 44 24 04 07 00 00 00 [0-32] FF [1-64] 89 ?? 0F B? [2-3] 89 ?? 04 0F B? [2] 88 ?? 06 8B ?? 08 8D ?? 01 8B 45 0C }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x010B ) and all of them
}

rule CredTheft_MSIL_ADPassHunt_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public ADPassHunt project."
		md5 = "6efb58cf54d1bb45c057efcfbbd68a93"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "35fb8032-c73a-549f-9bd9-409f7050bdb0"

	strings:
		$typelibguid = {((31 35 37 34 35 42 39 45 2d 41 30 35 39 2d 34 41 46 31 2d 41 30 44 38 2d 38 36 33 45 33 34 39 43 44 38 35 44) | (31 00 35 00 37 00 34 00 35 00 42 00 39 00 45 00 2d 00 41 00 30 00 35 00 39 00 2d 00 34 00 41 00 46 00 31 00 2d 00 41 00 30 00 44 00 38 00 2d 00 38 00 36 00 33 00 45 00 33 00 34 00 39 00 43 00 44 00 38 00 35 00 44 00))}

	condition:
		uint16( 0 ) == 0x5A4D and $typelibguid
}

rule HackTool_MSIL_GETDOMAINPASSWORDPOLICY_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the recon utility 'getdomainpasswordpolicy' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "69745e99-33cc-5171-ae7a-5c98439a0b6d"

	strings:
		$typelibguid0 = {((61 35 64 61 31 38 39 37 2d 32 39 61 61 2d 34 35 66 34 2d 61 39 32 34 2d 35 36 31 38 30 34 32 37 36 66 30 38) | (61 00 35 00 64 00 61 00 31 00 38 00 39 00 37 00 2d 00 32 00 39 00 61 00 61 00 2d 00 34 00 35 00 66 00 34 00 2d 00 61 00 39 00 32 00 34 00 2d 00 35 00 36 00 31 00 38 00 30 00 34 00 32 00 37 00 36 00 66 00 30 00 38 00))}

	condition:
		filesize < 10MB and ( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HackTool_MSIL_SharPivot_1 : hardened
{
	meta:
		date = "2020-11-25"
		modified = "2020-11-25"
		md5 = "e4efa759d425e2f26fbc29943a30f5bd"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "c2834bd6-efb0-5dac-adcd-a9450090fc28"

	strings:
		$s2 = { 73 ?? 00 00 0A 0A 06 1F ?? 1F ?? 6F ?? 00 00 0A 0B 73 ?? 00 00 0A 0C 16 13 04 2B 5E 23 [8] 06 6F ?? 00 00 0A 5A 23 [8] 58 28 ?? 00 00 0A 28 ?? 00 00 0A 28 ?? 00 00 0A }
		$s3 = {63 00 6d 00 64 00 5f 00 72 00 70 00 63 00}
		$s4 = {63 6f 73 74 75 72 61}

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule APT_Loader_Win32_PGF_3 : hardened
{
	meta:
		description = "PGF payload, generated rule based on symfunc/c02594972dbab6d489b46c5dee059e66. Identifies dllmain_hook x86 payloads."
		md5 = "4414953fa397a41156f6fa4f9462d207"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "adf91482-6e04-5d11-bc00-4b1c7a802c49"

	strings:
		$cond1 = { 55 89 E5 57 56 53 81 EC FC 06 00 00 C7 85 2C F9 FF FF 90 EE 01 6D C7 85 30 F9 FF FF 6C FE 01 6D 8D 85 34 F9 FF FF 89 28 BA CC 19 00 6D 89 50 04 89 60 08 8D 85 14 F9 FF FF 89 04 24 E8 BB A6 00 00 A1 48 A1 05 6D C7 85 18 F9 FF FF FF FF FF FF FF D0 C7 44 24 08 04 01 00 00 8D 95 B6 FD FF FF 89 54 24 04 89 04 24 E8 B8 AE 00 00 83 EC 0C 85 C0 0F 94 C0 84 C0 0F 85 8B 03 00 00 8D 45 BF 89 C1 E8 56 0B 01 00 8D 85 9C FD FF FF 8D 55 BF 89 54 24 04 8D 95 B6 FD FF FF 89 14 24 C7 85 18 F9 FF FF 01 00 00 00 89 C1 E8 DF B5 01 00 83 EC 08 8D 45 BF 89 C1 E8 52 0B 01 00 A1 4C A1 05 6D C7 85 18 F9 FF FF 02 00 00 00 FF D0 89 44 24 04 C7 04 24 08 00 00 00 E8 51 AE 00 00 83 EC 08 89 45 D0 83 7D D0 00 75 0F C7 85 10 F9 FF FF 00 00 00 00 E9 8C 02 00 00 C7 45 E4 00 00 00 00 C7 45 E0 00 00 00 00 C7 85 74 F9 FF FF 28 04 00 00 8D 85 74 F9 FF FF 89 44 24 04 8B 45 D0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 EF AD 00 00 83 EC 08 89 45 DC 83 7D DC 00 74 67 8D 85 9C FD FF FF C7 44 24 04 00 00 00 00 8D 95 74 F9 FF FF 83 C2 20 89 14 24 89 C1 E8 82 FF 00 00 83 EC 08 83 F8 FF 0F 95 C0 84 C0 74 12 8B 85 88 F9 FF FF 89 45 E4 8B 85 8C F9 FF FF 89 45 E0 8D 85 74 F9 FF FF 89 44 24 04 8B 45 D0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 84 AD 00 00 83 EC 08 89 45 DC EB 93 8B 45 D0 89 04 24 A1 2C A1 05 6D C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 04 83 7D E4 00 74 06 83 7D E0 00 75 0F C7 85 10 F9 FF FF 00 00 00 00 E9 AD 01 00 00 C7 04 24 0C 40 05 6D A1 5C A1 05 6D C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 04 C7 44 24 04 18 40 05 6D 89 04 24 A1 60 A1 05 6D FF D0 83 EC 08 89 45 CC 89 E8 89 45 D8 8D 85 6C F9 FF FF 89 44 24 04 8D 85 70 F9 FF FF 89 04 24 A1 54 A1 05 6D FF D0 83 EC 08 C7 45 D4 00 00 00 00 8B 55 D8 8B 85 6C F9 FF FF 39 C2 0F 83 F5 00 00 00 8B 45 D8 8B 00 3D FF 0F 00 00 0F 86 D8 00 00 00 8B 45 D8 8B 00 39 45 CC 73 19 8B 45 D8 8B 00 8B 55 CC 81 C2 00 10 00 00 39 D0 73 07 C7 45 D4 01 00 00 00 83 7D D4 00 0F 84 AF 00 00 00 8B 45 D8 8B 00 39 45 E4 0F 83 A1 00 00 00 8B 45 D8 8B 00 8B 4D E4 8B 55 E0 01 CA 39 D0 0F 83 8C 00 00 00 B9 00 00 00 00 B8 1C 00 00 00 83 E0 FC 89 C2 B8 00 00 00 00 89 8C 05 50 F9 FF FF 83 C0 04 39 D0 72 F2 8B 45 D8 8B 00 C7 44 24 08 1C 00 00 00 8D 95 50 F9 FF FF 89 54 24 04 89 04 24 A1 9C A1 05 6D C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 0C 8B 85 64 F9 FF FF 83 E0 20 85 C0 74 2E 8B 45 D8 8B 00 C7 44 24 04 30 14 00 6D 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 59 FC FF FF C7 85 10 F9 FF FF 00 00 00 00 EB 58 90 EB 01 90 83 45 D8 04 E9 FA FE FF FF 8B 45 E4 89 45 C8 8B 45 C8 8B 40 3C 89 C2 8B 45 E4 01 D0 89 45 C4 8B 45 C4 8B 50 28 8B 45 E4 01 D0 89 45 C0 C7 44 24 04 30 14 00 6D 8B 45 C0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 FF FB FF FF C7 85 10 F9 FF FF 01 00 00 00 8D 85 9C FD FF FF 89 C1 E8 5D BC 01 00 83 BD 10 F9 FF FF 01 EB 70 8B 95 1C F9 FF FF 8B 85 18 F9 FF FF 85 C0 74 0C 83 E8 01 85 C0 74 2D 83 E8 01 0F 0B 89 95 10 F9 FF FF 8D 45 BF 89 C1 E8 48 08 01 00 8B 85 10 F9 FF FF 89 04 24 C7 85 18 F9 FF FF FF FF FF FF E8 A0 A6 00 00 89 95 10 F9 FF FF 8D 85 9C FD FF FF 89 C1 E8 FD BB 01 00 8B 85 10 F9 FF FF 89 04 24 C7 85 18 F9 FF FF FF FF FF FF E8 75 A6 00 00 90 8D 85 14 F9 FF FF 89 04 24 E8 76 A3 00 00 8D 65 F4 5B 5E 5F 5D C3 }
		$cond2 = { 55 89 E5 57 56 53 81 EC FC 06 00 00 C7 85 2C F9 FF FF B0 EF 3D 6A C7 85 30 F9 FF FF 8C FF 3D 6A 8D 85 34 F9 FF FF 89 28 BA F4 1A 3C 6A 89 50 04 89 60 08 8D 85 14 F9 FF FF 89 04 24 E8 B3 A6 00 00 A1 64 A1 41 6A C7 85 18 F9 FF FF FF FF FF FF FF D0 C7 44 24 08 04 01 00 00 8D 95 B6 FD FF FF 89 54 24 04 89 04 24 E8 B0 AE 00 00 83 EC 0C 85 C0 0F 94 C0 84 C0 0F 85 8B 03 00 00 8D 45 BF 89 C1 E8 4E 0B 01 00 8D 85 9C FD FF FF 8D 55 BF 89 54 24 04 8D 95 B6 FD FF FF 89 14 24 C7 85 18 F9 FF FF 01 00 00 00 89 C1 E8 D7 B5 01 00 83 EC 08 8D 45 BF 89 C1 E8 4A 0B 01 00 A1 68 A1 41 6A C7 85 18 F9 FF FF 02 00 00 00 FF D0 89 44 24 04 C7 04 24 08 00 00 00 E8 49 AE 00 00 83 EC 08 89 45 D0 83 7D D0 00 75 0F C7 85 10 F9 FF FF 00 00 00 00 E9 8C 02 00 00 C7 45 E4 00 00 00 00 C7 45 E0 00 00 00 00 C7 85 74 F9 FF FF 28 04 00 00 8D 85 74 F9 FF FF 89 44 24 04 8B 45 D0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 E7 AD 00 00 83 EC 08 89 45 DC 83 7D DC 00 74 67 8D 85 9C FD FF FF C7 44 24 04 00 00 00 00 8D 95 74 F9 FF FF 83 C2 20 89 14 24 89 C1 E8 7A FF 00 00 83 EC 08 83 F8 FF 0F 95 C0 84 C0 74 12 8B 85 88 F9 FF FF 89 45 E4 8B 85 8C F9 FF FF 89 45 E0 8D 85 74 F9 FF FF 89 44 24 04 8B 45 D0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 7C AD 00 00 83 EC 08 89 45 DC EB 93 8B 45 D0 89 04 24 A1 44 A1 41 6A C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 04 83 7D E4 00 74 06 83 7D E0 00 75 0F C7 85 10 F9 FF FF 00 00 00 00 E9 AD 01 00 00 C7 04 24 62 40 41 6A A1 78 A1 41 6A C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 04 C7 44 24 04 6E 40 41 6A 89 04 24 A1 7C A1 41 6A FF D0 83 EC 08 89 45 CC 89 E8 89 45 D8 8D 85 6C F9 FF FF 89 44 24 04 8D 85 70 F9 FF FF 89 04 24 A1 70 A1 41 6A FF D0 83 EC 08 C7 45 D4 00 00 00 00 8B 55 D8 8B 85 6C F9 FF FF 39 C2 0F 83 F5 00 00 00 8B 45 D8 8B 00 3D FF 0F 00 00 0F 86 D8 00 00 00 8B 45 D8 8B 00 39 45 CC 73 19 8B 45 D8 8B 00 8B 55 CC 81 C2 00 10 00 00 39 D0 73 07 C7 45 D4 01 00 00 00 83 7D D4 00 0F 84 AF 00 00 00 8B 45 D8 8B 00 39 45 E4 0F 83 A1 00 00 00 8B 45 D8 8B 00 8B 4D E4 8B 55 E0 01 CA 39 D0 0F 83 8C 00 00 00 B9 00 00 00 00 B8 1C 00 00 00 83 E0 FC 89 C2 B8 00 00 00 00 89 8C 05 50 F9 FF FF 83 C0 04 39 D0 72 F2 8B 45 D8 8B 00 C7 44 24 08 1C 00 00 00 8D 95 50 F9 FF FF 89 54 24 04 89 04 24 A1 C8 A1 41 6A C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 0C 8B 85 64 F9 FF FF 83 E0 20 85 C0 74 2E 8B 45 D8 8B 00 C7 44 24 04 30 14 3C 6A 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 59 FC FF FF C7 85 10 F9 FF FF 00 00 00 00 EB 58 90 EB 01 90 83 45 D8 04 E9 FA FE FF FF 8B 45 E4 89 45 C8 8B 45 C8 8B 40 3C 89 C2 8B 45 E4 01 D0 89 45 C4 8B 45 C4 8B 50 28 8B 45 E4 01 D0 89 45 C0 C7 44 24 04 30 14 3C 6A 8B 45 C0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 FF FB FF FF C7 85 10 F9 FF FF 01 00 00 00 8D 85 9C FD FF FF 89 C1 E8 55 BC 01 00 83 BD 10 F9 FF FF 01 EB 70 8B 95 1C F9 FF FF 8B 85 18 F9 FF FF 85 C0 74 0C 83 E8 01 85 C0 74 2D 83 E8 01 0F 0B 89 95 10 F9 FF FF 8D 45 BF 89 C1 E8 40 08 01 00 8B 85 10 F9 FF FF 89 04 24 C7 85 18 F9 FF FF FF FF FF FF E8 98 A6 00 00 89 95 10 F9 FF FF 8D 85 9C FD FF FF 89 C1 E8 F5 BB 01 00 8B 85 10 F9 FF FF 89 04 24 C7 85 18 F9 FF FF FF FF FF FF E8 6D A6 00 00 90 8D 85 14 F9 FF FF 89 04 24 E8 6E A3 00 00 8D 65 F4 5B 5E 5F 5D C3 }
		$cond3 = { 55 89 E5 57 56 53 81 EC FC 06 00 00 C7 85 2C F9 FF FF F0 EF D5 63 C7 85 30 F9 FF FF CC FF D5 63 8D 85 34 F9 FF FF 89 28 BA 28 1B D4 63 89 50 04 89 60 08 8D 85 14 F9 FF FF 89 04 24 E8 BF A6 00 00 A1 64 A1 D9 63 C7 85 18 F9 FF FF FF FF FF FF FF D0 C7 44 24 08 04 01 00 00 8D 95 B6 FD FF FF 89 54 24 04 89 04 24 E8 BC AE 00 00 83 EC 0C 85 C0 0F 94 C0 84 C0 0F 85 8B 03 00 00 8D 45 BF 89 C1 E8 5A 0B 01 00 8D 85 9C FD FF FF 8D 55 BF 89 54 24 04 8D 95 B6 FD FF FF 89 14 24 C7 85 18 F9 FF FF 01 00 00 00 89 C1 E8 E3 B5 01 00 83 EC 08 8D 45 BF 89 C1 E8 56 0B 01 00 A1 68 A1 D9 63 C7 85 18 F9 FF FF 02 00 00 00 FF D0 89 44 24 04 C7 04 24 08 00 00 00 E8 55 AE 00 00 83 EC 08 89 45 D0 83 7D D0 00 75 0F C7 85 10 F9 FF FF 00 00 00 00 E9 8C 02 00 00 C7 45 E4 00 00 00 00 C7 45 E0 00 00 00 00 C7 85 74 F9 FF FF 28 04 00 00 8D 85 74 F9 FF FF 89 44 24 04 8B 45 D0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 F3 AD 00 00 83 EC 08 89 45 DC 83 7D DC 00 74 67 8D 85 9C FD FF FF C7 44 24 04 00 00 00 00 8D 95 74 F9 FF FF 83 C2 20 89 14 24 89 C1 E8 86 FF 00 00 83 EC 08 83 F8 FF 0F 95 C0 84 C0 74 12 8B 85 88 F9 FF FF 89 45 E4 8B 85 8C F9 FF FF 89 45 E0 8D 85 74 F9 FF FF 89 44 24 04 8B 45 D0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 88 AD 00 00 83 EC 08 89 45 DC EB 93 8B 45 D0 89 04 24 A1 44 A1 D9 63 C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 04 83 7D E4 00 74 06 83 7D E0 00 75 0F C7 85 10 F9 FF FF 00 00 00 00 E9 AD 01 00 00 C7 04 24 7E 40 D9 63 A1 7C A1 D9 63 C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 04 C7 44 24 04 8A 40 D9 63 89 04 24 A1 80 A1 D9 63 FF D0 83 EC 08 89 45 CC 89 E8 89 45 D8 8D 85 6C F9 FF FF 89 44 24 04 8D 85 70 F9 FF FF 89 04 24 A1 70 A1 D9 63 FF D0 83 EC 08 C7 45 D4 00 00 00 00 8B 55 D8 8B 85 6C F9 FF FF 39 C2 0F 83 F5 00 00 00 8B 45 D8 8B 00 3D FF 0F 00 00 0F 86 D8 00 00 00 8B 45 D8 8B 00 39 45 CC 73 19 8B 45 D8 8B 00 8B 55 CC 81 C2 00 10 00 00 39 D0 73 07 C7 45 D4 01 00 00 00 83 7D D4 00 0F 84 AF 00 00 00 8B 45 D8 8B 00 39 45 E4 0F 83 A1 00 00 00 8B 45 D8 8B 00 8B 4D E4 8B 55 E0 01 CA 39 D0 0F 83 8C 00 00 00 B9 00 00 00 00 B8 1C 00 00 00 83 E0 FC 89 C2 B8 00 00 00 00 89 8C 05 50 F9 FF FF 83 C0 04 39 D0 72 F2 8B 45 D8 8B 00 C7 44 24 08 1C 00 00 00 8D 95 50 F9 FF FF 89 54 24 04 89 04 24 A1 C8 A1 D9 63 C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 0C 8B 85 64 F9 FF FF 83 E0 20 85 C0 74 2E 8B 45 D8 8B 00 C7 44 24 04 30 14 D4 63 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 59 FC FF FF C7 85 10 F9 FF FF 00 00 00 00 EB 58 90 EB 01 90 83 45 D8 04 E9 FA FE FF FF 8B 45 E4 89 45 C8 8B 45 C8 8B 40 3C 89 C2 8B 45 E4 01 D0 89 45 C4 8B 45 C4 8B 50 28 8B 45 E4 01 D0 89 45 C0 C7 44 24 04 30 14 D4 63 8B 45 C0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 FF FB FF FF C7 85 10 F9 FF FF 01 00 00 00 8D 85 9C FD FF FF 89 C1 E8 61 BC 01 00 83 BD 10 F9 FF FF 01 EB 70 8B 95 1C F9 FF FF 8B 85 18 F9 FF FF 85 C0 74 0C 83 E8 01 85 C0 74 2D 83 E8 01 0F 0B 89 95 10 F9 FF FF 8D 45 BF 89 C1 E8 4C 08 01 00 8B 85 10 F9 FF FF 89 04 24 C7 85 18 F9 FF FF FF FF FF FF E8 A4 A6 00 00 89 95 10 F9 FF FF 8D 85 9C FD FF FF 89 C1 E8 01 BC 01 00 8B 85 10 F9 FF FF 89 04 24 C7 85 18 F9 FF FF FF FF FF FF E8 79 A6 00 00 90 8D 85 14 F9 FF FF 89 04 24 E8 7A A3 00 00 8D 65 F4 5B 5E 5F 5D C3 }
		$cond4 = { 55 89 E5 57 56 53 81 EC FC 06 00 00 C7 85 ?? ?? ?? ?? 90 EE 01 6D C7 85 ?? ?? ?? ?? 6C FE 01 6D 8D 85 ?? ?? ?? ?? 89 28 BA CC 19 00 6D 89 50 ?? 89 60 ?? 8D 85 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? FF FF FF FF FF D0 C7 44 24 ?? 04 01 00 00 8D 95 ?? ?? ?? ?? 89 54 24 ?? 89 04 24 E8 ?? ?? ?? ?? 83 EC 0C 85 C0 0F 94 C0 84 C0 0F 85 ?? ?? ?? ?? 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 8D 55 ?? 89 54 24 ?? 8D 95 ?? ?? ?? ?? 89 14 24 C7 85 ?? ?? ?? ?? 01 00 00 00 89 C1 E8 ?? ?? ?? ?? 83 EC 08 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 89 44 24 ?? C7 04 24 08 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? 83 7D ?? 00 75 ?? C7 85 ?? ?? ?? ?? 00 00 00 00 E9 ?? ?? ?? ?? C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 28 04 00 00 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? 83 7D ?? 00 74 ?? 8D 85 ?? ?? ?? ?? C7 44 24 ?? 00 00 00 00 8D 95 ?? ?? ?? ?? 83 C2 20 89 14 24 89 C1 E8 ?? ?? ?? ?? 83 EC 08 83 F8 FF 0F 95 C0 84 C0 74 ?? 8B 85 ?? ?? ?? ?? 89 45 ?? 8B 85 ?? ?? ?? ?? 89 45 ?? 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? EB ?? 8B 45 ?? 89 04 24 A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 04 83 7D ?? 00 74 ?? 83 7D ?? 00 75 ?? C7 85 ?? ?? ?? ?? 00 00 00 00 E9 ?? ?? ?? ?? C7 04 24 0C 40 05 6D A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 04 C7 44 24 ?? 18 40 05 6D 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC 08 89 45 ?? 89 E8 89 45 ?? 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8D 85 ?? ?? ?? ?? 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC 08 C7 45 ?? 00 00 00 00 8B 55 ?? 8B 85 ?? ?? ?? ?? 39 C2 0F 83 ?? ?? ?? ?? 8B 45 ?? 8B 00 3D FF 0F 00 00 0F 86 ?? ?? ?? ?? 8B 45 ?? 8B 00 39 45 ?? 73 ?? 8B 45 ?? 8B 00 8B 55 ?? 81 C2 00 10 00 00 39 D0 73 ?? C7 45 ?? 01 00 00 00 83 7D ?? 00 0F 84 ?? ?? ?? ?? 8B 45 ?? 8B 00 39 45 ?? 0F 83 ?? ?? ?? ?? 8B 45 ?? 8B 00 8B 4D ?? 8B 55 ?? 01 CA 39 D0 0F 83 ?? ?? ?? ?? B9 00 00 00 00 B8 1C 00 00 00 83 E0 FC 89 C2 B8 00 00 00 00 89 8C 05 ?? ?? ?? ?? 83 C0 04 39 D0 72 ?? 8B 45 ?? 8B 00 C7 44 24 ?? 1C 00 00 00 8D 95 ?? ?? ?? ?? 89 54 24 ?? 89 04 24 A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 0C 8B 85 ?? ?? ?? ?? 83 E0 20 85 C0 74 ?? 8B 45 ?? 8B 00 C7 44 24 ?? 30 14 00 6D 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 00 00 00 00 EB ?? 90 EB ?? 90 83 45 ?? 04 E9 ?? ?? ?? ?? 8B 45 ?? 89 45 ?? 8B 45 ?? 8B 40 ?? 89 C2 8B 45 ?? 01 D0 89 45 ?? 8B 45 ?? 8B 50 ?? 8B 45 ?? 01 D0 89 45 ?? C7 44 24 ?? 30 14 00 6D 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 01 00 00 00 8D 85 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 01 EB ?? 8B 95 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 85 C0 74 ?? 83 E8 01 85 C0 74 ?? 83 E8 01 0F 0B 89 95 ?? ?? ?? ?? 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 04 24 C7 85 ?? ?? ?? ?? FF FF FF FF E8 ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 04 24 C7 85 ?? ?? ?? ?? FF FF FF FF E8 ?? ?? ?? ?? 90 8D 85 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 8D 65 ?? 5B 5E 5F 5D C3 }
		$cond5 = { 55 89 E5 57 56 53 81 EC FC 06 00 00 C7 85 ?? ?? ?? ?? B0 EF 3D 6A C7 85 ?? ?? ?? ?? 8C FF 3D 6A 8D 85 ?? ?? ?? ?? 89 28 BA F4 1A 3C 6A 89 50 ?? 89 60 ?? 8D 85 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? FF FF FF FF FF D0 C7 44 24 ?? 04 01 00 00 8D 95 ?? ?? ?? ?? 89 54 24 ?? 89 04 24 E8 ?? ?? ?? ?? 83 EC 0C 85 C0 0F 94 C0 84 C0 0F 85 ?? ?? ?? ?? 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 8D 55 ?? 89 54 24 ?? 8D 95 ?? ?? ?? ?? 89 14 24 C7 85 ?? ?? ?? ?? 01 00 00 00 89 C1 E8 ?? ?? ?? ?? 83 EC 08 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 89 44 24 ?? C7 04 24 08 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? 83 7D ?? 00 75 ?? C7 85 ?? ?? ?? ?? 00 00 00 00 E9 ?? ?? ?? ?? C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 28 04 00 00 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? 83 7D ?? 00 74 ?? 8D 85 ?? ?? ?? ?? C7 44 24 ?? 00 00 00 00 8D 95 ?? ?? ?? ?? 83 C2 20 89 14 24 89 C1 E8 ?? ?? ?? ?? 83 EC 08 83 F8 FF 0F 95 C0 84 C0 74 ?? 8B 85 ?? ?? ?? ?? 89 45 ?? 8B 85 ?? ?? ?? ?? 89 45 ?? 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? EB ?? 8B 45 ?? 89 04 24 A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 04 83 7D ?? 00 74 ?? 83 7D ?? 00 75 ?? C7 85 ?? ?? ?? ?? 00 00 00 00 E9 ?? ?? ?? ?? C7 04 24 62 40 41 6A A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 04 C7 44 24 ?? 6E 40 41 6A 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC 08 89 45 ?? 89 E8 89 45 ?? 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8D 85 ?? ?? ?? ?? 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC 08 C7 45 ?? 00 00 00 00 8B 55 ?? 8B 85 ?? ?? ?? ?? 39 C2 0F 83 ?? ?? ?? ?? 8B 45 ?? 8B 00 3D FF 0F 00 00 0F 86 ?? ?? ?? ?? 8B 45 ?? 8B 00 39 45 ?? 73 ?? 8B 45 ?? 8B 00 8B 55 ?? 81 C2 00 10 00 00 39 D0 73 ?? C7 45 ?? 01 00 00 00 83 7D ?? 00 0F 84 ?? ?? ?? ?? 8B 45 ?? 8B 00 39 45 ?? 0F 83 ?? ?? ?? ?? 8B 45 ?? 8B 00 8B 4D ?? 8B 55 ?? 01 CA 39 D0 0F 83 ?? ?? ?? ?? B9 00 00 00 00 B8 1C 00 00 00 83 E0 FC 89 C2 B8 00 00 00 00 89 8C 05 ?? ?? ?? ?? 83 C0 04 39 D0 72 ?? 8B 45 ?? 8B 00 C7 44 24 ?? 1C 00 00 00 8D 95 ?? ?? ?? ?? 89 54 24 ?? 89 04 24 A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 0C 8B 85 ?? ?? ?? ?? 83 E0 20 85 C0 74 ?? 8B 45 ?? 8B 00 C7 44 24 ?? 30 14 3C 6A 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 00 00 00 00 EB ?? 90 EB ?? 90 83 45 ?? 04 E9 ?? ?? ?? ?? 8B 45 ?? 89 45 ?? 8B 45 ?? 8B 40 ?? 89 C2 8B 45 ?? 01 D0 89 45 ?? 8B 45 ?? 8B 50 ?? 8B 45 ?? 01 D0 89 45 ?? C7 44 24 ?? 30 14 3C 6A 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 01 00 00 00 8D 85 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 01 EB ?? 8B 95 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 85 C0 74 ?? 83 E8 01 85 C0 74 ?? 83 E8 01 0F 0B 89 95 ?? ?? ?? ?? 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 04 24 C7 85 ?? ?? ?? ?? FF FF FF FF E8 ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 04 24 C7 85 ?? ?? ?? ?? FF FF FF FF E8 ?? ?? ?? ?? 90 8D 85 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 8D 65 ?? 5B 5E 5F 5D C3 }
		$cond6 = { 55 89 E5 57 56 53 81 EC FC 06 00 00 C7 85 ?? ?? ?? ?? F0 EF D5 63 C7 85 ?? ?? ?? ?? CC FF D5 63 8D 85 ?? ?? ?? ?? 89 28 BA 28 1B D4 63 89 50 ?? 89 60 ?? 8D 85 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? FF FF FF FF FF D0 C7 44 24 ?? 04 01 00 00 8D 95 ?? ?? ?? ?? 89 54 24 ?? 89 04 24 E8 ?? ?? ?? ?? 83 EC 0C 85 C0 0F 94 C0 84 C0 0F 85 ?? ?? ?? ?? 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 8D 55 ?? 89 54 24 ?? 8D 95 ?? ?? ?? ?? 89 14 24 C7 85 ?? ?? ?? ?? 01 00 00 00 89 C1 E8 ?? ?? ?? ?? 83 EC 08 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 89 44 24 ?? C7 04 24 08 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? 83 7D ?? 00 75 ?? C7 85 ?? ?? ?? ?? 00 00 00 00 E9 ?? ?? ?? ?? C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 28 04 00 00 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? 83 7D ?? 00 74 ?? 8D 85 ?? ?? ?? ?? C7 44 24 ?? 00 00 00 00 8D 95 ?? ?? ?? ?? 83 C2 20 89 14 24 89 C1 E8 ?? ?? ?? ?? 83 EC 08 83 F8 FF 0F 95 C0 84 C0 74 ?? 8B 85 ?? ?? ?? ?? 89 45 ?? 8B 85 ?? ?? ?? ?? 89 45 ?? 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? EB ?? 8B 45 ?? 89 04 24 A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 04 83 7D ?? 00 74 ?? 83 7D ?? 00 75 ?? C7 85 ?? ?? ?? ?? 00 00 00 00 E9 ?? ?? ?? ?? C7 04 24 7E 40 D9 63 A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 04 C7 44 24 ?? 8A 40 D9 63 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC 08 89 45 ?? 89 E8 89 45 ?? 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8D 85 ?? ?? ?? ?? 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC 08 C7 45 ?? 00 00 00 00 8B 55 ?? 8B 85 ?? ?? ?? ?? 39 C2 0F 83 ?? ?? ?? ?? 8B 45 ?? 8B 00 3D FF 0F 00 00 0F 86 ?? ?? ?? ?? 8B 45 ?? 8B 00 39 45 ?? 73 ?? 8B 45 ?? 8B 00 8B 55 ?? 81 C2 00 10 00 00 39 D0 73 ?? C7 45 ?? 01 00 00 00 83 7D ?? 00 0F 84 ?? ?? ?? ?? 8B 45 ?? 8B 00 39 45 ?? 0F 83 ?? ?? ?? ?? 8B 45 ?? 8B 00 8B 4D ?? 8B 55 ?? 01 CA 39 D0 0F 83 ?? ?? ?? ?? B9 00 00 00 00 B8 1C 00 00 00 83 E0 FC 89 C2 B8 00 00 00 00 89 8C 05 ?? ?? ?? ?? 83 C0 04 39 D0 72 ?? 8B 45 ?? 8B 00 C7 44 24 ?? 1C 00 00 00 8D 95 ?? ?? ?? ?? 89 54 24 ?? 89 04 24 A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 0C 8B 85 ?? ?? ?? ?? 83 E0 20 85 C0 74 ?? 8B 45 ?? 8B 00 C7 44 24 ?? 30 14 D4 63 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 00 00 00 00 EB ?? 90 EB ?? 90 83 45 ?? 04 E9 ?? ?? ?? ?? 8B 45 ?? 89 45 ?? 8B 45 ?? 8B 40 ?? 89 C2 8B 45 ?? 01 D0 89 45 ?? 8B 45 ?? 8B 50 ?? 8B 45 ?? 01 D0 89 45 ?? C7 44 24 ?? 30 14 D4 63 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 01 00 00 00 8D 85 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 01 EB ?? 8B 95 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 85 C0 74 ?? 83 E8 01 85 C0 74 ?? 83 E8 01 0F 0B 89 95 ?? ?? ?? ?? 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 04 24 C7 85 ?? ?? ?? ?? FF FF FF FF E8 ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 04 24 C7 85 ?? ?? ?? ?? FF FF FF FF E8 ?? ?? ?? ?? 90 8D 85 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 8D 65 ?? 5B 5E 5F 5D C3 }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x010B ) and any of them
}

rule APT_Loader_Win32_REDFLARE_2 : hardened
{
	meta:
		date = "2020-11-27"
		modified = "2020-11-27"
		md5 = "4e7e90c7147ee8aa01275894734f4492"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "6a585401-bfd3-5aad-b484-09b6a30d9af5"

	strings:
		$inject = { 83 F8 01 [4-50] 6A 00 6A 00 68 04 00 00 08 6A 00 6A 00 6A 00 6A 00 5? [10-70] FF 15 [4] 85 C0 [1-20] 6A 04 68 00 10 00 00 5? 6A 00 5? [1-10] FF 15 [4-8] 85 C0 [1-20] 5? 5? 5? 8B [1-4] 5? 5? FF 15 [4] 85 C0 [1-20] 6A 20 [4-20] FF 15 [4] 85 C0 [1-40] 01 00 01 00 [2-20] FF 15 [4] 85 C0 [1-30] FF 15 [4] 85 C0 [1-20] FF 15 [4] 83 F8 FF }
		$s1 = {52 65 73 75 6d 65 54 68 72 65 61 64}

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x010B ) and all of them
}

rule APT_HackTool_MSIL_SHARPSTOMP_2 : hardened limited
{
	meta:
		date = "2020-12-02"
		modified = "2020-12-02"
		md5 = "83ed748cd94576700268d35666bf3e01"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "d1a3477d-55c6-5c33-bd65-5b1e0d65f24b"

	strings:
		$f0 = {6d 73 63 6f 72 65 65 2e 64 6c 6c}
		$s0 = { 06 72 [4] 6F [4] 2C ?? 06 72 [4] 6F [4] 2D ?? 72 [4] 28 [4] 28 [4] 2A }
		$s1 = { 02 28 [4] 0A 02 28 [4] 0B 02 28 [4] 0C 72 [4] 28 [4] 72 }
		$s2 = { 28 [4] 02 28 [4] 0D 12 ?? 03 6C 28 [4] 28 [4] 02 28 [4] 0D 12 ?? 03 6C 28 [4] 28 [4] 02 28 [4] 0D 12 ?? 03 6C 28 [4] 28 [4] 72 }
		$s3 = {53 65 74 43 72 65 61 74 69 6f 6e 54 69 6d 65}
		$s4 = {47 65 74 4c 61 73 74 41 63 63 65 73 73 54 69 6d 65}
		$s5 = {53 65 74 4c 61 73 74 41 63 63 65 73 73 54 69 6d 65}

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule Loader_MSIL_NetshShellCodeRunner_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'NetshShellCodeRunner' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "b3521812-7ea3-5f80-89bd-3bdd71b687f2"

	strings:
		$typelibguid0 = {((34 39 63 30 34 35 62 63 2d 35 39 62 62 2d 34 61 30 30 2d 38 35 63 33 2d 34 62 65 62 35 39 62 32 65 65 31 32) | (34 00 39 00 63 00 30 00 34 00 35 00 62 00 63 00 2d 00 35 00 39 00 62 00 62 00 2d 00 34 00 61 00 30 00 30 00 2d 00 38 00 35 00 63 00 33 00 2d 00 34 00 62 00 65 00 62 00 35 00 39 00 62 00 32 00 65 00 65 00 31 00 32 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HackTool_MSIL_SharPivot_4 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the SharPivot project."
		md5 = "e4efa759d425e2f26fbc29943a30f5bd"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "c1bd64da-6a54-5bc6-8a89-9c8a93dd965c"

	strings:
		$typelibguid1 = {((34 34 42 38 33 41 36 39 2d 33 34 39 46 2d 34 41 33 45 2d 38 33 32 38 2d 41 34 35 31 33 32 41 37 30 44 36 32) | (34 00 34 00 42 00 38 00 33 00 41 00 36 00 39 00 2d 00 33 00 34 00 39 00 46 00 2d 00 34 00 41 00 33 00 45 00 2d 00 38 00 33 00 32 00 38 00 2d 00 41 00 34 00 35 00 31 00 33 00 32 00 41 00 37 00 30 00 44 00 36 00 32 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and $typelibguid1
}

rule APT_Backdoor_Win_GoRat_Memory : hardened
{
	meta:
		description = "Identifies GoRat malware in memory based on strings."
		md5 = "3b926b5762e13ceec7ac3a61e85c93bb"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "4fcdd98f-1873-58e1-a9f5-73ee0aa5a69f"

	strings:
		$rat1 = {72 61 74 2f 6d 6f 64 75 6c 65 73 2f 73 6f 63 6b 73 2e 28 2a 48 54 54 50 50 72 6f 78 79 43 6c 69 65 6e 74 29 2e 62 65 61 63 6f 6e}
		$rat2 = {72 61 74 2e 28 2a 43 6f 72 65 29 2e 67 65 6e 65 72 61 74 65 42 65 61 63 6f 6e}
		$rat3 = {72 61 74 2e 67 4a 69 74 74 65 72}
		$rat4 = {72 61 74 2f 63 6f 6d 6d 73 2e 28 2a 70 72 6f 74 65 63 74 65 64 43 68 61 6e 6e 65 6c 29 2e 53 65 6e 64 43 6d 64 52 65 73 70 6f 6e 73 65}
		$rat5 = {72 61 74 2f 6d 6f 64 75 6c 65 73 2f 66 69 6c 65 6d 67 6d 74 2e 28 2a 61 63 71 75 69 72 65 29 2e 4e 65 77 43 6f 6d 6d 61 6e 64 45 78 65 63 75 74 69 6f 6e}
		$rat6 = {72 61 74 2f 6d 6f 64 75 6c 65 73 2f 6c 61 74 6c 69 73 74 65 6e 2e 28 2a 6c 61 74 6c 69 73 74 65 6e 73 72 76 29 2e 68 61 6e 64 6c 65 43 6d 64}
		$rat7 = {72 61 74 2f 6d 6f 64 75 6c 65 73 2f 6e 65 74 73 77 65 65 70 65 72 2e 28 2a 6e 65 74 73 77 65 65 70 65 72 52 75 6e 6e 65 72 29 2e 72 75 6e 53 77 65 65 70}
		$rat8 = {72 61 74 2f 6d 6f 64 75 6c 65 73 2f 6e 65 74 73 77 65 65 70 65 72 2e 28 2a 50 69 6e 67 65 72 29 2e 6c 69 73 74 65 6e}
		$rat9 = {72 61 74 2f 6d 6f 64 75 6c 65 73 2f 73 6f 63 6b 73 2e 28 2a 48 54 54 50 50 72 6f 78 79 43 6c 69 65 6e 74 29 2e 62 65 61 63 6f 6e}
		$rat10 = {72 61 74 2f 70 6c 61 74 66 6f 72 6d 73 2f 77 69 6e 2f 64 79 6c 6f 61 64 65 72 2e 28 2a 6d 65 6d 6f 72 79 4c 6f 61 64 65 72 29 2e 45 78 65 63 75 74 65 50 6c 75 67 69 6e 46 75 6e 63 74 69 6f 6e}
		$rat11 = {72 61 74 2f 70 6c 61 74 66 6f 72 6d 73 2f 77 69 6e 2f 6d 6f 64 75 6c 65 73 2f 6e 61 6d 65 64 70 69 70 65 2e 28 2a 64 75 6d 6d 79 29 2e 4f 70 65 6e}
		$winblows = {72 61 74 2f 70 6c 61 74 66 6f 72 6d 73 2f 77 69 6e 2e 28 2a 77 69 6e 62 6c 6f 77 73 29 2e 47 65 74 53 74 61 67 65}

	condition:
		$winblows or 3 of ( $rat* )
}

rule Loader_MSIL_AllTheThings_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'AllTheThings' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "1805b406-2531-56bf-8e08-e63a59ffcc84"

	strings:
		$typelibguid0 = {((35 34 32 63 63 63 36 34 2d 63 34 63 33 2d 34 63 30 33 2d 61 62 63 64 2d 31 39 39 61 31 31 62 32 36 37 35 34) | (35 00 34 00 32 00 63 00 63 00 63 00 36 00 34 00 2d 00 63 00 34 00 63 00 33 00 2d 00 34 00 63 00 30 00 33 00 2d 00 61 00 62 00 63 00 64 00 2d 00 31 00 39 00 39 00 61 00 31 00 31 00 62 00 32 00 36 00 37 00 35 00 34 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule APT_Loader_Win64_PGF_1 : hardened
{
	meta:
		date = "2020-11-25"
		modified = "2020-11-25"
		description = "base dlls: /lib/payload/techniques/unmanaged_exports/"
		md5 = "2b686a8b83f8e1d8b455976ae70dab6e"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "1f2280c0-0fdd-5930-947a-931274bccd6f"

	strings:
		$sb1 = { B9 14 00 00 00 FF 15 [4-32] 0F B6 ?? 04 [0-32] F3 A4 [0-64] 0F B6 [2-3] 0F B6 [2-3] 33 [0-32] 88 [1-9] EB }
		$sb2 = { 41 B8 00 30 00 00 [0-32] FF 15 [8-64] 83 ?? 01 [4-80] 0F B6 [1-64] 33 [1-32] 88 [1-64] FF ( D? | 5? ) }
		$sb3 = { 48 89 4C 24 08 [4-64] 48 63 48 3C [0-32] 48 03 C1 [0-64] 0F B7 48 14 [0-64] 48 8D 44 08 18 [8-64] 0F B7 40 06 [2-32] 48 6B C0 28 }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) and all of them
}

rule APT_Trojan_Win_REDFLARE_5 : hardened
{
	meta:
		date = "2020-12-01"
		modified = "2020-12-01"
		md5 = "dfbb1b988c239ade4c23856e42d4127b, 3322fba40c4de7e3de0fda1123b0bf5d"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "892981d6-f310-5ee8-95b5-dd4bd720a86c"

	strings:
		$s1 = {41 64 6a 75 73 74 54 6f 6b 65 6e 50 72 69 76 69 6c 65 67 65 73}
		$s2 = {4c 6f 6f 6b 75 70 50 72 69 76 69 6c 65 67 65 56 61 6c 75 65 57}
		$s3 = {49 6d 70 65 72 73 6f 6e 61 74 65 4c 6f 67 67 65 64 4f 6e 55 73 65 72}
		$s4 = {72 75 6e 43 6f 6d 6d 61 6e 64}
		$steal_token = { FF 15 [4] 85 C0 [1-40] C7 44 24 ?? 01 00 00 00 [0-20] C7 44 24 ?? 02 00 00 00 [0-20] FF 15 [4] FF [1-5] 85 C0 [4-40] 00 04 00 00 FF 15 [4-5] 85 C0 [2-20] ( BA 0F 00 00 00 | 6A 0F ) [1-4] FF 15 [4] 85 C0 74 [1-20] FF 15 [4] 85 C0 74 [1-20] ( 6A 0B | B9 0B 00 00 00 ) E8 }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule CredTheft_MSIL_TitoSpecial_1 : hardened
{
	meta:
		description = "This rule looks for .NET PE files that have the strings of various method names in the TitoSpecial code."
		md5 = "4bf96a7040a683bd34c618431e571e26"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "932bb013-03de-5cf7-89e9-b3232151d303"

	strings:
		$str1 = {((4d 69 6e 69 64 75 6d 70) | (4d 00 69 00 6e 00 69 00 64 00 75 00 6d 00 70 00))}
		$str2 = {((64 75 6d 70 54 79 70 65) | (64 00 75 00 6d 00 70 00 54 00 79 00 70 00 65 00))}
		$str3 = {((57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79) | (57 00 72 00 69 00 74 00 65 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 4d 00 65 00 6d 00 6f 00 72 00 79 00))}
		$str4 = {((62 49 6e 68 65 72 69 74 48 61 6e 64 6c 65) | (62 00 49 00 6e 00 68 00 65 00 72 00 69 00 74 00 48 00 61 00 6e 00 64 00 6c 00 65 00))}
		$str5 = {((47 65 74 50 72 6f 63 65 73 73 42 79 49 64) | (47 00 65 00 74 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 42 00 79 00 49 00 64 00))}
		$str6 = {((53 61 66 65 48 61 6e 64 6c 65) | (53 00 61 00 66 00 65 00 48 00 61 00 6e 00 64 00 6c 00 65 00))}
		$str7 = {((42 65 67 69 6e 49 6e 76 6f 6b 65) | (42 00 65 00 67 00 69 00 6e 00 49 00 6e 00 76 00 6f 00 6b 00 65 00))}
		$str8 = {((45 6e 64 49 6e 76 6f 6b 65) | (45 00 6e 00 64 00 49 00 6e 00 76 00 6f 00 6b 00 65 00))}
		$str9 = {((43 6f 6e 73 6f 6c 65 41 70 70 6c 69 63 61 74 69 6f 6e 31) | (43 00 6f 00 6e 00 73 00 6f 00 6c 00 65 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 31 00))}
		$str10 = {((67 65 74 4f 53 49 6e 66 6f) | (67 00 65 00 74 00 4f 00 53 00 49 00 6e 00 66 00 6f 00))}
		$str11 = {((4f 70 65 6e 50 72 6f 63 65 73 73) | (4f 00 70 00 65 00 6e 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00))}
		$str12 = {((4c 6f 61 64 4c 69 62 72 61 72 79) | (4c 00 6f 00 61 00 64 00 4c 00 69 00 62 00 72 00 61 00 72 00 79 00))}
		$str13 = {((47 65 74 50 72 6f 63 41 64 64 72 65 73 73) | (47 00 65 00 74 00 50 00 72 00 6f 00 63 00 41 00 64 00 64 00 72 00 65 00 73 00 73 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of ( $str* )
}

rule Builder_MSIL_G2JS_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the Gadget2JScript project."
		md5 = "fa255fdc88ab656ad9bc383f9b322a76"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "484202c2-ac7d-5e6c-8bf1-3452a357c668"

	strings:
		$typelibguid1 = {((41 46 39 43 36 32 41 31 2d 46 38 44 32 2d 34 42 45 30 2d 42 30 31 39 2d 30 41 37 38 37 33 45 38 31 45 41 39) | (41 00 46 00 39 00 43 00 36 00 32 00 41 00 31 00 2d 00 46 00 38 00 44 00 32 00 2d 00 34 00 42 00 45 00 30 00 2d 00 42 00 30 00 31 00 39 00 2d 00 30 00 41 00 37 00 38 00 37 00 33 00 45 00 38 00 31 00 45 00 41 00 39 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and $typelibguid1
}

rule APT_Loader_Win32_DShell_2 : hardened
{
	meta:
		date = "2020-11-27"
		modified = "2020-11-27"
		md5 = "590d98bb74879b52b97d8a158af912af"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "ae34d547-d979-5ce2-bcf8-a5b4e4567de3"

	strings:
		$sb1 = { 6A 40 68 00 30 00 00 [4-32] E8 [4-8] 50 [0-16] E8 [4-150] 6A FF [1-32] 6A 00 6A 00 5? 6A 00 6A 00 [0-32] E8 [4] 50 }
		$ss1 = {00 43 72 65 61 74 65 54 68 72 65 61 64 00}
		$ss2 = {62 61 73 65 36 34 2e 64}
		$ss3 = {63 6f 72 65 2e 73 79 73 2e 77 69 6e 64 6f 77 73}
		$ss4 = {43 3a 5c 55 73 65 72 73 5c 63 6f 6e 66 69 67 2e 69 6e 69}
		$ss5 = {49 6e 76 61 6c 69 64 20 63 6f 6e 66 69 67 20 66 69 6c 65}

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x010B ) and all of them
}

rule HackTool_MSIL_SharPivot_3 : hardened
{
	meta:
		description = "This rule looks for .NET PE files that have the strings of various method names in the SharPivot code."
		md5 = "e4efa759d425e2f26fbc29943a30f5bd"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "956ba026-c2fa-55fd-be53-0cfaa345f27a"

	strings:
		$msil = {((5f 43 6f 72 45 78 65 4d 61 69 6e) | (5f 00 43 00 6f 00 72 00 45 00 78 00 65 00 4d 00 61 00 69 00 6e 00))}
		$str1 = {((53 68 61 72 50 69 76 6f 74) | (53 00 68 00 61 00 72 00 50 00 69 00 76 00 6f 00 74 00))}
		$str2 = {((50 61 72 73 65 41 72 67 73) | (50 00 61 00 72 00 73 00 65 00 41 00 72 00 67 00 73 00))}
		$str3 = {((47 65 6e 52 61 6e 64 6f 6d 53 74 72 69 6e 67) | (47 00 65 00 6e 00 52 00 61 00 6e 00 64 00 6f 00 6d 00 53 00 74 00 72 00 69 00 6e 00 67 00))}
		$str4 = {((53 63 68 65 64 75 6c 65 64 54 61 73 6b 45 78 69 73 74 73) | (53 00 63 00 68 00 65 00 64 00 75 00 6c 00 65 00 64 00 54 00 61 00 73 00 6b 00 45 00 78 00 69 00 73 00 74 00 73 00))}
		$str5 = {((53 65 72 76 69 63 65 45 78 69 73 74 73) | (53 00 65 00 72 00 76 00 69 00 63 00 65 00 45 00 78 00 69 00 73 00 74 00 73 00))}
		$str6 = {((6c 70 50 61 73 73 77 6f 72 64) | (6c 00 70 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00))}
		$str7 = {((65 78 65 63 75 74 65) | (65 00 78 00 65 00 63 00 75 00 74 00 65 00))}
		$str8 = {((57 69 6e 52 4d) | (57 00 69 00 6e 00 52 00 4d 00))}
		$str9 = {((53 63 68 74 61 73 6b 4d 6f 64) | (53 00 63 00 68 00 74 00 61 00 73 00 6b 00 4d 00 6f 00 64 00))}
		$str10 = {((50 6f 69 73 6f 6e 48 61 6e 64 6c 65 72) | (50 00 6f 00 69 00 73 00 6f 00 6e 00 48 00 61 00 6e 00 64 00 6c 00 65 00 72 00))}
		$str11 = {((53 43 53 68 65 6c 6c) | (53 00 43 00 53 00 68 00 65 00 6c 00 6c 00))}
		$str12 = {((53 63 68 74 61 73 6b 4d 6f 64) | (53 00 63 00 68 00 74 00 61 00 73 00 6b 00 4d 00 6f 00 64 00))}
		$str13 = {((53 65 72 76 69 63 65 48 69 6a 61 63 6b) | (53 00 65 00 72 00 76 00 69 00 63 00 65 00 48 00 69 00 6a 00 61 00 63 00 6b 00))}
		$str14 = {((53 65 72 76 69 63 65 48 69 6a 61 63 6b) | (53 00 65 00 72 00 76 00 69 00 63 00 65 00 48 00 69 00 6a 00 61 00 63 00 6b 00))}
		$str15 = {((63 6f 6d 6d 61 6e 64 41 72 67) | (63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 41 00 72 00 67 00))}
		$str16 = {((70 61 79 6c 6f 61 64 50 61 74 68) | (70 00 61 00 79 00 6c 00 6f 00 61 00 64 00 50 00 61 00 74 00 68 00))}
		$str17 = {((53 63 68 74 61 73 6b) | (53 00 63 00 68 00 74 00 61 00 73 00 6b 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and $msil and all of ( $str* )
}

rule APT_HackTool_MSIL_FLUFFY_2 : hardened
{
	meta:
		date = "2020-12-04"
		modified = "2020-12-04"
		md5 = "11b5aceb428c3e8c61ed24a8ca50553e"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "ce39710e-7649-5f7d-bbbe-65dc30f678e8"

	strings:
		$s1 = {00 41 73 6b 74 67 74 00}
		$s2 = {00 4b 65 72 62 65 72 6f 61 73 74 00}
		$s3 = {00 48 61 72 76 65 73 74 43 6f 6d 6d 61 6e 64 00}
		$s4 = {00 45 6e 75 6d 65 72 61 74 65 54 69 63 6b 65 74 73 00}
		$s5 = {5b 00 2a 00 5d 00 20 00 41 00 63 00 74 00 69 00 6f 00 6e 00 3a 00 20 00}
		$s6 = {00 46 6c 75 66 66 79 2e 43 6f 6d 6d 61 6e 64 73 00}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule APT_HackTool_MSIL_FLUFFY_1 : hardened
{
	meta:
		date = "2020-12-04"
		modified = "2020-12-04"
		md5 = "11b5aceb428c3e8c61ed24a8ca50553e"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "6593202d-9b30-59ed-98c0-3e730fb5ceb7"

	strings:
		$sb1 = { 0E ?? 1? 72 [4] 28 [2] 00 06 [0-16] 28 [2] 00 0A [2-80] 1F 58 0? [0-32] 28 [2] 00 06 [2-32] 1? 28 [2] 00 06 0? 0? 6F [2] 00 06 [2-4] 1F 0B }
		$sb2 = { 73 [2] 00 06 13 ?? 11 ?? 11 ?? 7D [2] 00 04 11 ?? 73 [2] 00 0A 7D [2] 00 04 0E ?? 2D ?? 11 ?? 7B [2] 00 04 72 [4] 28 [2] 00 0A [2-32] 0? 28 [2] 00 0A [2-16] 11 ?? 7B [2] 00 04 0? 28 [2] 00 0A 1? 28 [2] 00 0A [2-32] 7E [2] 00 0A [0-32] FE 15 [2] 00 02 [0-16] 7D [2] 00 04 28 [2] 00 06 [2-32] 7B [2] 00 04 7D [2] 00 04 [2-32] 7C [2] 00 04 FE 15 [2] 00 02 [0-16] 11 ?? 8C [2] 00 02 28 [2] 00 0A 28 [2] 00 0A [2-80] 8C [2] 00 02 28 [2] 00 0A 12 ?? 12 ?? 12 ?? 28 [2] 00 06 }
		$ss1 = {00 46 6c 75 66 66 79 00}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HackTool_MSIL_SEATBELT_1 : hardened limited
{
	meta:
		description = "This rule looks for .NET PE files that have regex and format strings found in the public tool SeatBelt. Due to the nature of the regex and format strings used for detection, this rule should detect custom variants of the SeatBelt project."
		md5 = "848837b83865f3854801be1f25cb9f4d"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		date = "2020-12-08"
		modified = "2023-01-27"
		id = "cfd730ac-1eec-5e04-b871-c14912bc0425"

	strings:
		$msil = {((5f 43 6f 72 45 78 65 4d 61 69 6e) | (5f 00 43 00 6f 00 72 00 45 00 78 00 65 00 4d 00 61 00 69 00 6e 00))}
		$str1 = {((7b 20 50 72 6f 63 65 73 73 20 3d 20 7b 30 7d 2c 20 50 61 74 68 20 3d 20 7b 31 7d 2c 20 43 6f 6d 6d 61 6e 64 4c 69 6e 65 20 3d 20 7b 32 7d 20 7d) | (7b 00 20 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 3d 00 20 00 7b 00 30 00 7d 00 2c 00 20 00 50 00 61 00 74 00 68 00 20 00 3d 00 20 00 7b 00 31 00 7d 00 2c 00 20 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 4c 00 69 00 6e 00 65 00 20 00 3d 00 20 00 7b 00 32 00 7d 00 20 00 7d 00))}
		$str2 = {((44 6f 6d 61 69 6e 3d 22 28 2e 2a 29 22 2c 4e 61 6d 65 3d 22 28 2e 2a 29 22) | (44 00 6f 00 6d 00 61 00 69 00 6e 00 3d 00 22 00 28 00 2e 00 2a 00 29 00 22 00 2c 00 4e 00 61 00 6d 00 65 00 3d 00 22 00 28 00 2e 00 2a 00 29 00 22 00))}
		$str3 = {((4c 6f 67 6f 6e 49 64 3d 22 28 5c 64 2b 29 22) | (4c 00 6f 00 67 00 6f 00 6e 00 49 00 64 00 3d 00 22 00 28 00 5c 00 64 00 2b 00 29 00 22 00))}
		$str4 = {((7b 30 7d 2e 7b 31 7d 2e 7b 32 7d 2e 7b 33 7d) | (7b 00 30 00 7d 00 2e 00 7b 00 31 00 7d 00 2e 00 7b 00 32 00 7d 00 2e 00 7b 00 33 00 7d 00))}
		$str5 = {((5e 5c 57 2a 28 5b 61 2d 7a 5d 3a 5c 5c 2e 2b 3f 28 5c 2e 65 78 65 7c 5c 2e 64 6c 6c 7c 5c 2e 73 79 73 29 29 5c 57 2a) | (5e 00 5c 00 57 00 2a 00 28 00 5b 00 61 00 2d 00 7a 00 5d 00 3a 00 5c 00 5c 00 2e 00 2b 00 3f 00 28 00 5c 00 2e 00 65 00 78 00 65 00 7c 00 5c 00 2e 00 64 00 6c 00 6c 00 7c 00 5c 00 2e 00 73 00 79 00 73 00 29 00 29 00 5c 00 57 00 2a 00))}
		$str6 = {((2a 5b 53 79 73 74 65 6d 2f 45 76 65 6e 74 49 44 3d 7b 30 7d 5d) | (2a 00 5b 00 53 00 79 00 73 00 74 00 65 00 6d 00 2f 00 45 00 76 00 65 00 6e 00 74 00 49 00 44 00 3d 00 7b 00 30 00 7d 00 5d 00))}
		$str7 = {((2a 5b 53 79 73 74 65 6d 5b 54 69 6d 65 43 72 65 61 74 65 64 5b 40 53 79 73 74 65 6d 54 69 6d 65 20 3e 3d 20 27 7b) | (2a 00 5b 00 53 00 79 00 73 00 74 00 65 00 6d 00 5b 00 54 00 69 00 6d 00 65 00 43 00 72 00 65 00 61 00 74 00 65 00 64 00 5b 00 40 00 53 00 79 00 73 00 74 00 65 00 6d 00 54 00 69 00 6d 00 65 00 20 00 3e 00 3d 00 20 00 27 00 7b 00))}
		$str8 = {((28 68 74 74 70 7c 66 74 70 7c 68 74 74 70 73 7c 66 69 6c 65 29 3a 2f 2f 28 5b 5c 77 5f 2d 5d 2b 28 3f 3a 28 3f 3a 5c 2e 5b 5c 77 5f 2d 5d 2b 29 2b 29 29 28 5b 5c 77 2e 2c 40 3f 5e 3d 25 26 3a 2f 7e 2b 23 2d 5d 2a 5b 5c 77 40 3f 5e 3d 25 26 2f 7e 2b 23 2d 5d 29 3f) | (28 00 68 00 74 00 74 00 70 00 7c 00 66 00 74 00 70 00 7c 00 68 00 74 00 74 00 70 00 73 00 7c 00 66 00 69 00 6c 00 65 00 29 00 3a 00 2f 00 2f 00 28 00 5b 00 5c 00 77 00 5f 00 2d 00 5d 00 2b 00 28 00 3f 00 3a 00 28 00 3f 00 3a 00 5c 00 2e 00 5b 00 5c 00 77 00 5f 00 2d 00 5d 00 2b 00 29 00 2b 00 29 00 29 00 28 00 5b 00 5c 00 77 00 2e 00 2c 00 40 00 3f 00 5e 00 3d 00 25 00 26 00 3a 00 2f 00 7e 00 2b 00 23 00 2d 00 5d 00 2a 00 5b 00 5c 00 77 00 40 00 3f 00 5e 00 3d 00 25 00 26 00 2f 00 7e 00 2b 00 23 00 2d 00 5d 00 29 00 3f 00))}
		$str10 = {((7b 30 2c 2d 32 33 7d) | (7b 00 30 00 2c 00 2d 00 32 00 33 00 7d 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and $msil and all of ( $str* )
}

rule HackTool_MSIL_INVEIGHZERO_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'inveighzero' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "f46fe365-ea50-5597-828e-61a7225e4c6e"

	strings:
		$typelibguid0 = {((31 31 33 61 65 32 38 31 2d 64 31 65 35 2d 34 32 65 37 2d 39 63 63 32 2d 31 32 64 33 30 37 35 37 62 61 66 31) | (31 00 31 00 33 00 61 00 65 00 32 00 38 00 31 00 2d 00 64 00 31 00 65 00 35 00 2d 00 34 00 32 00 65 00 37 00 2d 00 39 00 63 00 63 00 32 00 2d 00 31 00 32 00 64 00 33 00 30 00 37 00 35 00 37 00 62 00 61 00 66 00 31 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule Loader_MSIL_RURALBISHOP_1 : hardened
{
	meta:
		date = "2020-12-03"
		modified = "2020-12-03"
		md5 = "e91670423930cbbd3dbf5eac1f1a7cb6"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "1b5f1f39-9fa2-5940-8da3-03808e4b7a5d"

	strings:
		$sb1 = { 28 [2] 00 06 0A 06 7B [2] 00 04 [12-64] 06 7B [2] 00 04 6E 28 [2] 00 06 0B 07 7B [2] 00 04 [12-64] 0? 7B [2] 00 04 0? 7B [2] 00 04 0? 7B [2] 00 04 6E 28 [2] 00 06 0? 0? 7B [2] 00 04 [12-80] 0? 7B [2] 00 04 1? 0? 7B [2] 00 04 }
		$sb2 = { 0F ?? 7C [2] 00 04 28 [2] 00 0A 8C [2] 00 01 [20-80] 28 [2] 00 06 0? 0? 7E [2] 00 0A 28 [2] 00 0A [12-80] 7E [2] 00 0A 13 ?? 0? 7B [2] 00 04 28 [2] 00 0A 0? 28 [2] 00 0A 58 28 [2] 00 0A 13 [1-32] 28 [2] 00 0A [0-32] D0 [2] 00 02 28 [2] 00 0A 28 [2] 00 0A 74 [2] 00 02 }
		$ss1 = {00 4e 74 4d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e 00}
		$ss2 = {00 4e 74 4f 70 65 6e 50 72 6f 63 65 73 73 00}
		$ss3 = {00 4e 74 41 6c 65 72 74 52 65 73 75 6d 65 54 68 72 65 61 64 00}
		$ss4 = {00 4c 64 72 47 65 74 50 72 6f 63 65 64 75 72 65 41 64 64 72 65 73 73 00}
		$tb1 = {00 53 68 61 72 70 53 70 6c 6f 69 74 2e 45 78 65 63 75 74 69 6f 6e 2e 44 79 6e 61 6d 69 63 49 6e 76 6f 6b 65 00}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( @sb1 [ 1 ] < @sb2 [ 1 ] ) and ( all of ( $ss* ) ) and ( all of ( $tb* ) )
}

rule Loader_MSIL_RURALBISHOP_2 : hardened
{
	meta:
		date = "2020-12-03"
		modified = "2020-12-03"
		md5 = "e91670423930cbbd3dbf5eac1f1a7cb6"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "3befb3f2-81d1-5db2-84d9-773158b9837c"

	strings:
		$ss1 = {00 4e 74 4d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e 00}
		$ss2 = {00 4e 74 4f 70 65 6e 50 72 6f 63 65 73 73 00}
		$ss3 = {00 4e 74 41 6c 65 72 74 52 65 73 75 6d 65 54 68 72 65 61 64 00}
		$ss4 = {00 4c 64 72 47 65 74 50 72 6f 63 65 64 75 72 65 41 64 64 72 65 73 73 00}
		$ss5 = {2f 28 00 3f 00 69 00 29 00 28 00 2d 00 7c 00 2d 00 2d 00 7c 00 2f 00 29 00 28 00 69 00 7c 00 49 00 6e 00 6a 00 65 00 63 00 74 00 29 00 24 00}
		$ss6 = {2d 28 00 3f 00 69 00 29 00 28 00 2d 00 7c 00 2d 00 2d 00 7c 00 2f 00 29 00 28 00 63 00 7c 00 43 00 6c 00 65 00 61 00 6e 00 29 00 24 00}
		$tb1 = {00 53 68 61 72 70 53 70 6c 6f 69 74 2e 45 78 65 63 75 74 69 6f 6e 2e 44 79 6e 61 6d 69 63 49 6e 76 6f 6b 65 00}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HackTool_MSIL_PrepShellcode_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'PrepShellcode' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "32fb6b1d-e01f-5555-8516-088dca2166cf"

	strings:
		$typelibguid0 = {((64 31 36 65 64 32 37 35 2d 37 30 64 35 2d 34 61 65 35 2d 38 63 65 37 2d 64 32 34 39 66 39 36 37 36 31 36 63) | (64 00 31 00 36 00 65 00 64 00 32 00 37 00 35 00 2d 00 37 00 30 00 64 00 35 00 2d 00 34 00 61 00 65 00 35 00 2d 00 38 00 63 00 65 00 37 00 2d 00 64 00 32 00 34 00 39 00 66 00 39 00 36 00 37 00 36 00 31 00 36 00 63 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule APT_Downloader_Win32_REDFLARE_1 : hardened
{
	meta:
		date = "2020-11-27"
		modified = "2020-11-27"
		md5 = "05b99d438dac63a5a993cea37c036673"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "e8d7ee31-568e-58ac-98ad-49baa2eb37ea"

	strings:
		$const = {43 6f 6f 6b 69 65 3a 20 53 49 44 31 3d 25 73}
		$http_req = { 00 00 08 80 81 3D [4] BB 01 00 00 75 [1-10] 00 00 80 00 [1-4] 00 10 00 00 [1-4] 00 20 00 00 89 [1-10] 6A 00 8B [1-8] 5? 6A 00 6A 00 6A 00 8B [1-8] 5? 68 [4] 8B [1-8] 5? FF 15 [4-40] 6A 14 E8 }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x010B ) and all of them
}

rule Loader_MSIL_WMIRunner_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'WMIRunner' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "04c6acfc-859f-5e4a-8c59-9adf08f21657"

	strings:
		$typelibguid0 = {((36 63 63 36 31 39 39 35 2d 39 66 64 35 2d 34 36 34 39 2d 62 33 63 63 2d 36 66 30 30 31 64 36 30 63 65 64 61) | (36 00 63 00 63 00 36 00 31 00 39 00 39 00 35 00 2d 00 39 00 66 00 64 00 35 00 2d 00 34 00 36 00 34 00 39 00 2d 00 62 00 33 00 63 00 63 00 2d 00 36 00 66 00 30 00 30 00 31 00 64 00 36 00 30 00 63 00 65 00 64 00 61 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HackTool_MSIL_SharpStomp_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the SharpStomp project."
		md5 = "83ed748cd94576700268d35666bf3e01"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "e113c221-fabe-5af4-b763-463c4f86288d"

	strings:
		$typelibguid1 = {((34 31 66 33 35 65 37 39 2d 32 30 33 34 2d 34 39 36 61 2d 38 63 38 32 2d 38 36 34 34 33 31 36 34 61 64 61 32) | (34 00 31 00 66 00 33 00 35 00 65 00 37 00 39 00 2d 00 32 00 30 00 33 00 34 00 2d 00 34 00 39 00 36 00 61 00 2d 00 38 00 63 00 38 00 32 00 2d 00 38 00 36 00 34 00 34 00 33 00 31 00 36 00 34 00 61 00 64 00 61 00 32 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and $typelibguid1
}

rule Tool_MSIL_SharpGrep_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'SharpGrep' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "c7569d33-f57d-5f9c-aa2a-78866c680b5b"

	strings:
		$typelibguid0 = {((66 36 35 64 37 35 62 35 2d 61 32 61 36 2d 34 38 38 66 2d 62 37 34 35 2d 65 36 37 66 63 30 37 35 66 34 34 35) | (66 00 36 00 35 00 64 00 37 00 35 00 62 00 35 00 2d 00 61 00 32 00 61 00 36 00 2d 00 34 00 38 00 38 00 66 00 2d 00 62 00 37 00 34 00 35 00 2d 00 65 00 36 00 37 00 66 00 63 00 30 00 37 00 35 00 66 00 34 00 34 00 35 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule Dropper_HTA_WildChild_1 : hardened
{
	meta:
		description = "This rule looks for strings present in unobfuscated HTAs generated by the WildChild builder."
		md5 = "3e61ca5057633459e96897f79970a46d"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "f570baa5-7d58-5a0a-b713-769e62076f76"

	strings:
		$s1 = {((70 72 6f 63 65 73 73 70 61 74 68) | (70 00 72 00 6f 00 63 00 65 00 73 00 73 00 70 00 61 00 74 00 68 00))}
		$s2 = {((76 34 2e 30 2e 33 30 33 31 39) | (76 00 34 00 2e 00 30 00 2e 00 33 00 30 00 33 00 31 00 39 00))}
		$s3 = {((76 32 2e 30 2e 35 30 37 32 37) | (76 00 32 00 2e 00 30 00 2e 00 35 00 30 00 37 00 32 00 37 00))}
		$s4 = {((43 4f 4d 50 4c 55 53 5f 56 65 72 73 69 6f 6e) | (43 00 4f 00 4d 00 50 00 4c 00 55 00 53 00 5f 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00))}
		$s5 = {((46 72 6f 6d 42 61 73 65 36 34 54 72 61 6e 73 66 6f 72 6d) | (46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 54 00 72 00 61 00 6e 00 73 00 66 00 6f 00 72 00 6d 00))}
		$s6 = {((4d 65 6d 6f 72 79 53 74 72 65 61 6d) | (4d 00 65 00 6d 00 6f 00 72 00 79 00 53 00 74 00 72 00 65 00 61 00 6d 00))}
		$s7 = {((65 6e 74 72 79 5f 63 6c 61 73 73) | (65 00 6e 00 74 00 72 00 79 00 5f 00 63 00 6c 00 61 00 73 00 73 00))}
		$s8 = {((44 79 6e 61 6d 69 63 49 6e 76 6f 6b 65) | (44 00 79 00 6e 00 61 00 6d 00 69 00 63 00 49 00 6e 00 76 00 6f 00 6b 00 65 00))}
		$s9 = {((53 65 6e 64 6f 66 66) | (53 00 65 00 6e 00 64 00 6f 00 66 00 66 00))}
		$script_header = {((3c 73 63 72 69 70 74 20 6c 61 6e 67 75 61 67 65 3d) | (3c 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 6c 00 61 00 6e 00 67 00 75 00 61 00 67 00 65 00 3d 00))}

	condition:
		$script_header at 0 and all of ( $s* )
}

rule APT_Builder_PY_REDFLARE_2 : hardened
{
	meta:
		date = "2020-12-01"
		modified = "2020-12-01"
		md5 = "4410e95de247d7f1ab649aa640ee86fb"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "74c56ee1-734e-5fdb-beee-6345a5993f68"

	strings:
		$s1 = {3c 35 31 30 73 78 78 49 49}
		$s2 = {30 78 34 33 2c 30 78 30 30 2c 30 78 33 61 2c 30 78 30 30 2c 30 78 35 63 2c 30 78 30 30 2c 30 78 35 37 2c 30 78 30 30 2c 30 78 36 39 2c 30 78 30 30 2c 30 78 36 65 2c 30 78 30 30 2c 30 78 36 34 2c 30 78 30 30 2c 30 78 36 66 2c 30 78 30 30 2c}
		$s3 = {70 61 72 73 65 50 6c 75 67 69 6e 4f 75 74 70 75 74}

	condition:
		all of them and #s2 == 2
}

rule APT_Loader_Win32_DShell_3 : hardened
{
	meta:
		date = "2020-11-27"
		modified = "2020-11-27"
		md5 = "12c3566761495b8353f67298f15b882c"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "6b6fccef-ac93-5f1b-b9b6-c2d3ee4d8da7"

	strings:
		$sb1 = { 6A 40 68 00 30 00 00 [4-32] E8 [4-8] 50 [0-16] E8 [4-150] 6A FF [1-32] 6A 00 6A 00 5? 6A 00 6A 00 [0-32] E8 [4] 50 }
		$ss1 = {00 43 72 65 61 74 65 54 68 72 65 61 64 00}
		$ss2 = {62 61 73 65 36 34 2e 64}
		$ss3 = {63 6f 72 65 2e 73 79 73 2e 77 69 6e 64 6f 77 73}

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x010B ) and all of them
}

rule APT_Trojan_Linux_REDFLARE_1 : hardened
{
	meta:
		date = "2020-12-02"
		modified = "2020-12-02"
		md5 = "79259451ff47b864d71fb3f94b1774f3, 82773afa0860d668d7fe40e3f22b0f3e"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "220302bc-4ed3-5e10-9bd2-a8ed2bdaef73"

	strings:
		$s1 = {66 69 6e 64 5f 61 70 70 6c 65 74 5f 62 79 5f 6e 61 6d 65}
		$s2 = {62 62 5f 62 61 73 65 6e 61 6d 65}
		$s3 = {68 6b 5f 70 72 69 6e 74 66 5f 63 68 6b}
		$s4 = {72 75 6e 43 6f 6d 6d 61 6e 64}
		$s5 = {69 6e 69 74 69 61 6c 69 7a 65}

	condition:
		( uint32( 0 ) == 0x464c457f ) and all of them
}

rule Loader_MSIL_WildChild_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the WildChild project."
		md5 = "7e6bc0ed11c2532b2ae7060327457812"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "350dd658-46c9-573b-b532-07e4b437ba8d"

	strings:
		$typelibguid1 = {((32 65 37 31 64 35 66 66 2d 65 63 65 34 2d 34 30 30 36 2d 39 65 39 38 2d 33 37 62 62 37 32 34 61 37 37 38 30) | (32 00 65 00 37 00 31 00 64 00 35 00 66 00 66 00 2d 00 65 00 63 00 65 00 34 00 2d 00 34 00 30 00 30 00 36 00 2d 00 39 00 65 00 39 00 38 00 2d 00 33 00 37 00 62 00 62 00 37 00 32 00 34 00 61 00 37 00 37 00 38 00 30 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and $typelibguid1
}

rule MSIL_Launcher_DUEDLLIGENCE_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'DUEDLLIGENCE' project."
		md5 = "a91bf61cc18705be2288a0f6f125068f"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "86f0ebe5-110b-53e2-bba5-676f00c2cddd"

	strings:
		$typelibguid0 = {((37 33 39 34 38 39 31 32 2d 63 65 62 64 2d 34 38 65 64 2d 38 35 65 32 2d 38 35 66 63 64 31 64 34 66 35 36 30) | (37 00 33 00 39 00 34 00 38 00 39 00 31 00 32 00 2d 00 63 00 65 00 62 00 64 00 2d 00 34 00 38 00 65 00 64 00 2d 00 38 00 35 00 65 00 32 00 2d 00 38 00 35 00 66 00 63 00 64 00 31 00 64 00 34 00 66 00 35 00 36 00 30 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule APT_Backdoor_Win_GORAT_2 : hardened
{
	meta:
		description = "Verifies that the sample is a Windows PE that is less than 10MB in size and has the Go build ID strings. Then checks for various strings known to be in the Gorat implant including strings used in C2 json, names of methods, and the unique string 'murica' used in C2 comms. A check is done to ensure the string 'rat' appears in the binary over 1000 times as it is the name of the project used by the implant and is present well over 2000 times."
		md5 = "f59095f0ab15f26a1ead7eed8cdb4902"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "e2c47711-d088-5cb4-8d21-f8199a865a28"

	strings:
		$go1 = {((67 6f 2e 62 75 69 6c 64 69 64) | (67 00 6f 00 2e 00 62 00 75 00 69 00 6c 00 64 00 69 00 64 00))}
		$go2 = {((47 6f 20 62 75 69 6c 64 20 49 44 3a) | (47 00 6f 00 20 00 62 00 75 00 69 00 6c 00 64 00 20 00 49 00 44 00 3a 00))}
		$json1 = {((6a 73 6f 6e 3a 22 70 69 64 22) | (6a 00 73 00 6f 00 6e 00 3a 00 22 00 70 00 69 00 64 00 22 00))}
		$json2 = {((6a 73 6f 6e 3a 22 6b 65 79 22) | (6a 00 73 00 6f 00 6e 00 3a 00 22 00 6b 00 65 00 79 00 22 00))}
		$json3 = {((6a 73 6f 6e 3a 22 61 67 65 6e 74 5f 74 69 6d 65 22) | (6a 00 73 00 6f 00 6e 00 3a 00 22 00 61 00 67 00 65 00 6e 00 74 00 5f 00 74 00 69 00 6d 00 65 00 22 00))}
		$json4 = {((6a 73 6f 6e 3a 22 72 69 64 22) | (6a 00 73 00 6f 00 6e 00 3a 00 22 00 72 00 69 00 64 00 22 00))}
		$json5 = {((6a 73 6f 6e 3a 22 70 6f 72 74 73 22) | (6a 00 73 00 6f 00 6e 00 3a 00 22 00 70 00 6f 00 72 00 74 00 73 00 22 00))}
		$json6 = {((6a 73 6f 6e 3a 22 61 67 65 6e 74 5f 70 6c 61 74 66 6f 72 6d 22) | (6a 00 73 00 6f 00 6e 00 3a 00 22 00 61 00 67 00 65 00 6e 00 74 00 5f 00 70 00 6c 00 61 00 74 00 66 00 6f 00 72 00 6d 00 22 00))}
		$rat = {((72 61 74) | (72 00 61 00 74 00))}
		$str1 = {((68 61 6e 64 6c 65 43 6f 6d 6d 61 6e 64) | (68 00 61 00 6e 00 64 00 6c 00 65 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00))}
		$str2 = {((73 65 6e 64 42 65 61 63 6f 6e) | (73 00 65 00 6e 00 64 00 42 00 65 00 61 00 63 00 6f 00 6e 00))}
		$str3 = {((72 61 74 2e 41 67 65 6e 74 56 65 72 73 69 6f 6e) | (72 00 61 00 74 00 2e 00 41 00 67 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00))}
		$str4 = {((72 61 74 2e 43 6f 72 65) | (72 00 61 00 74 00 2e 00 43 00 6f 00 72 00 65 00))}
		$str5 = {((72 61 74 2f 6c 6f 67) | (72 00 61 00 74 00 2f 00 6c 00 6f 00 67 00))}
		$str6 = {((72 61 74 2f 63 6f 6d 6d 73) | (72 00 61 00 74 00 2f 00 63 00 6f 00 6d 00 6d 00 73 00))}
		$str7 = {((72 61 74 2f 6d 6f 64 75 6c 65 73) | (72 00 61 00 74 00 2f 00 6d 00 6f 00 64 00 75 00 6c 00 65 00 73 00))}
		$str8 = {((6d 75 72 69 63 61) | (6d 00 75 00 72 00 69 00 63 00 61 00))}
		$str9 = {((6d 61 73 74 65 72 20 73 65 63 72 65 74) | (6d 00 61 00 73 00 74 00 65 00 72 00 20 00 73 00 65 00 63 00 72 00 65 00 74 00))}
		$str10 = {((54 61 73 6b 49 44) | (54 00 61 00 73 00 6b 00 49 00 44 00))}
		$str11 = {((72 61 74 2e 4e 65 77) | (72 00 61 00 74 00 2e 00 4e 00 65 00 77 00))}

	condition:
		uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 and filesize < 10MB and all of ( $go* ) and all of ( $json* ) and all of ( $str* ) and #rat > 1000
}

rule APT_Loader_Win64_REDFLARE_2 : hardened
{
	meta:
		date = "2020-11-27"
		modified = "2020-11-27"
		md5 = "100d73b35f23b2fe84bf7cd37140bf4d"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "043f4e29-710d-5e17-a0ed-82cd3a565194"

	strings:
		$alloc = { 45 8B C0 33 D2 [2-6] 00 10 00 00 [2-6] 04 00 00 00 [1-6] FF 15 [4-60] FF 15 [4] 85 C0 [4-40] 20 00 00 00 [4-40] FF 15 [4] 85 C0 }
		$inject = { 83 F8 01 [2-20] 33 C0 45 33 C9 [3-10] 45 33 C0 [3-10] 33 D2 [30-100] FF 15 [4] 85 C0 [20-100] 01 00 10 00 [0-10] FF 15 [4] 85 C0 [4-30] FF 15 [4] 85 C0 [2-20] FF 15 [4] 83 F8 FF }
		$s1 = {52 65 73 75 6d 65 54 68 72 65 61 64}

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) and all of them
}

rule HackTool_MSIL_SharPersist_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the SharPersist project."
		md5 = "98ecf58d48a3eae43899b45cec0fc6b7"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "586e6c91-6970-57d1-8d8c-05ae9eb6117a"

	strings:
		$typelibguid1 = {((39 44 31 42 38 35 33 45 2d 35 38 46 31 2d 34 42 41 35 2d 41 45 46 43 2d 35 43 32 32 31 43 41 33 30 45 34 38) | (39 00 44 00 31 00 42 00 38 00 35 00 33 00 45 00 2d 00 35 00 38 00 46 00 31 00 2d 00 34 00 42 00 41 00 35 00 2d 00 41 00 45 00 46 00 43 00 2d 00 35 00 43 00 32 00 32 00 31 00 43 00 41 00 33 00 30 00 45 00 34 00 38 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and $typelibguid1
}

import "pe"

rule APT_Backdoor_Win_GORAT_4 : hardened
{
	meta:
		description = "Verifies that the sample is a Windows PE that is less than 10MB in size and exports numerous functions that are known to be exported by the Gorat implant. This is done in an effort to provide detection for packed samples that may not have other strings but will need to replicate exports to maintain functionality."
		md5 = "f59095f0ab15f26a1ead7eed8cdb4902"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "ae67445c-e7fd-5858-be8b-7ee84a16a031"

	condition:
		uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 and filesize < 10MB and pe.exports ( "MemoryCallEntryPoint" ) and pe.exports ( "MemoryDefaultAlloc" ) and pe.exports ( "MemoryDefaultFree" ) and pe.exports ( "MemoryDefaultFreeLibrary" ) and pe.exports ( "MemoryDefaultGetProcAddress" ) and pe.exports ( "MemoryDefaultLoadLibrary" ) and pe.exports ( "MemoryFindResource" ) and pe.exports ( "MemoryFindResourceEx" ) and pe.exports ( "MemoryFreeLibrary" ) and pe.exports ( "MemoryGetProcAddress" ) and pe.exports ( "MemoryLoadLibrary" ) and pe.exports ( "MemoryLoadLibraryEx" ) and pe.exports ( "MemoryLoadResource" ) and pe.exports ( "MemoryLoadString" ) and pe.exports ( "MemoryLoadStringEx" ) and pe.exports ( "MemorySizeofResource" ) and pe.exports ( "callback" ) and pe.exports ( "crosscall2" ) and pe.exports ( "crosscall_386" )
}

rule APT_HackTool_MSIL_SHARPNFS_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpnfs' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "b9d1b4e8-644a-5611-85e8-a124f915b443"

	strings:
		$typelibguid0 = {((39 66 36 37 65 62 65 33 2d 66 63 39 62 2d 34 30 66 32 2d 38 61 31 38 2d 35 39 34 30 63 66 65 64 34 34 63 66) | (39 00 66 00 36 00 37 00 65 00 62 00 65 00 33 00 2d 00 66 00 63 00 39 00 62 00 2d 00 34 00 30 00 66 00 32 00 2d 00 38 00 61 00 31 00 38 00 2d 00 35 00 39 00 34 00 30 00 63 00 66 00 65 00 64 00 34 00 34 00 63 00 66 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule CredTheft_MSIL_CredSnatcher_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'CredSnatcher' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "0d8f7495-4748-577d-8ef2-ccc4829fc165"

	strings:
		$typelibguid0 = {((33 37 30 62 34 64 32 31 2d 30 39 64 30 2d 34 33 33 66 2d 62 37 65 34 2d 34 65 62 64 64 37 39 39 34 38 65 63) | (33 00 37 00 30 00 62 00 34 00 64 00 32 00 31 00 2d 00 30 00 39 00 64 00 30 00 2d 00 34 00 33 00 33 00 66 00 2d 00 62 00 37 00 65 00 34 00 2d 00 34 00 65 00 62 00 64 00 64 00 37 00 39 00 39 00 34 00 38 00 65 00 63 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HackTool_MSIL_SEATBELT_2 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public SeatBelt project."
		md5 = "9f401176a9dd18fa2b5b90b4a2aa1356"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "225b42fe-c73a-59c0-a1f4-1d6dff6e76e1"
		score = 60

	strings:
		$typelibguid1 = {((41 45 43 33 32 31 35 35 2d 44 35 38 39 2d 34 31 35 30 2d 38 46 45 37 2d 32 39 30 30 44 46 34 35 35 34 43 38) | (41 00 45 00 43 00 33 00 32 00 31 00 35 00 35 00 2d 00 44 00 35 00 38 00 39 00 2d 00 34 00 31 00 35 00 30 00 2d 00 38 00 46 00 45 00 37 00 2d 00 32 00 39 00 30 00 30 00 44 00 46 00 34 00 35 00 35 00 34 00 43 00 38 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and $typelibguid1
}

rule APT_Loader_Win32_DShell_1 : hardened
{
	meta:
		date = "2020-11-27"
		modified = "2020-11-27"
		md5 = "12c3566761495b8353f67298f15b882c"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "dad763bd-0e4a-542a-9920-ece11d23ce24"

	strings:
		$sb1 = { 6A 40 68 00 30 00 00 [4-32] E8 [4-8] 50 [0-16] E8 [4-150] 6A FF [1-32] 6A 00 6A 00 5? 6A 00 6A 00 [0-32] E8 [4] 50 }
		$sb2 = { FF 7? 0C B? [4-16] FF 7? 08 5? [0-12] E8 [4] 84 C0 74 05 B? 01 00 00 00 [0-16] 80 F2 01 0F 84 }
		$ss1 = {00 43 72 65 61 74 65 54 68 72 65 61 64 00}
		$ss2 = {62 61 73 65 36 34 2e 64}
		$ss3 = {63 6f 72 65 2e 73 79 73 2e 77 69 6e 64 6f 77 73}

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x010B ) and all of them
}

rule APT_Loader_Win32_PGF_1 : hardened
{
	meta:
		date = "2020-11-25"
		modified = "2020-11-25"
		description = "base dlls: /lib/payload/techniques/unmanaged_exports/"
		md5 = "383161e4deaf7eb2ebeda2c5e9c3204c"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "1af4f2ce-c540-5836-a749-43a0b08609b1"

	strings:
		$sb1 = { 6A ?? FF 15 [4-32] 8A ?? 04 [0-32] 8B ?? 89 ?? 8B [2] 89 [2] 8B [2] 89 ?? 08 8B [2] 89 [2] 8B [2] 89 [2-64] 8B [5] 83 ?? 01 89 [5] 83 [5-32] 0F B6 [1-2] 0F B6 [1-2] 33 [1-16] 88 ?? EB }
		$sb2 = { 6A 40 [0-32] 68 00 30 00 00 [0-32] 6A 00 [0-16] FF 15 [4-32] 89 45 [4-64] E8 [4-32] 83 ?? 01 [4-80] 0F B6 [1-64] 33 [1-32] 88 [2-64] FF ( D? | 55 ) }
		$sb3 = { 8B ?? 08 03 ?? 3C [2-32] 0F B? ?? 14 [0-32] 8D [2] 18 [2-64] 0F B? ?? 06 [3-64] 6B ?? 28 }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x010B ) and all of them
}

rule APT_HackTool_MSIL_SHARPDACL_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpdacl' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "13f4e3ea-1e36-5fad-9197-66511d6f026a"

	strings:
		$typelibguid0 = {((62 33 63 31 37 66 62 35 2d 35 64 35 61 2d 34 62 31 34 2d 61 66 33 63 2d 38 37 61 39 61 61 39 34 31 34 35 37) | (62 00 33 00 63 00 31 00 37 00 66 00 62 00 35 00 2d 00 35 00 64 00 35 00 61 00 2d 00 34 00 62 00 31 00 34 00 2d 00 61 00 66 00 33 00 63 00 2d 00 38 00 37 00 61 00 39 00 61 00 61 00 39 00 34 00 31 00 34 00 35 00 37 00))}

	condition:
		filesize < 10MB and ( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule APT_HackTool_MSIL_SHARPZIPLIBZIPPER_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpziplibzipper' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "392a52be-29ae-58e1-b517-1ab34a1e1fb8"

	strings:
		$typelibguid0 = {((34 38 35 62 61 33 35 30 2d 35 39 63 34 2d 34 39 33 32 2d 61 34 63 31 2d 63 39 36 66 66 65 63 35 31 31 65 66) | (34 00 38 00 35 00 62 00 61 00 33 00 35 00 30 00 2d 00 35 00 39 00 63 00 34 00 2d 00 34 00 39 00 33 00 32 00 2d 00 61 00 34 00 63 00 31 00 2d 00 63 00 39 00 36 00 66 00 66 00 65 00 63 00 35 00 31 00 31 00 65 00 66 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule APT_Downloader_Win64_REDFLARE_1 : hardened
{
	meta:
		date = "2020-11-27"
		modified = "2020-11-27"
		md5 = "9529c4c9773392893a8a0ab8ce8f8ce1"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "15a5e22b-84b0-5b36-8772-1d496ac447b2"

	strings:
		$const = {43 6f 6f 6b 69 65 3a 20 53 49 44 31 3d 25 73}
		$http_req = { 00 00 08 80 81 3D [4] BB 01 00 00 75 [1-10] 00 00 80 00 [1-4] 00 10 00 00 [1-4] 00 20 00 00 89 [6-20] 00 00 00 00 [6-20] 00 00 00 00 [2-10] 00 00 00 00 45 33 C9 [4-20] 48 8D 15 [4] 48 8B 0D [4] FF 15 [4-50] B9 14 00 00 00 E8 }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) and all of them
}

rule APT_Loader_Win64_MATRYOSHKA_1 : hardened
{
	meta:
		date = "2020-12-02"
		modified = "2020-12-02"
		description = "matryoshka_process_hollow.rs"
		md5 = "44887551a47ae272d7873a354d24042d"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "69919a80-8ed1-5b8c-911a-ceb75570f11f"

	strings:
		$sb1 = { 48 8B 45 ?? 48 89 85 [0-64] C7 45 ?? 00 00 00 00 31 ?? E8 [4-64] BA 00 10 00 00 [0-32] 41 B8 04 00 00 00 E8 [4] 83 F8 01 [2-32] BA [4] E8 }
		$sb2 = { E8 [4] 83 F8 01 [2-64] 41 B9 00 10 00 00 [0-32] E8 [4] 83 F8 01 [2-32] 3D 4D 5A 00 00 [0-32] 48 63 ?? 3C [0-32] 50 45 00 00 [4-64] 0F B7 [2] 18 81 ?? 0B 01 00 00 [2-32] 81 ?? 0B 02 00 00 [2-32] 8B [2] 28 }
		$sb3 = { 66 C7 45 ?? 48 B8 48 C7 45 ?? 00 00 00 00 66 C7 45 ?? FF E0 [0-64] 41 B9 40 00 00 00 [0-32] E8 [4] 83 F8 01 }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) and all of them
}

rule HackTool_MSIL_WMIspy_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'WMIspy' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "ac394751-da40-564b-8e24-8f353326b46a"

	strings:
		$typelibguid0 = {((35 65 65 32 62 63 61 33 2d 30 31 61 64 2d 34 38 39 62 2d 61 62 31 62 2d 62 64 61 37 39 36 32 65 30 36 62 62) | (35 00 65 00 65 00 32 00 62 00 63 00 61 00 33 00 2d 00 30 00 31 00 61 00 64 00 2d 00 34 00 38 00 39 00 62 00 2d 00 61 00 62 00 31 00 62 00 2d 00 62 00 64 00 61 00 37 00 39 00 36 00 32 00 65 00 30 00 36 00 62 00 62 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule APT_Trojan_Win_REDFLARE_3 : hardened
{
	meta:
		date = "2020-12-01"
		modified = "2020-12-01"
		md5 = "9ccda4d7511009d5572ef2f8597fba4e,ece07daca53dd0a7c23dacabf50f56f1"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "2f6785c4-f4d0-52ff-8c46-da953e2ca92a"

	strings:
		$calc_image_size = { 28 00 00 00 [2-30] 83 E2 1F [4-20] C1 F8 05 [0-8] 0F AF C? [0-30] C1 E0 02 }
		$str1 = {43 72 65 61 74 65 43 6f 6d 70 61 74 69 62 6c 65 42 69 74 6d 61 70}
		$str2 = {42 69 74 42 6c 74}
		$str3 = {72 75 6e 43 6f 6d 6d 61 6e 64}

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule APT_Loader_Win_PGF_1 : hardened
{
	meta:
		description = "PDB string used in some PGF DLL samples"
		md5 = "013c7708f1343d684e3571453261b586"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "fcbefa45-8dcd-57a3-a2ac-f4613152716f"

	strings:
		$pdb1 = /RSDS[\x00-\xFF]{20}c:\\source\\dllconfig-master\\dllsource[\x00-\xFF]{0,500}\.pdb\x00/ nocase
		$pdb2 = /RSDS[\x00-\xFF]{20}C:\\Users\\Developer\\Source[\x00-\xFF]{0,500}\Release\\DllSource\.pdb\x00/ nocase
		$pdb3 = /RSDS[\x00-\xFF]{20}q:\\objchk_win7_amd64\\amd64\\init\.pdb\x00/ nocase

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and filesize < 15MB and any of them
}

rule APT_HackTool_MSIL_SHARPDNS_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpdns' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "db6b45be-f42f-5d0f-b50a-32e7a2cbfce6"

	strings:
		$typelibguid0 = {((64 38 38 38 63 65 63 38 2d 37 35 36 32 2d 34 30 65 39 2d 39 63 37 36 2d 32 62 62 39 65 34 33 62 62 36 33 34) | (64 00 38 00 38 00 38 00 63 00 65 00 63 00 38 00 2d 00 37 00 35 00 36 00 32 00 2d 00 34 00 30 00 65 00 39 00 2d 00 39 00 63 00 37 00 36 00 2d 00 32 00 62 00 62 00 39 00 65 00 34 00 33 00 62 00 62 00 36 00 33 00 34 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule Loader_MSIL_TrimBishop_1 : hardened
{
	meta:
		description = "This rule looks for .NET PE files that have the string 'msg' more than 60 times as well as numerous function names unique to or used by the TrimBishop tool. All strings found in RuralBishop are reversed in TrimBishop and stored in a variable with the format 'msg##'. With the exception of 'msg', 'DTrim', and 'ReverseString' the other strings referenced in this rule may be shared with RuralBishop."
		md5 = "09bdbad8358b04994e2c04bb26a160ef"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "4d58f0a2-bf16-584c-8e92-c8ef54427767"

	strings:
		$msg = {((6d 73 67) | (6d 00 73 00 67 00))}
		$msil = {((5f 43 6f 72 45 78 65 4d 61 69 6e) | (5f 00 43 00 6f 00 72 00 45 00 78 00 65 00 4d 00 61 00 69 00 6e 00))}
		$str1 = {((52 75 72 61 6c 42 69 73 68 6f 70) | (52 00 75 00 72 00 61 00 6c 00 42 00 69 00 73 00 68 00 6f 00 70 00))}
		$str2 = {((4b 6e 69 67 68 74 4b 69 6e 67 73 69 64 65) | (4b 00 6e 00 69 00 67 00 68 00 74 00 4b 00 69 00 6e 00 67 00 73 00 69 00 64 00 65 00))}
		$str3 = {((52 65 61 64 53 68 65 6c 6c 63 6f 64 65) | (52 00 65 00 61 00 64 00 53 00 68 00 65 00 6c 00 6c 00 63 00 6f 00 64 00 65 00))}
		$str4 = {((52 65 76 65 72 73 65 53 74 72 69 6e 67) | (52 00 65 00 76 00 65 00 72 00 73 00 65 00 53 00 74 00 72 00 69 00 6e 00 67 00))}
		$str5 = {((44 54 72 69 6d) | (44 00 54 00 72 00 69 00 6d 00))}
		$str6 = {((51 75 65 65 6e 73 47 61 6d 62 69 74) | (51 00 75 00 65 00 65 00 6e 00 73 00 47 00 61 00 6d 00 62 00 69 00 74 00))}
		$str7 = {((4d 65 73 73 61 67 65 73) | (4d 00 65 00 73 00 73 00 61 00 67 00 65 00 73 00))}
		$str8 = {((4e 74 51 75 65 75 65 41 70 63 54 68 72 65 61 64) | (4e 00 74 00 51 00 75 00 65 00 75 00 65 00 41 00 70 00 63 00 54 00 68 00 72 00 65 00 61 00 64 00))}
		$str9 = {((4e 74 41 6c 65 72 74 52 65 73 75 6d 65 54 68 72 65 61 64) | (4e 00 74 00 41 00 6c 00 65 00 72 00 74 00 52 00 65 00 73 00 75 00 6d 00 65 00 54 00 68 00 72 00 65 00 61 00 64 00))}
		$str10 = {((4e 74 51 75 65 72 79 49 6e 66 6f 72 6d 61 74 69 6f 6e 54 68 72 65 61 64) | (4e 00 74 00 51 00 75 00 65 00 72 00 79 00 49 00 6e 00 66 00 6f 00 72 00 6d 00 61 00 74 00 69 00 6f 00 6e 00 54 00 68 00 72 00 65 00 61 00 64 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and $msil and #msg > 60 and all of ( $str* )
}

rule Loader_Win_Generic_17 : hardened
{
	meta:
		date = "2020-11-25"
		modified = "2020-11-25"
		md5 = "562ecbba043552d59a0f23f61cea0983"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "4e5bf741-c1e3-54af-9580-02925ba6fc6a"

	strings:
		$s0 = { 89 [1-16] FF 15 [4-16] 89 [1-24] E8 [4-16] 89 C6 [4-24] 8D [1-8] 89 [1-4] 89 [1-4] E8 [4-16] 89 [1-8] E8 [4-24] 01 00 00 00 [1-8] 89 [1-8] E8 [4-64] 8A [1-8] 88 }
		$s1 = { 83 EC [1-16] 04 00 00 00 [1-24] 00 30 00 00 [1-24] FF 15 [4-16] EB [16-64] 20 00 00 00 [0-8] FF 15 [4-32] C7 44 24 ?? 00 00 00 00 [0-8] C7 44 24 ?? 00 00 00 00 [0-16] FF 15 }
		$si1 = {66 72 65 61 64}
		$si2 = {66 77 72 69 74 65}

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule APT_Loader_Win64_PGF_3 : hardened
{
	meta:
		description = "PGF payload, generated rule based on symfunc/8a2f2236fdfaa3583ab89076025c6269. Identifies dllmain_hook x64 payloads."
		md5 = "3bb34ebd93b8ab5799f4843e8cc829fa"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "340ea6d4-7111-520c-9bd4-0465a43ea235"

	strings:
		$cond1 = { 55 53 48 89 E5 48 81 EC 28 07 00 00 48 8B 05 80 8B 06 00 FF D0 48 89 C1 48 8D 85 98 FD FF FF 41 B8 04 01 00 00 48 89 C2 E8 5A B4 00 00 85 C0 0F 94 C0 84 C0 0F 85 16 03 00 00 48 8D 45 AF 48 89 C1 E8 E9 FE 00 00 48 8D 4D AF 48 8D 95 98 FD FF FF 48 8D 85 78 FD FF FF 49 89 C8 48 89 C1 E8 AC 96 01 00 48 8D 45 AF 48 89 C1 E8 F0 FE 00 00 48 8B 05 25 8B 06 00 FF D0 89 C2 B9 08 00 00 00 E8 6B B4 00 00 48 89 45 D0 48 83 7D D0 00 75 0A BB 00 00 00 00 E9 6C 02 00 00 48 C7 45 F0 00 00 00 00 C7 45 EC 00 00 00 00 C7 85 38 F9 FF FF 38 04 00 00 48 8D 95 38 F9 FF FF 48 8B 45 D0 48 89 C1 E8 AA B3 00 00 89 45 E8 83 7D E8 00 74 57 48 8D 85 38 F9 FF FF 48 8D 50 30 48 8D 85 78 FD FF FF 41 B8 00 00 00 00 48 89 C1 E8 61 F3 00 00 48 83 F8 FF 0F 95 C0 84 C0 74 14 48 8B 85 50 F9 FF FF 48 89 45 F0 8B 85 58 F9 FF FF 89 45 EC 48 8D 95 38 F9 FF FF 48 8B 45 D0 48 89 C1 E8 4F B3 00 00 89 45 E8 EB A3 48 8B 45 D0 48 89 C1 48 8B 05 20 8A 06 00 FF D0 48 83 7D F0 00 74 06 83 7D EC 00 75 0A BB 00 00 00 00 E9 B9 01 00 00 48 8D 0D 0E C8 05 00 48 8B 05 69 8A 06 00 FF D0 48 8D 15 0A C8 05 00 48 89 C1 48 8B 05 5E 8A 06 00 FF D0 48 89 45 C8 48 89 E8 48 89 45 E0 48 8D 95 28 F9 FF FF 48 8D 85 30 F9 FF FF 48 89 C1 48 8B 05 19 8A 06 00 FF D0 C7 45 DC 00 00 00 00 48 8B 55 E0 48 8B 85 28 F9 FF FF 48 39 C2 0F 83 0D 01 00 00 48 8B 45 E0 48 8B 00 48 3D FF 0F 00 00 0F 86 EC 00 00 00 48 8B 45 E0 48 8B 00 48 39 45 C8 73 1E 48 8B 45 E0 48 8B 00 48 8B 55 C8 48 81 C2 00 10 00 00 48 39 D0 73 07 C7 45 DC 01 00 00 00 83 7D DC 00 0F 84 BB 00 00 00 48 8B 45 E0 48 8B 00 48 39 45 F0 0F 83 AA 00 00 00 48 8B 45 E0 48 8B 00 8B 4D EC 48 8B 55 F0 48 01 CA 48 39 D0 0F 83 90 00 00 00 48 C7 85 F8 F8 FF FF 00 00 00 00 48 C7 85 00 F9 FF FF 00 00 00 00 48 C7 85 08 F9 FF FF 00 00 00 00 48 C7 85 10 F9 FF FF 00 00 00 00 48 C7 85 18 F9 FF FF 00 00 00 00 48 C7 85 20 F9 FF FF 00 00 00 00 48 8B 45 E0 48 8B 00 48 8D 95 F8 F8 FF FF 41 B8 30 00 00 00 48 89 C1 48 8B 05 01 8A 06 00 FF D0 8B 85 1C F9 FF FF 83 E0 20 85 C0 74 20 48 8B 45 E0 48 8B 00 48 8D 15 E0 F9 FF FF 48 89 C1 E8 D5 FC FF FF BB 00 00 00 00 EB 57 90 EB 01 90 48 83 45 E0 08 E9 DF FE FF FF 48 8B 45 F0 48 89 45 C0 48 8B 45 C0 8B 40 3C 48 63 D0 48 8B 45 F0 48 01 D0 48 89 45 B8 48 8B 45 B8 8B 40 28 89 C2 48 8B 45 F0 48 01 D0 48 89 45 B0 48 8B 45 B0 48 8D 15 87 F9 FF FF 48 89 C1 E8 7C FC FF FF BB 01 00 00 00 48 8D 85 78 FD FF FF 48 89 C1 E8 CB 9C 01 00 83 FB 01 EB 38 48 89 C3 48 8D 45 AF 48 89 C1 E8 37 FC 00 00 48 89 D8 48 89 C1 E8 4C AA 00 00 48 89 C3 48 8D 85 78 FD FF FF 48 89 C1 E8 9A 9C 01 00 48 89 D8 48 89 C1 E8 2F AA 00 00 90 48 81 C4 28 07 00 00 5B 5D C3 }
		$cond2 = { 55 53 48 89 E5 48 81 EC 28 07 00 00 48 8B 05 ?? ?? ?? ?? FF D0 48 89 C1 48 8D 85 ?? ?? ?? ?? 41 B8 04 01 00 00 48 89 C2 E8 ?? ?? ?? ?? 85 C0 0F 94 C0 84 C0 0F 85 ?? ?? ?? ?? 48 8D 45 ?? 48 89 C1 E8 ?? ?? ?? ?? 48 8D 4D ?? 48 8D 95 ?? ?? ?? ?? 48 8D 85 ?? ?? ?? ?? 49 89 C8 48 89 C1 E8 ?? ?? ?? ?? 48 8D 45 ?? 48 89 C1 E8 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? FF D0 89 C2 B9 08 00 00 00 E8 ?? ?? ?? ?? 48 89 45 ?? 48 83 7D ?? 00 75 ?? BB 00 00 00 00 E9 ?? ?? ?? ?? 48 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 38 04 00 00 48 8D 95 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C1 E8 ?? ?? ?? ?? 89 45 ?? 83 7D ?? 00 74 ?? 48 8D 85 ?? ?? ?? ?? 48 8D 50 ?? 48 8D 85 ?? ?? ?? ?? 41 B8 00 00 00 00 48 89 C1 E8 ?? ?? ?? ?? 48 83 F8 FF 0F 95 C0 84 C0 74 ?? 48 8B 85 ?? ?? ?? ?? 48 89 45 ?? 8B 85 ?? ?? ?? ?? 89 45 ?? 48 8D 95 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C1 E8 ?? ?? ?? ?? 89 45 ?? EB ?? 48 8B 45 ?? 48 89 C1 48 8B 05 ?? ?? ?? ?? FF D0 48 83 7D ?? 00 74 ?? 83 7D ?? 00 75 ?? BB 00 00 00 00 E9 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? FF D0 48 8D 15 ?? ?? ?? ?? 48 89 C1 48 8B 05 ?? ?? ?? ?? FF D0 48 89 45 ?? 48 89 E8 48 89 45 ?? 48 8D 95 ?? ?? ?? ?? 48 8D 85 ?? ?? ?? ?? 48 89 C1 48 8B 05 ?? ?? ?? ?? FF D0 C7 45 ?? 00 00 00 00 48 8B 55 ?? 48 8B 85 ?? ?? ?? ?? 48 39 C2 0F 83 ?? ?? ?? ?? 48 8B 45 ?? 48 8B 00 48 3D FF 0F 00 00 0F 86 ?? ?? ?? ?? 48 8B 45 ?? 48 8B 00 48 39 45 ?? 73 ?? 48 8B 45 ?? 48 8B 00 48 8B 55 ?? 48 81 C2 00 10 00 00 48 39 D0 73 ?? C7 45 ?? 01 00 00 00 83 7D ?? 00 0F 84 ?? ?? ?? ?? 48 8B 45 ?? 48 8B 00 48 39 45 ?? 0F 83 ?? ?? ?? ?? 48 8B 45 ?? 48 8B 00 8B 4D ?? 48 8B 55 ?? 48 01 CA 48 39 D0 0F 83 ?? ?? ?? ?? 48 C7 85 ?? ?? ?? ?? 00 00 00 00 48 C7 85 ?? ?? ?? ?? 00 00 00 00 48 C7 85 ?? ?? ?? ?? 00 00 00 00 48 C7 85 ?? ?? ?? ?? 00 00 00 00 48 C7 85 ?? ?? ?? ?? 00 00 00 00 48 C7 85 ?? ?? ?? ?? 00 00 00 00 48 8B 45 ?? 48 8B 00 48 8D 95 ?? ?? ?? ?? 41 B8 30 00 00 00 48 89 C1 48 8B 05 ?? ?? ?? ?? FF D0 8B 85 ?? ?? ?? ?? 83 E0 20 85 C0 74 ?? 48 8B 45 ?? 48 8B 00 48 8D 15 ?? ?? ?? ?? 48 89 C1 E8 ?? ?? ?? ?? BB 00 00 00 00 EB ?? 90 EB ?? 90 48 83 45 ?? 08 E9 ?? ?? ?? ?? 48 8B 45 ?? 48 89 45 ?? 48 8B 45 ?? 8B 40 ?? 48 63 D0 48 8B 45 ?? 48 01 D0 48 89 45 ?? 48 8B 45 ?? 8B 40 ?? 89 C2 48 8B 45 ?? 48 01 D0 48 89 45 ?? 48 8B 45 ?? 48 8D 15 ?? ?? ?? ?? 48 89 C1 E8 ?? ?? ?? ?? BB 01 00 00 00 48 8D 85 ?? ?? ?? ?? 48 89 C1 E8 ?? ?? ?? ?? 83 FB 01 EB ?? 48 89 C3 48 8D 45 ?? 48 89 C1 E8 ?? ?? ?? ?? 48 89 D8 48 89 C1 E8 ?? ?? ?? ?? 48 89 C3 48 8D 85 ?? ?? ?? ?? 48 89 C1 E8 ?? ?? ?? ?? 48 89 D8 48 89 C1 E8 ?? ?? ?? ?? 90 48 81 C4 28 07 00 00 5B 5D C3 }
		$cond3 = { 55 53 48 89 E5 48 81 EC 28 07 00 00 48 8B 05 C1 7C 06 00 FF D0 48 89 C1 48 8D 85 98 FD FF FF 41 B8 04 01 00 00 48 89 C2 E8 33 B4 00 00 85 C0 0F 94 C0 84 C0 0F 85 16 03 00 00 48 8D 45 AF 48 89 C1 E8 B2 FE 00 00 48 8D 4D AF 48 8D 95 98 FD FF FF 48 8D 85 78 FD FF FF 49 89 C8 48 89 C1 E8 75 96 01 00 48 8D 45 AF 48 89 C1 E8 B9 FE 00 00 48 8B 05 66 7C 06 00 FF D0 89 C2 B9 08 00 00 00 E8 3C B4 00 00 48 89 45 D0 48 83 7D D0 00 75 0A BB 00 00 00 00 E9 6C 02 00 00 48 C7 45 F0 00 00 00 00 C7 45 EC 00 00 00 00 C7 85 38 F9 FF FF 38 04 00 00 48 8D 95 38 F9 FF FF 48 8B 45 D0 48 89 C1 E8 83 B3 00 00 89 45 E8 83 7D E8 00 74 57 48 8D 85 38 F9 FF FF 48 8D 50 30 48 8D 85 78 FD FF FF 41 B8 00 00 00 00 48 89 C1 E8 2A F3 00 00 48 83 F8 FF 0F 95 C0 84 C0 74 14 48 8B 85 50 F9 FF FF 48 89 45 F0 8B 85 58 F9 FF FF 89 45 EC 48 8D 95 38 F9 FF FF 48 8B 45 D0 48 89 C1 E8 28 B3 00 00 89 45 E8 EB A3 48 8B 45 D0 48 89 C1 48 8B 05 69 7B 06 00 FF D0 48 83 7D F0 00 74 06 83 7D EC 00 75 0A BB 00 00 00 00 E9 B9 01 00 00 48 8D 0D 11 B9 05 00 48 8B 05 A2 7B 06 00 FF D0 48 8D 15 0D B9 05 00 48 89 C1 48 8B 05 97 7B 06 00 FF D0 48 89 45 C8 48 89 E8 48 89 45 E0 48 8D 95 28 F9 FF FF 48 8D 85 30 F9 FF FF 48 89 C1 48 8B 05 5A 7B 06 00 FF D0 C7 45 DC 00 00 00 00 48 8B 55 E0 48 8B 85 28 F9 FF FF 48 39 C2 0F 83 0D 01 00 00 48 8B 45 E0 48 8B 00 48 3D FF 0F 00 00 0F 86 EC 00 00 00 48 8B 45 E0 48 8B 00 48 39 45 C8 73 1E 48 8B 45 E0 48 8B 00 48 8B 55 C8 48 81 C2 00 10 00 00 48 39 D0 73 07 C7 45 DC 01 00 00 00 83 7D DC 00 0F 84 BB 00 00 00 48 8B 45 E0 48 8B 00 48 39 45 F0 0F 83 AA 00 00 00 48 8B 45 E0 48 8B 00 8B 4D EC 48 8B 55 F0 48 01 CA 48 39 D0 0F 83 90 00 00 00 48 C7 85 F8 F8 FF FF 00 00 00 00 48 C7 85 00 F9 FF FF 00 00 00 00 48 C7 85 08 F9 FF FF 00 00 00 00 48 C7 85 10 F9 FF FF 00 00 00 00 48 C7 85 18 F9 FF FF 00 00 00 00 48 C7 85 20 F9 FF FF 00 00 00 00 48 8B 45 E0 48 8B 00 48 8D 95 F8 F8 FF FF 41 B8 30 00 00 00 48 89 C1 48 8B 05 22 7B 06 00 FF D0 8B 85 1C F9 FF FF 83 E0 20 85 C0 74 20 48 8B 45 E0 48 8B 00 48 8D 15 59 FB FF FF 48 89 C1 E8 D5 FC FF FF BB 00 00 00 00 EB 57 90 EB 01 90 48 83 45 E0 08 E9 DF FE FF FF 48 8B 45 F0 48 89 45 C0 48 8B 45 C0 8B 40 3C 48 63 D0 48 8B 45 F0 48 01 D0 48 89 45 B8 48 8B 45 B8 8B 40 28 89 C2 48 8B 45 F0 48 01 D0 48 89 45 B0 48 8B 45 B0 48 8D 15 00 FB FF FF 48 89 C1 E8 7C FC FF FF BB 01 00 00 00 48 8D 85 78 FD FF FF 48 89 C1 E8 94 9C 01 00 83 FB 01 EB 38 48 89 C3 48 8D 45 AF 48 89 C1 E8 00 FC 00 00 48 89 D8 48 89 C1 E8 45 AA 00 00 48 89 C3 48 8D 85 78 FD FF FF 48 89 C1 E8 63 9C 01 00 48 89 D8 48 89 C1 E8 28 AA 00 00 90 48 81 C4 28 07 00 00 5B 5D C3 }
		$cond4 = { 55 53 48 89 E5 48 81 EC 28 07 00 00 48 8B 05 D3 8B 06 00 FF D0 48 89 C1 48 8D 85 98 FD FF FF 41 B8 04 01 00 00 48 89 C2 E8 65 B4 00 00 85 C0 0F 94 C0 84 C0 0F 85 16 03 00 00 48 8D 45 AF 48 89 C1 E8 EC FE 00 00 48 8D 4D AF 48 8D 95 98 FD FF FF 48 8D 85 78 FD FF FF 49 89 C8 48 89 C1 E8 AF 96 01 00 48 8D 45 AF 48 89 C1 E8 F3 FE 00 00 48 8B 05 78 8B 06 00 FF D0 89 C2 B9 08 00 00 00 E8 6E B4 00 00 48 89 45 D0 48 83 7D D0 00 75 0A BB 00 00 00 00 E9 6C 02 00 00 48 C7 45 F0 00 00 00 00 C7 45 EC 00 00 00 00 C7 85 38 F9 FF FF 38 04 00 00 48 8D 95 38 F9 FF FF 48 8B 45 D0 48 89 C1 E8 B5 B3 00 00 89 45 E8 83 7D E8 00 74 57 48 8D 85 38 F9 FF FF 48 8D 50 30 48 8D 85 78 FD FF FF 41 B8 00 00 00 00 48 89 C1 E8 64 F3 00 00 48 83 F8 FF 0F 95 C0 84 C0 74 14 48 8B 85 50 F9 FF FF 48 89 45 F0 8B 85 58 F9 FF FF 89 45 EC 48 8D 95 38 F9 FF FF 48 8B 45 D0 48 89 C1 E8 5A B3 00 00 89 45 E8 EB A3 48 8B 45 D0 48 89 C1 48 8B 05 73 8A 06 00 FF D0 48 83 7D F0 00 74 06 83 7D EC 00 75 0A BB 00 00 00 00 E9 B9 01 00 00 48 8D 0D 45 C8 05 00 48 8B 05 B4 8A 06 00 FF D0 48 8D 15 41 C8 05 00 48 89 C1 48 8B 05 A9 8A 06 00 FF D0 48 89 45 C8 48 89 E8 48 89 45 E0 48 8D 95 28 F9 FF FF 48 8D 85 30 F9 FF FF 48 89 C1 48 8B 05 6C 8A 06 00 FF D0 C7 45 DC 00 00 00 00 48 8B 55 E0 48 8B 85 28 F9 FF FF 48 39 C2 0F 83 0D 01 00 00 48 8B 45 E0 48 8B 00 48 3D FF 0F 00 00 0F 86 EC 00 00 00 48 8B 45 E0 48 8B 00 48 39 45 C8 73 1E 48 8B 45 E0 48 8B 00 48 8B 55 C8 48 81 C2 00 10 00 00 48 39 D0 73 07 C7 45 DC 01 00 00 00 83 7D DC 00 0F 84 BB 00 00 00 48 8B 45 E0 48 8B 00 48 39 45 F0 0F 83 AA 00 00 00 48 8B 45 E0 48 8B 00 8B 4D EC 48 8B 55 F0 48 01 CA 48 39 D0 0F 83 90 00 00 00 48 C7 85 F8 F8 FF FF 00 00 00 00 48 C7 85 00 F9 FF FF 00 00 00 00 48 C7 85 08 F9 FF FF 00 00 00 00 48 C7 85 10 F9 FF FF 00 00 00 00 48 C7 85 18 F9 FF FF 00 00 00 00 48 C7 85 20 F9 FF FF 00 00 00 00 48 8B 45 E0 48 8B 00 48 8D 95 F8 F8 FF FF 41 B8 30 00 00 00 48 89 C1 48 8B 05 54 8A 06 00 FF D0 8B 85 1C F9 FF FF 83 E0 20 85 C0 74 20 48 8B 45 E0 48 8B 00 48 8D 15 33 FA FF FF 48 89 C1 E8 D5 FC FF FF BB 00 00 00 00 EB 57 90 EB 01 90 48 83 45 E0 08 E9 DF FE FF FF 48 8B 45 F0 48 89 45 C0 48 8B 45 C0 8B 40 3C 48 63 D0 48 8B 45 F0 48 01 D0 48 89 45 B8 48 8B 45 B8 8B 40 28 89 C2 48 8B 45 F0 48 01 D0 48 89 45 B0 48 8B 45 B0 48 8D 15 DA F9 FF FF 48 89 C1 E8 7C FC FF FF BB 01 00 00 00 48 8D 85 78 FD FF FF 48 89 C1 E8 CE 9C 01 00 83 FB 01 EB 38 48 89 C3 48 8D 45 AF 48 89 C1 E8 3A FC 00 00 48 89 D8 48 89 C1 E8 4F AA 00 00 48 89 C3 48 8D 85 78 FD FF FF 48 89 C1 E8 9D 9C 01 00 48 89 D8 48 89 C1 E8 32 AA 00 00 90 48 81 C4 28 07 00 00 5B 5D C3 }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) and any of them
}

rule HackTool_PY_ImpacketObfuscation_1 : hardened limited
{
	meta:
		date = "2020-12-01"
		modified = "2020-12-01"
		description = "smbexec"
		md5 = "0b1e512afe24c31531d6db6b47bac8ee"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "992d1132-3136-5e1b-a1ef-dcdf36ebf0f5"

	strings:
		$s1 = {63 6c 61 73 73 20 43 4d 44 45 58 45 43}
		$s2 = {63 6c 61 73 73 20 52 65 6d 6f 74 65 53 68 65 6c 6c}
		$s3 = {73 65 6c 66 2e 73 65 72 76 69 63 65 73 5f 6e 61 6d 65 73}
		$s4 = {69 6d 70 6f 72 74 20 72 61 6e 64 6f 6d}
		$s6 = /self\.__shell[\x09\x20]{0,32}=[\x09\x20]{0,32}[\x22\x27]%CoMSpEC%[\x09\x20]{1,32}\/q[\x09\x20]{1,32}\/K [\x22\x27]/ nocase
		$s7 = /self\.__serviceName[\x09\x20]{0,32}=[\x09\x20]{0,32}self\.services_names\[random\.randint\([\x09\x20]{0,32}0[\x09\x20]{0,32},[\x09\x20]{0,32}len\(self\.services_names\)[\x09\x20]{0,32}-[\x09\x20]{0,32}1\)\]/

	condition:
		all of them
}

rule APT_HackTool_Win64_EXCAVATOR_2 : hardened
{
	meta:
		date = "2020-12-02"
		modified = "2020-12-02"
		md5 = "4fd62068e591cbd6f413e1c2b8f75442"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "4b7640e8-5621-5cc3-8ac9-84347f23f5eb"

	strings:
		$api1 = {50 73 73 43 61 70 74 75 72 65 53 6e 61 70 73 68 6f 74}
		$api2 = {4d 69 6e 69 44 75 6d 70 57 72 69 74 65 44 75 6d 70}
		$dump = { C7 [2-5] FD 03 00 AC 4C 8D 4D ?? 41 B8 1F 00 10 00 8B [2-5] 48 8B 4D ?? E8 [4] 89 [2-5] 83 [2-5] 00 74 ?? 48 8B 4D ?? FF 15 [4] 33 C0 E9 [4] 41 B8 10 00 00 00 33 D2 48 8D 8D [4] E8 [4] 48 8D 05 [4] 48 89 85 [4] 48 C7 85 [8] 48 C7 44 24 30 00 00 00 00 C7 44 24 28 80 00 00 00 C7 44 24 20 01 00 00 00 45 33 C9 45 33 C0 BA 00 00 00 10 48 8D 0D [4] FF 15 [4] 48 89 85 [4] 48 83 BD [4] FF 75 ?? 48 8B 4D ?? FF 15 [4] 33 C0 EB [0-17] 48 8D [5] 48 89 ?? 24 30 48 C7 44 24 28 00 00 00 00 48 C7 44 24 20 00 00 00 00 41 B9 02 00 00 00 4C 8B 85 [4] 8B [1-5] 48 8B 4D ?? E8 }
		$enable_dbg_pri = { 4C 8D 45 ?? 48 8D 15 [4] 33 C9 FF 15 [4] 85 C0 0F 84 [4] C7 45 ?? 01 00 00 00 B8 0C 00 00 00 48 6B C0 00 48 8B 4D ?? 48 89 4C 05 ?? B8 0C 00 00 00 48 6B C0 00 C7 44 05 ?? 02 00 00 00 FF 15 [4] 4C 8D 45 ?? BA 20 00 00 00 48 8B C8 FF 15 [4] 85 C0 74 ?? 48 C7 44 24 28 00 00 00 00 48 C7 44 24 20 00 00 00 00 45 33 C9 4C 8D 45 ?? 33 D2 48 8B 4D ?? FF 15 }

	condition:
		(( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) ) and all of them
}

rule APT_Loader_Raw32_REDFLARE_1 : hardened
{
	meta:
		date = "2020-11-27"
		modified = "2020-11-27"
		md5 = "4022baddfda3858a57c9cbb0d49f6f86"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "8f8ec27f-afac-5da5-b76f-b984e14e0066"

	strings:
		$load = { EB ?? 58 [0-4] 8B 10 8B 48 [1-3] 8B C8 83 C1 ?? 03 D1 83 E9 [1-3] 83 C1 [1-4] FF D? }

	condition:
		( uint16( 0 ) != 0x5A4D ) and all of them
}

rule APT_Loader_Win64_PGF_2 : hardened
{
	meta:
		date = "2020-11-25"
		modified = "2020-11-25"
		description = "base dlls: /lib/payload/techniques/dllmain/"
		md5 = "4326a7e863928ffbb5f6bdf63bb9126e"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "5253cb2a-28fd-57ab-be3d-f11cf2ea24cf"

	strings:
		$sb1 = { B9 [4] FF 15 [4-32] 8B ?? 1C [0-16] 0F B? ?? 04 [0-64] F3 0F 6F 00 [0-64] 66 0F EF C8 [0-64] F3 0F 7F 08 [0-64] 30 ?? 48 8D 40 01 48 83 ?? 01 7? }
		$sb2 = { 44 8B ?? 08 [0-32] 41 B8 00 30 00 00 [0-16] FF 15 [4-32] 48 8B C8 [0-16] E8 [4-64] 4D 8D 49 01 [0-32] C1 ?? 04 [0-64] 0F B? [2-16] 41 30 ?? FF 45 3? ?? 7? }
		$sb3 = { 63 ?? 3C [0-16] 03 [1-32] 0F B? ?? 14 [0-16] 8D ?? 18 [0-16] 03 [1-16] 66 ?? 3B ?? 06 7? [1-64] 48 8D 15 [4-32] FF 15 [4-16] 85 C0 [2-32] 41 0F B? ?? 06 }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) and all of them
}

rule APT_HackTool_MSIL_SHARPTEMPLATE_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharptemplate' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "0ca9a13c-e0a0-588b-be13-5954b17d95b1"

	strings:
		$typelibguid0 = {((65 39 65 34 35 32 64 34 2d 39 65 35 38 2d 34 34 66 66 2d 62 61 32 64 2d 30 31 62 31 35 38 64 64 61 39 62 62) | (65 00 39 00 65 00 34 00 35 00 32 00 64 00 34 00 2d 00 39 00 65 00 35 00 38 00 2d 00 34 00 34 00 66 00 66 00 2d 00 62 00 61 00 32 00 64 00 2d 00 30 00 31 00 62 00 31 00 35 00 38 00 64 00 64 00 61 00 39 00 62 00 62 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule APT_HackTool_MSIL_MODIFIEDSHARPVIEW_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'modifiedsharpview' project."
		md5 = "db0eaad52465d5a2b86fdd6a6aa869a5"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "e07d3d4b-fba3-5df7-85f4-927bb8cec2d1"

	strings:
		$typelibguid0 = {((32 32 61 31 35 36 65 61 2d 32 36 32 33 2d 34 35 63 37 2d 38 65 35 30 2d 65 38 36 34 64 39 66 63 34 34 64 33) | (32 00 32 00 61 00 31 00 35 00 36 00 65 00 61 00 2d 00 32 00 36 00 32 00 33 00 2d 00 34 00 35 00 63 00 37 00 2d 00 38 00 65 00 35 00 30 00 2d 00 65 00 38 00 36 00 34 00 64 00 39 00 66 00 63 00 34 00 34 00 64 00 33 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule APT_Loader_Win32_PGF_5 : hardened
{
	meta:
		description = "PGF payload, generated rule based on symfunc/a86b004b5005c0bcdbd48177b5bac7b8"
		md5 = "8c91a27bbdbe9fb0877daccd28bd7bb5"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "376875f3-00f2-58d0-ae22-7f52ea566da2"

	strings:
		$cond1 = { 8B FF 55 8B EC 81 EC 30 01 00 00 A1 00 30 00 10 33 C5 89 45 E0 56 C7 45 F8 00 00 00 00 C6 85 D8 FE FF FF 00 68 03 01 00 00 6A 00 8D 85 D9 FE FF FF 50 E8 F9 07 00 00 83 C4 0C C7 45 F4 00 00 00 00 C6 45 E7 00 C7 45 E8 00 00 00 00 C7 45 EC 00 00 00 00 C7 45 FC 00 00 00 00 C7 45 F0 00 00 00 00 6A 01 6A 00 8D 8D D8 FE FF FF 51 6A 00 68 9C 10 00 10 8B 15 10 30 00 10 52 E8 31 01 00 00 89 45 F8 6A 14 FF 15 5C 10 00 10 83 C4 04 89 45 E8 8B 45 F8 8A 48 04 88 4D E7 8B 55 F8 83 C2 0C 8B 45 E8 8B 0A 89 08 8B 4A 04 89 48 04 8B 4A 08 89 48 08 8B 4A 0C 89 48 0C 8B 52 10 89 50 10 C7 85 D4 FE FF FF 00 00 00 00 EB 0F 8B 85 D4 FE FF FF 83 C0 01 89 85 D4 FE FF FF 83 BD D4 FE FF FF 14 7D 1F 8B 4D E8 03 8D D4 FE FF FF 0F B6 11 0F B6 45 E7 33 D0 8B 4D E8 03 8D D4 FE FF FF 88 11 EB C9 8B 55 F8 8B 42 08 89 45 FC 6A 40 68 00 30 00 00 8B 4D FC 51 6A 00 FF 15 00 10 00 10 89 45 EC 8B 55 FC 52 8B 45 F8 83 C0 20 50 8B 4D EC 51 E8 F0 06 00 00 83 C4 0C C7 85 D0 FE FF FF 00 00 00 00 EB 0F 8B 95 D0 FE FF FF 83 C2 01 89 95 D0 FE FF FF 8B 85 D0 FE FF FF 3B 45 FC 73 30 8B 4D EC 03 8D D0 FE FF FF 0F B6 09 8B 85 D0 FE FF FF 99 BE 14 00 00 00 F7 FE 8B 45 E8 0F B6 14 10 33 CA 8B 45 EC 03 85 D0 FE FF FF 88 08 EB B6 8B 4D EC 89 4D F0 FF 55 F0 5E 8B 4D E0 33 CD E8 6D 06 00 00 8B E5 5D C3 }
		$cond2 = { 8B FF 55 8B EC 81 EC 30 01 00 00 A1 00 30 00 10 33 C5 89 45 E0 56 C7 45 F8 00 00 00 00 C6 85 D8 FE FF FF 00 68 03 01 00 00 6A 00 8D 85 D9 FE FF FF 50 E8 F9 07 00 00 83 C4 0C C7 45 F4 00 00 00 00 C6 45 E7 00 C7 45 E8 00 00 00 00 C7 45 EC 00 00 00 00 C7 45 FC 00 00 00 00 C7 45 F0 00 00 00 00 6A 01 6A 00 8D 8D D8 FE FF FF 51 6A 00 68 9C 10 00 10 8B 15 20 33 00 10 52 E8 31 01 00 00 89 45 F8 6A 14 FF 15 58 10 00 10 83 C4 04 89 45 E8 8B 45 F8 8A 48 04 88 4D E7 8B 55 F8 83 C2 0C 8B 45 E8 8B 0A 89 08 8B 4A 04 89 48 04 8B 4A 08 89 48 08 8B 4A 0C 89 48 0C 8B 52 10 89 50 10 C7 85 D4 FE FF FF 00 00 00 00 EB 0F 8B 85 D4 FE FF FF 83 C0 01 89 85 D4 FE FF FF 83 BD D4 FE FF FF 14 7D 1F 8B 4D E8 03 8D D4 FE FF FF 0F B6 11 0F B6 45 E7 33 D0 8B 4D E8 03 8D D4 FE FF FF 88 11 EB C9 8B 55 F8 8B 42 08 89 45 FC 6A 40 68 00 30 00 00 8B 4D FC 51 6A 00 FF 15 2C 10 00 10 89 45 EC 8B 55 FC 52 8B 45 F8 83 C0 20 50 8B 4D EC 51 E8 F0 06 00 00 83 C4 0C C7 85 D0 FE FF FF 00 00 00 00 EB 0F 8B 95 D0 FE FF FF 83 C2 01 89 95 D0 FE FF FF 8B 85 D0 FE FF FF 3B 45 FC 73 30 8B 4D EC 03 8D D0 FE FF FF 0F B6 09 8B 85 D0 FE FF FF 99 BE 14 00 00 00 F7 FE 8B 45 E8 0F B6 14 10 33 CA 8B 45 EC 03 85 D0 FE FF FF 88 08 EB B6 8B 4D EC 89 4D F0 FF 55 F0 5E 8B 4D E0 33 CD E8 6D 06 00 00 8B E5 5D C3 }
		$cond3 = { 8B FF 55 8B EC 81 EC 30 01 00 00 A1 ?? ?? ?? ?? 33 C5 89 45 ?? 56 C7 45 ?? 00 00 00 00 C6 85 ?? ?? ?? ?? 00 68 03 01 00 00 6A 00 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 0C C7 45 ?? 00 00 00 00 C6 45 ?? 00 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 6A 01 6A 00 8D 8D ?? ?? ?? ?? 51 6A 00 68 9C 10 00 10 8B 15 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 89 45 ?? 6A 14 FF 15 ?? ?? ?? ?? 83 C4 04 89 45 ?? 8B 45 ?? 8A 48 ?? 88 4D ?? 8B 55 ?? 83 C2 0C 8B 45 ?? 8B 0A 89 08 8B 4A ?? 89 48 ?? 8B 4A ?? 89 48 ?? 8B 4A ?? 89 48 ?? 8B 52 ?? 89 50 ?? C7 85 ?? ?? ?? ?? 00 00 00 00 EB ?? 8B 85 ?? ?? ?? ?? 83 C0 01 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 14 7D ?? 8B 4D ?? 03 8D ?? ?? ?? ?? 0F B6 11 0F B6 45 ?? 33 D0 8B 4D ?? 03 8D ?? ?? ?? ?? 88 11 EB ?? 8B 55 ?? 8B 42 ?? 89 45 ?? 6A 40 68 00 30 00 00 8B 4D ?? 51 6A 00 FF 15 ?? ?? ?? ?? 89 45 ?? 8B 55 ?? 52 8B 45 ?? 83 C0 20 50 8B 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 0C C7 85 ?? ?? ?? ?? 00 00 00 00 EB ?? 8B 95 ?? ?? ?? ?? 83 C2 01 89 95 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 3B 45 ?? 73 ?? 8B 4D ?? 03 8D ?? ?? ?? ?? 0F B6 09 8B 85 ?? ?? ?? ?? 99 BE 14 00 00 00 F7 FE 8B 45 ?? 0F B6 14 10 33 CA 8B 45 ?? 03 85 ?? ?? ?? ?? 88 08 EB ?? 8B 4D ?? 89 4D ?? FF 55 ?? 5E 8B 4D ?? 33 CD E8 ?? ?? ?? ?? 8B E5 5D C3 }
		$cond4 = { 8B FF 55 8B EC 81 EC 3? ?1 ?? ?? A1 ?? ?? ?? ?? 33 C5 89 45 E0 56 C7 45 F8 ?? ?? ?? ?? C6 85 D8 FE FF FF ?? 68 ?? ?? ?? ?? 6A ?? 8D 85 D9 FE FF FF 50 E8 ?? ?? ?? ?? 83 C4 0C C7 45 F4 ?? ?? ?? ?? C6 45 E7 ?? C7 45 E8 ?? ?? ?? ?? C7 45 EC ?? ?? ?? ?? C7 45 FC ?? ?? ?? ?? C7 45 F? ?? ?? ?? ?0 6A ?? 6A ?? 8D 8D D8 FE FF FF 51 6A ?? 68 ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 89 45 F8 6A ?? FF ?? ?? ?? ?? ?? 83 C4 04 89 45 E8 8B 45 F8 8A 48 04 88 4D E7 8B 55 F8 83 ?? ?? 8B 45 E8 8B 0A 89 08 8B 4A 04 89 48 04 8B 4A 08 89 48 08 8B 4A 0C 89 48 0C 8B 52 10 89 50 10 C7 85 D4 FE FF FF ?? ?? ?? ?? EB ?? 8B 85 D4 FE FF FF 83 C? ?1 89 85 D4 FE FF FF 83 BD D4 FE FF FF 14 7D ?? 8B 4D E8 03 8D D4 FE FF FF 0F B6 11 0F B6 45 E7 33 D0 8B 4D E8 03 8D D4 FE FF FF 88 11 EB ?? 8B 55 F8 8B 42 08 89 45 FC 6A ?? 68 ?? ?? ?? ?? 8B 4D FC 51 6A ?? FF ?? ?? ?? ?? ?? 89 45 EC 8B 55 FC 52 8B 45 F8 83 ?? ?? 50 8B 4D EC 51 E8 ?? ?? ?? ?? 83 C4 0C C7 85 D0 FE FF FF ?? ?? ?? ?? EB ?? 8B 95 D0 FE FF FF 83 C2 01 89 95 D0 FE FF FF 8B 85 D0 FE FF FF 3B 45 FC 73 ?? 8B 4D EC 03 8D D0 FE FF FF 0F B6 09 8B 85 D0 FE FF FF 99 BE ?? ?? ?? ?? F7 FE 8B 45 E8 0F B6 14 10 33 CA 8B 45 EC 03 85 D0 FE FF FF 88 08 EB ?? 8B 4D EC 89 4D F0 FF ?? ?? 5E 8B 4D E0 33 CD E8 ?? ?? ?? ?? 8B E5 5D C3 }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x010B ) and any of them
}

rule APT_HackTool_MSIL_LUALOADER_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'lualoader' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "e8480cf8-1852-5572-8e92-c0ae676b7507"

	strings:
		$typelibguid0 = {((38 62 35 34 36 62 34 39 2d 32 62 32 63 2d 34 35 37 37 2d 61 33 32 33 2d 37 36 64 63 37 31 33 66 65 32 65 61) | (38 00 62 00 35 00 34 00 36 00 62 00 34 00 39 00 2d 00 32 00 62 00 32 00 63 00 2d 00 34 00 35 00 37 00 37 00 2d 00 61 00 33 00 32 00 33 00 2d 00 37 00 36 00 64 00 63 00 37 00 31 00 33 00 66 00 65 00 32 00 65 00 61 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HackTool_MSIL_PXELOOT_2 : hardened limited
{
	meta:
		description = "This rule looks for .NET PE files that have the strings of various method names in the PXE And Loot code."
		md5 = "d93100fe60c342e9e3b13150fd91c7d8"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		date = "2020-12-08"
		modified = "2023-01-27"
		id = "ff46a0e9-f7d2-57f2-9727-26b69ea5ba71"

	strings:
		$msil = {((5f 43 6f 72 45 78 65 4d 61 69 6e) | (5f 00 43 00 6f 00 72 00 45 00 78 00 65 00 4d 00 61 00 69 00 6e 00))}
		$str2 = {((49 6e 76 65 73 74 69 67 61 74 65 52 50 43) | (49 00 6e 00 76 00 65 00 73 00 74 00 69 00 67 00 61 00 74 00 65 00 52 00 50 00 43 00))}
		$str3 = {((44 68 63 70 52 65 63 6f 6e) | (44 00 68 00 63 00 70 00 52 00 65 00 63 00 6f 00 6e 00))}
		$str4 = {((55 6e 4d 6f 75 6e 74 57 69 6d) | (55 00 6e 00 4d 00 6f 00 75 00 6e 00 74 00 57 00 69 00 6d 00))}
		$str5 = {((72 65 6d 6f 74 65 20 57 49 4d 20 69 6d 61 67 65) | (72 00 65 00 6d 00 6f 00 74 00 65 00 20 00 57 00 49 00 4d 00 20 00 69 00 6d 00 61 00 67 00 65 00))}
		$str6 = {((44 49 53 4d 57 72 61 70 70 65 72) | (44 00 49 00 53 00 4d 00 57 00 72 00 61 00 70 00 70 00 65 00 72 00))}
		$str7 = {((66 69 6e 64 54 46 54 50 53 65 72 76 65 72) | (66 00 69 00 6e 00 64 00 54 00 46 00 54 00 50 00 53 00 65 00 72 00 76 00 65 00 72 00))}
		$str8 = {((44 48 43 50 52 65 71 75 65 73 74 52 65 63 6f 6e) | (44 00 48 00 43 00 50 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00 52 00 65 00 63 00 6f 00 6e 00))}
		$str9 = {((44 48 43 50 44 69 73 63 6f 76 65 72 52 65 63 6f 6e) | (44 00 48 00 43 00 50 00 44 00 69 00 73 00 63 00 6f 00 76 00 65 00 72 00 52 00 65 00 63 00 6f 00 6e 00))}
		$str10 = {((47 6f 6f 64 69 65 46 69 6c 65) | (47 00 6f 00 6f 00 64 00 69 00 65 00 46 00 69 00 6c 00 65 00))}
		$str11 = {((49 6e 66 6f 53 74 6f 72 65) | (49 00 6e 00 66 00 6f 00 53 00 74 00 6f 00 72 00 65 00))}
		$str12 = {((65 78 65 63 75 74 65) | (65 00 78 00 65 00 63 00 75 00 74 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and $msil and all of ( $str* )
}

rule APT_HackTool_MSIL_PRAT_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'prat' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "4a876eb0-ed2f-5ef2-a9b3-ba728b07c8c0"

	strings:
		$typelibguid0 = {((37 64 31 32 31 39 66 62 2d 61 39 35 34 2d 34 39 61 37 2d 39 36 63 39 2d 64 66 39 65 36 34 32 39 61 38 63 37) | (37 00 64 00 31 00 32 00 31 00 39 00 66 00 62 00 2d 00 61 00 39 00 35 00 34 00 2d 00 34 00 39 00 61 00 37 00 2d 00 39 00 36 00 63 00 39 00 2d 00 64 00 66 00 39 00 65 00 36 00 34 00 32 00 39 00 61 00 38 00 63 00 37 00))}
		$typelibguid1 = {((62 63 31 31 35 37 63 32 2d 61 61 36 64 2d 34 36 66 38 2d 38 64 37 33 2d 30 36 38 66 63 30 38 61 36 37 30 36) | (62 00 63 00 31 00 31 00 35 00 37 00 63 00 32 00 2d 00 61 00 61 00 36 00 64 00 2d 00 34 00 36 00 66 00 38 00 2d 00 38 00 64 00 37 00 33 00 2d 00 30 00 36 00 38 00 66 00 63 00 30 00 38 00 61 00 36 00 37 00 30 00 36 00))}
		$typelibguid2 = {((63 36 30 32 66 61 65 32 2d 62 38 33 31 2d 34 31 65 32 2d 62 35 66 38 2d 64 34 64 66 36 65 33 32 35 35 64 66) | (63 00 36 00 30 00 32 00 66 00 61 00 65 00 32 00 2d 00 62 00 38 00 33 00 31 00 2d 00 34 00 31 00 65 00 32 00 2d 00 62 00 35 00 66 00 38 00 2d 00 64 00 34 00 64 00 66 00 36 00 65 00 33 00 32 00 35 00 35 00 64 00 66 00))}
		$typelibguid3 = {((64 66 61 61 30 62 37 64 2d 36 31 38 34 2d 34 61 39 61 2d 39 65 65 62 2d 63 30 38 36 32 32 64 31 35 38 30 31) | (64 00 66 00 61 00 61 00 30 00 62 00 37 00 64 00 2d 00 36 00 31 00 38 00 34 00 2d 00 34 00 61 00 39 00 61 00 2d 00 39 00 65 00 65 00 62 00 2d 00 63 00 30 00 38 00 36 00 32 00 32 00 64 00 31 00 35 00 38 00 30 00 31 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule APT_HackTool_MSIL_SHARPNATIVEZIPPER_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpnativezipper' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "c48835a7-06fe-5b30-be4d-086d98dc7a21"

	strings:
		$typelibguid0 = {((64 65 35 35 33 36 64 62 2d 39 61 33 35 2d 34 65 30 36 2d 62 63 37 35 2d 31 32 38 37 31 33 65 61 36 64 32 37) | (64 00 65 00 35 00 35 00 33 00 36 00 64 00 62 00 2d 00 39 00 61 00 33 00 35 00 2d 00 34 00 65 00 30 00 36 00 2d 00 62 00 63 00 37 00 35 00 2d 00 31 00 32 00 38 00 37 00 31 00 33 00 65 00 61 00 36 00 64 00 32 00 37 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule APT_Loader_Win32_REDFLARE_1 : hardened
{
	meta:
		date = "2020-11-27"
		modified = "2020-11-27"
		md5 = "01d68343ac46db6065f888a094edfe4f"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "b8a2c388-3b27-5075-b0ee-2773ae0c67ad"

	strings:
		$alloc_n_load = { 6A 40 68 00 30 00 00 [0-20] 6A 00 [0-20] FF D0 [4-60] F3 A4 [30-100] 6B C0 28 8B 4D ?? 8B 4C 01 10 8B 55 ?? 6B D2 28 }
		$const_values = { 0F B6 ?? 83 C? 20 83 F? 6D [2-20] 83 C? 20 83 F? 7A }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x010B ) and all of them
}

rule APT_Loader_MSIL_PGF_1 : hardened
{
	meta:
		date = "2020-11-24"
		modified = "2020-11-24"
		description = "base.cs"
		md5 = "a495c6d11ff3f525915345fb762f8047"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "39d9821f-86e8-528a-a0a9-287dbe325484"

	strings:
		$sb1 = { 72 [4] 6F [2] 00 0A 26 [0-16] 0? 6F [2] 00 0A [1-3] 0? 28 [2] 00 0A [0-1] 0? 72 [4-5] 0? 28 [2] 00 0A [0-1] 0? 6F [2] 00 0A 13 ?? 1? 13 ?? 38 [8-16] 91 [3-6] 8E 6? 5D 91 61 D2 9C 11 ?? 1? 58 13 [3-5] 8E 6? 3F }

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule CredTheft_Win_EXCAVATOR_2 : hardened
{
	meta:
		description = "This rule looks for the binary signature of the routine that calls PssFreeSnapshot found in the Excavator-Reflector DLL."
		md5 = "6a9a114928554c26675884eeb40cc01b"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "89037b9a-78b0-5a8c-bb60-3d54842d81e1"

	strings:
		$bytes1 = { 4C 89 74 24 20 55 48 8D AC 24 60 FF FF FF 48 81 EC A0 01 00 00 48 8B 05 4C 4A 01 00 48 33 C4 48 89 85 90 00 00 00 BA 50 00 00 00 C7 05 CB 65 01 00 43 00 3A 00 66 89 15 EC 65 01 00 4C 8D 44 24 68 48 8D 15 D8 68 01 00 C7 05 B2 65 01 00 5C 00 57 00 33 C9 C7 05 AA 65 01 00 69 00 6E 00 C7 05 A4 65 01 00 64 00 6F 00 C7 05 9E 65 01 00 77 00 73 00 C7 05 98 65 01 00 5C 00 4D 00 C7 05 92 65 01 00 45 00 4D 00 C7 05 8C 65 01 00 4F 00 52 00 C7 05 86 65 01 00 59 00 2E 00 C7 05 80 65 01 00 44 00 4D 00 C7 05 72 68 01 00 53 00 65 00 C7 05 6C 68 01 00 44 00 65 00 C7 05 66 68 01 00 42 00 75 00 C7 05 60 68 01 00 47 00 50 00 C7 05 5A 68 01 00 72 00 69 00 C7 05 54 68 01 00 56 00 69 00 C7 05 4E 68 01 00 4C 00 45 00 C7 05 48 68 01 00 67 00 65 00 C7 05 12 67 01 00 6C 73 61 73 C7 05 0C 67 01 00 73 2E 65 78 C6 05 09 67 01 00 65 FF 15 63 B9 00 00 45 33 F6 85 C0 74 66 48 8B 44 24 68 48 89 44 24 74 C7 44 24 70 01 00 00 00 C7 44 24 7C 02 00 00 00 FF 15 A4 B9 00 00 48 8B C8 4C 8D 44 24 48 41 8D 56 20 FF 15 1A B9 00 00 85 C0 74 30 48 8B 4C 24 48 4C 8D 44 24 70 4C 89 74 24 28 45 33 C9 33 D2 4C 89 74 24 20 FF 15 EF B8 00 00 FF 15 11 B9 00 00 48 8B 4C 24 48 FF 15 16 B9 00 00 48 89 9C 24 B0 01 00 00 48 8D 0D BF 2E 01 00 48 89 B4 24 B8 01 00 00 4C 89 74 24 40 FF 15 1C B9 00 00 48 85 C0 0F 84 B0 00 00 00 48 8D 15 AC 2E 01 00 48 8B C8 FF 15 1B B9 00 00 48 8B D8 48 85 C0 0F 84 94 00 00 00 33 D2 48 8D 4D 80 41 B8 04 01 00 00 E8 06 15 00 00 48 8B 4C 24 40 48 8D 44 24 40 45 33 C9 48 89 44 24 20 45 33 C0 BA 00 00 00 02 FF D3 85 C0 75 63 66 0F 1F 44 00 00 48 8B 4C 24 40 4C 8D 45 80 41 B9 04 01 00 00 33 D2 FF 15 89 B8 00 00 48 8D 15 F2 65 01 00 48 8D 4D 80 E8 49 0F 00 00 48 85 C0 75 38 33 D2 48 8D 4D 80 41 B8 04 01 00 00 E8 A3 14 00 00 48 8B 4C 24 40 48 8D 44 24 40 45 33 C9 48 89 44 24 20 45 33 C0 BA 00 00 00 02 FF D3 85 C0 74 A3 33 C0 E9 F5 00 00 00 48 8B 5C 24 40 48 8B CB FF 15 5E B8 00 00 8B F0 48 85 DB 74 E4 85 C0 74 E0 4C 8D 4C 24 50 48 89 BC 24 C0 01 00 00 BA FD 03 00 AC 41 B8 1F 00 10 00 48 8B CB FF 15 12 B8 00 00 85 C0 0F 85 A0 00 00 00 48 8D 05 43 FD FF FF 4C 89 74 24 30 C7 44 24 28 80 00 00 00 48 8D 0D 3F 63 01 00 45 33 C9 48 89 44 24 58 45 33 C0 C7 44 24 20 01 00 00 00 BA 00 00 00 10 4C 89 74 24 60 FF 15 E4 B7 00 00 48 8B F8 48 83 F8 FF 74 59 48 8B 4C 24 50 48 8D 44 24 58 48 89 44 24 30 41 B9 02 00 00 00 4C 89 74 24 28 4C 8B C7 8B D6 4C 89 74 24 20 FF 15 B1 B9 00 00 48 8B CB FF 15 78 B7 00 00 48 8B CF FF 15 6F B7 00 00 FF 15 B1 B7 00 00 48 8B 54 24 50 48 8B C8 FF 15 53 B7 00 00 33 C9 FF 15 63 B7 00 00 CC 48 8B CB FF 15 49 B7 00 00 48 8B BC 24 C0 01 00 00 33 C0 48 8B B4 24 B8 01 00 00 48 8B 9C 24 B0 01 00 00 48 8B 8D 90 00 00 00 48 33 CC E8 28 00 00 00 4C 8B B4 24 C8 01 00 00 48 81 C4 A0 01 00 00 5D C3 }
		$bytes2 = { 4C 89 74 24 20 55 48 8D AC 24 60 FF FF FF 48 81 EC A? ?1 ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 33 C4 48 89 85 9? ?? ?? ?0 BA ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? 66 89 ?? ?? ?? ?? ?? 4C 8D 44 24 68 48 ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? 33 C9 C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C6 ?? ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 45 33 F6 85 C0 74 ?? 48 8B 44 24 68 48 89 44 24 74 C7 44 24 7? ?1 ?? ?? ?? C7 44 24 7C 02 ?? ?? ?? FF ?? ?? ?? ?? ?? 48 8B C8 4C 8D 44 24 48 41 8D 56 20 FF ?? ?? ?? ?? ?? 85 C0 74 ?? 48 8B 4C 24 48 4C 8D 44 24 70 4C 89 74 24 28 45 33 C9 33 D2 4C 89 74 24 20 FF ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 48 8B 4C 24 48 FF ?? ?? ?? ?? ?? 48 89 9C 24 B? ?1 ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 89 B4 24 B8 01 ?? ?? 4C 89 74 24 40 FF ?? ?? ?? ?? ?? 48 85 C0 0F 84 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 8B C8 FF ?? ?? ?? ?? ?? 48 8B D8 48 85 C0 0F 84 ?? ?? ?? ?? 33 D2 48 8D 4D 80 41 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 4C 24 40 48 8D 44 24 40 45 33 C9 48 89 44 24 20 45 33 C0 BA ?? ?? ?? ?? FF D3 85 C0 75 ?? 66 0F 1F 44 ?? ?? 48 8B 4C 24 40 4C 8D 45 80 41 ?? ?? ?? ?? ?? 33 D2 FF ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 8D 4D 80 E8 ?? ?? ?? ?? 48 85 C0 75 ?? 33 D2 48 8D 4D 80 41 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 4C 24 40 48 8D 44 24 40 45 33 C9 48 89 44 24 20 45 33 C0 BA ?? ?? ?? ?? FF D3 85 C0 74 ?? 33 C0 E9 ?? ?? ?? ?? 48 8B 5C 24 40 48 8B CB FF ?? ?? ?? ?? ?? 8B F0 48 85 DB 74 ?? 85 C0 74 ?? 4C 8D 4C 24 50 48 89 BC 24 C? ?1 ?? ?? BA ?? ?? ?? ?? 41 ?? ?? ?? ?? ?? 48 8B CB FF ?? ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 4C 89 74 24 30 C7 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 45 33 C9 48 89 44 24 58 45 33 C0 C7 44 24 2? ?1 ?? ?? ?? BA ?? ?? ?? ?? 4C 89 74 24 60 FF ?? ?? ?? ?? ?? 48 8B F8 48 83 F8 FF 74 ?? 48 8B 4C 24 50 48 8D 44 24 58 48 89 44 24 30 41 B9 02 ?? ?? ?? 4C 89 74 24 28 4C 8B C7 8B D6 4C 89 74 24 20 FF ?? ?? ?? ?? ?? 48 8B CB FF ?? ?? ?? ?? ?? 48 8B CF FF ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 48 8B 54 24 50 48 8B C8 FF ?? ?? ?? ?? ?? 33 C9 FF ?? ?? ?? ?? ?? 48 8B CB FF ?? ?? ?? ?? ?? 48 8B BC 24 C? ?1 ?? ?? 33 C0 48 8B B4 24 B8 01 ?? ?? 48 8B 9C 24 B? ?1 ?? ?? 48 8B 8D 9? ?? ?? ?0 48 33 CC E8 ?? ?? ?? ?? 4C 8B B4 24 C8 01 ?? ?? 48 81 C4 A? ?1 ?? ?? 5D C3 }
		$bytes3 = { 4C 89 74 24 20 55 48 8D AC 24 60 FF FF FF 48 81 EC A? ?1 ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 33 C4 48 89 85 9? ?? ?? ?0 BA ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? 66 89 ?? ?? ?? ?? ?? 4C 8D 44 24 68 48 ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? 33 C9 C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C6 ?? ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 45 33 F6 85 C0 74 ?? 48 8B 44 24 68 48 89 44 24 74 C7 44 24 7? ?1 ?? ?? ?? C7 44 24 7C 02 ?? ?? ?? FF ?? ?? ?? ?? ?? 48 8B C8 4C 8D 44 24 48 41 8D 56 20 FF ?? ?? ?? ?? ?? 85 C0 74 ?? 48 8B 4C 24 48 4C 8D 44 24 70 4C 89 74 24 28 45 33 C9 33 D2 4C 89 74 24 20 FF ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 48 8B 4C 24 48 FF ?? ?? ?? ?? ?? 48 89 9C 24 B? ?1 ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 89 B4 24 B8 01 ?? ?? 4C 89 74 24 40 FF ?? ?? ?? ?? ?? 48 85 C0 0F 84 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 8B C8 FF ?? ?? ?? ?? ?? 48 8B D8 48 85 C0 0F 84 ?? ?? ?? ?? 33 D2 48 8D 4D 80 41 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 4C 24 40 48 8D 44 24 40 45 33 C9 48 89 44 24 20 45 33 C0 BA ?? ?? ?? ?? FF D3 85 C0 75 ?? 66 0F 1F 44 ?? ?? 48 8B 4C 24 40 4C 8D 45 80 41 ?? ?? ?? ?? ?? 33 D2 FF ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 8D 4D 80 E8 ?? ?? ?? ?? 48 85 C0 75 ?? 33 D2 48 8D 4D 80 41 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 4C 24 40 48 8D 44 24 40 45 33 C9 48 89 44 24 20 45 33 C0 BA ?? ?? ?? ?? FF D3 85 C0 74 ?? 33 C0 E9 ?? ?? ?? ?? 48 8B 5C 24 40 48 8B CB FF ?? ?? ?? ?? ?? 8B F0 48 85 DB 74 ?? 85 C0 74 ?? 4C 8D 4C 24 50 48 89 BC 24 C? ?1 ?? ?? BA ?? ?? ?? ?? 41 ?? ?? ?? ?? ?? 48 8B CB FF ?? ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 4C 89 74 24 30 C7 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 45 33 C9 48 89 44 24 58 45 33 C0 C7 44 24 2? ?1 ?? ?? ?? BA ?? ?? ?? ?? 4C 89 74 24 60 FF ?? ?? ?? ?? ?? 48 8B F8 48 83 F8 FF 74 ?? 48 8B 4C 24 50 48 8D 44 24 58 48 89 44 24 30 41 B9 02 ?? ?? ?? 4C 89 74 24 28 4C 8B C7 8B D6 4C 89 74 24 20 FF ?? ?? ?? ?? ?? 48 8B CB FF ?? ?? ?? ?? ?? 48 8B CF FF ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 48 8B 54 24 50 48 8B C8 FF ?? ?? ?? ?? ?? 33 C9 FF ?? ?? ?? ?? ?? 48 8B CB FF ?? ?? ?? ?? ?? 48 8B BC 24 C? ?1 ?? ?? 33 C0 48 8B B4 24 B8 01 ?? ?? 48 8B 9C 24 B? ?1 ?? ?? 48 8B 8D 9? ?? ?? ?0 48 33 CC E8 ?? ?? ?? ?? 4C 8B B4 24 C8 01 ?? ?? 48 81 C4 A? ?1 ?? ?? 5D C3 }
		$bytes4 = { 4C 89 74 24 ?? 55 48 8D AC 24 ?? ?? ?? ?? 48 81 EC A0 01 00 00 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 85 ?? ?? ?? ?? BA 50 00 00 00 C7 05 ?? ?? ?? ?? 43 00 3A 00 66 89 15 ?? ?? 01 00 4C 8D 44 24 ?? 48 8D 15 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 5C 00 57 00 33 C9 C7 05 ?? ?? ?? ?? 69 00 6E 00 C7 05 ?? ?? ?? ?? 64 00 6F 00 C7 05 ?? ?? ?? ?? 77 00 73 00 C7 05 ?? ?? ?? ?? 5C 00 4D 00 C7 05 ?? ?? ?? ?? 45 00 4D 00 C7 05 ?? ?? ?? ?? 4F 00 52 00 C7 05 ?? ?? ?? ?? 59 00 2E 00 C7 05 ?? ?? ?? ?? 44 00 4D 00 C7 05 ?? ?? ?? ?? 53 00 65 00 C7 05 ?? ?? ?? ?? 44 00 65 00 C7 05 ?? ?? ?? ?? 42 00 75 00 C7 05 ?? ?? ?? ?? 47 00 50 00 C7 05 ?? ?? ?? ?? 72 00 69 00 C7 05 ?? ?? ?? ?? 56 00 69 00 C7 05 ?? ?? ?? ?? 4C 00 45 00 C7 05 ?? ?? ?? ?? 67 00 65 00 C7 05 ?? ?? ?? ?? 6C 73 61 73 C7 05 ?? ?? ?? ?? 73 2E 65 78 C6 05 ?? ?? ?? ?? 65 FF 15 ?? ?? ?? ?? 45 33 F6 85 C0 74 ?? 48 8B 44 24 ?? 48 89 44 24 ?? C7 44 24 ?? 01 00 00 00 C7 44 24 ?? 02 00 00 00 FF 15 ?? ?? ?? ?? 48 8B C8 4C 8D 44 24 ?? 41 8D 56 ?? FF 15 ?? ?? ?? ?? 85 C0 74 ?? 48 8B 4C 24 ?? 4C 8D 44 24 ?? 4C 89 74 24 ?? 45 33 C9 33 D2 4C 89 74 24 ?? FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 48 8B 4C 24 ?? FF 15 ?? ?? ?? ?? 48 89 9C 24 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? 48 89 B4 24 ?? ?? ?? ?? 4C 89 74 24 ?? FF 15 ?? ?? ?? ?? 48 85 C0 0F 84 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8B C8 FF 15 ?? ?? ?? ?? 48 8B D8 48 85 C0 0F 84 ?? ?? ?? ?? 33 D2 48 8D 4D ?? 41 B8 04 01 00 00 E8 ?? ?? ?? ?? 48 8B 4C 24 ?? 48 8D 44 24 ?? 45 33 C9 48 89 44 24 ?? 45 33 C0 BA 00 00 00 02 FF D3 85 C0 75 ?? 66 0F 1F 44 00 ?? 48 8B 4C 24 ?? 4C 8D 45 ?? 41 B9 04 01 00 00 33 D2 FF 15 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8D 4D ?? E8 ?? ?? ?? ?? 48 85 C0 75 ?? 33 D2 48 8D 4D ?? 41 B8 04 01 00 00 E8 ?? ?? ?? ?? 48 8B 4C 24 ?? 48 8D 44 24 ?? 45 33 C9 48 89 44 24 ?? 45 33 C0 BA 00 00 00 02 FF D3 85 C0 74 ?? 33 C0 E9 ?? ?? ?? ?? 48 8B 5C 24 ?? 48 8B CB FF 15 ?? ?? ?? ?? 8B F0 48 85 DB 74 ?? 85 C0 74 ?? 4C 8D 4C 24 ?? 48 89 BC 24 ?? ?? ?? ?? BA FD 03 00 AC 41 B8 1F 00 10 00 48 8B CB FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 48 8D 05 ?? ?? ?? ?? 4C 89 74 24 ?? C7 44 24 ?? 80 00 00 00 48 8D 0D ?? ?? ?? ?? 45 33 C9 48 89 44 24 ?? 45 33 C0 C7 44 24 ?? 01 00 00 00 BA 00 00 00 10 4C 89 74 24 ?? FF 15 ?? ?? ?? ?? 48 8B F8 48 83 F8 FF 74 ?? 48 8B 4C 24 ?? 48 8D 44 24 ?? 48 89 44 24 ?? 41 B9 02 00 00 00 4C 89 74 24 ?? 4C 8B C7 8B D6 4C 89 74 24 ?? FF 15 ?? ?? ?? ?? 48 8B CB FF 15 ?? ?? ?? ?? 48 8B CF FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 48 8B 54 24 ?? 48 8B C8 FF 15 ?? ?? ?? ?? 33 C9 FF 15 ?? ?? ?? ?? CC 48 8B CB FF 15 ?? ?? ?? ?? 48 8B BC 24 ?? ?? ?? ?? 33 C0 48 8B B4 24 ?? ?? ?? ?? 48 8B 9C 24 ?? ?? ?? ?? 48 8B 8D ?? ?? ?? ?? 48 33 CC E8 ?? ?? ?? ?? 4C 8B B4 24 ?? ?? ?? ?? 48 81 C4 A0 01 00 00 5D C3 }

	condition:
		uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 and any of ( $bytes* )
}

rule Builder_MSIL_SharpGenerator_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'SharpGenerator' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "ab661cba-f695-59d2-9071-9b9a90233457"

	strings:
		$typelibguid0 = {((33 66 34 35 30 39 37 37 2d 64 37 39 36 2d 34 30 31 36 2d 62 62 37 38 2d 63 39 65 39 31 63 36 61 30 66 30 38) | (33 00 66 00 34 00 35 00 30 00 39 00 37 00 37 00 2d 00 64 00 37 00 39 00 36 00 2d 00 34 00 30 00 31 00 36 00 2d 00 62 00 62 00 37 00 38 00 2d 00 63 00 39 00 65 00 39 00 31 00 63 00 36 00 61 00 30 00 66 00 30 00 38 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HackTool_Win64_AndrewSpecial_1 : hardened
{
	meta:
		description = "Detects AndrewSpecial process dumping tool"
		date = "2020-11-25"
		modified = "2020-11-25"
		md5 = "4456e52f6f8543c3ba76cb25ea3e9bd2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "20ce4902-4eb3-5ecf-aa8c-0515965dde57"

	strings:
		$dump = { 33 D2 B9 FF FF 1F 00 FF 15 [10-90] 00 00 00 00 [2-6] 80 00 00 00 [2-6] 02 00 00 00 45 33 C9 45 33 C0 BA 00 00 00 10 48 8D 0D [4] FF 15 [4-120] 00 00 00 00 [2-6] 00 00 00 00 [2-6] 00 00 00 00 41 B9 02 00 00 00 [6-15] E8 [4-20] FF 15 }
		$shellcode_x64 = { 4C 8B D1 B8 3C 00 00 00 0F 05 C3 }
		$shellcode_x64_inline = { C6 44 24 ?? 4C C6 44 24 ?? 8B C6 44 24 ?? D1 C6 44 24 ?? B8 C6 44 24 ?? 3C C6 44 24 ?? 00 C6 44 24 ?? 00 C6 44 24 ?? 00 C6 44 24 ?? 0F C6 44 24 ?? 05 C6 44 24 ?? C3 }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) and $dump and any of ( $shellcode* )
}

rule Loader_MSIL_Generic_1 : hardened
{
	meta:
		description = "Detects generic loader"
		md5 = "b8415b4056c10c15da5bba4826a44ffd"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "f919e3fc-cf76-53af-8f04-24921830666f"

	strings:
		$MSIL = {5f 43 6f 72 45 78 65 4d 61 69 6e}
		$opc1 = { 00 72 [4] 0A 72 [4] 0B 06 28 [4] 0C 12 03 FE 15 [4] 12 04 FE 15 [4] 07 14 }
		$str1 = {44 6c 6c 49 6d 70 6f 72 74 41 74 74 72 69 62 75 74 65}
		$str2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67}
		$str3 = {52 65 73 75 6d 65 54 68 72 65 61 64}
		$str4 = {4f 70 65 6e 54 68 72 65 61 64}
		$str5 = {53 75 73 70 65 6e 64 54 68 72 65 61 64}
		$str6 = {51 75 65 75 65 55 73 65 72 41 50 43}

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and $MSIL and all of them
}

rule APT_Keylogger_Win32_REDFLARE_1 : hardened
{
	meta:
		description = "Detects REDFLARE Keylogger"
		date = "2020-12-01"
		modified = "2020-12-01"
		md5 = "d7cfb9fbcf19ce881180f757aeec77dd"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "ad14db66-d640-5712-b2c8-a3d42d5a90f3"

	strings:
		$create_window = { 6A 00 68 [4] 6A 00 6A 00 68 00 00 00 80 68 00 00 00 80 68 00 00 00 80 68 00 00 00 80 68 00 00 CF 00 68 [4] 68 [4] 6A 00 FF 15 }
		$keys_check = { 6A 14 [0-5] FF [1-5] 6A 10 [0-5] FF [1-5] B9 00 80 FF FF 66 85 C1 75 ?? 68 A0 00 00 00 FF [1-5] B9 00 80 FF FF 66 85 C1 75 ?? 68 A1 00 00 00 FF [1-5] B9 00 80 FF FF 66 85 C1 74 }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x010B ) and all of them
}

rule Loader_MSIL_InMemoryCompilation_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'In-MemoryCompilation' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "80234352-a449-5292-9f0c-beb7a1d39a6c"

	strings:
		$typelibguid0 = {((35 32 34 64 32 36 38 37 2d 30 30 34 32 2d 34 66 39 33 2d 62 36 39 35 2d 35 35 37 39 66 33 38 36 35 32 30 35) | (35 00 32 00 34 00 64 00 32 00 36 00 38 00 37 00 2d 00 30 00 30 00 34 00 32 00 2d 00 34 00 66 00 39 00 33 00 2d 00 62 00 36 00 39 00 35 00 2d 00 35 00 35 00 37 00 39 00 66 00 33 00 38 00 36 00 35 00 32 00 30 00 35 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HackTool_MSIL_WMISharp_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'WMISharp' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "97b9d057-30d3-5af7-bac6-4dd53f47650f"

	strings:
		$typelibguid0 = {((33 61 32 34 32 31 64 39 2d 63 31 61 61 2d 34 66 66 66 2d 61 64 37 36 2d 37 66 63 62 34 38 65 64 34 62 66 66) | (33 00 61 00 32 00 34 00 32 00 31 00 64 00 39 00 2d 00 63 00 31 00 61 00 61 00 2d 00 34 00 66 00 66 00 66 00 2d 00 61 00 64 00 37 00 36 00 2d 00 37 00 66 00 63 00 62 00 34 00 38 00 65 00 64 00 34 00 62 00 66 00 66 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule APT_Loader_Win_PGF_2 : hardened
{
	meta:
		description = "PE rich header matches PGF backdoor"
		md5 = "226b1ac427eb5a4dc2a00cc72c163214"
		md5_2 = "2398ed2d5b830d226af26dedaf30f64a"
		md5_3 = "24a7c99da9eef1c58f09cf09b9744d7b"
		md5_4 = "aeb0e1d0e71ce2a08db9b1e5fb98e0aa"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "595c9e2a-3d9d-5366-9449-de1bcf333f78"

	strings:
		$rich1 = { A8 B7 17 3A EC D6 79 69 EC D6 79 69 EC D6 79 69 2F D9 24 69 E8 D6 79 69 E5 AE EC 69 EA D6 79 69 EC D6 78 69 A8 D6 79 69 E5 AE EA 69 EF D6 79 69 E5 AE FA 69 D0 D6 79 69 E5 AE EB 69 ED D6 79 69 E5 AE FD 69 E2 D6 79 69 CB 10 07 69 ED D6 79 69 E5 AE E8 69 ED D6 79 69 }
		$rich2 = { C1 CF 75 A4 85 AE 1B F7 85 AE 1B F7 85 AE 1B F7 8C D6 88 F7 83 AE 1B F7 0D C9 1A F6 87 AE 1B F7 0D C9 1E F6 8F AE 1B F7 0D C9 1F F6 8F AE 1B F7 0D C9 18 F6 84 AE 1B F7 DE C6 1A F6 86 AE 1B F7 85 AE 1A F7 BF AE 1B F7 84 C3 12 F6 81 AE 1B F7 84 C3 E4 F7 84 AE 1B F7 84 C3 19 F6 84 AE 1B F7 }
		$rich3 = { D6 60 82 B8 92 01 EC EB 92 01 EC EB 92 01 EC EB 9B 79 7F EB 94 01 EC EB 1A 66 ED EA 90 01 EC EB 1A 66 E9 EA 98 01 EC EB 1A 66 E8 EA 9A 01 EC EB 1A 66 EF EA 90 01 EC EB C9 69 ED EA 91 01 EC EB 92 01 ED EB AF 01 EC EB 93 6C E5 EA 96 01 EC EB 93 6C 13 EB 93 01 EC EB 93 6C EE EA 93 01 EC EB }
		$rich4 = { 41 36 64 33 05 57 0A 60 05 57 0A 60 05 57 0A 60 73 CA 71 60 01 57 0A 60 0C 2F 9F 60 04 57 0A 60 0C 2F 89 60 3D 57 0A 60 0C 2F 8E 60 0A 57 0A 60 05 57 0B 60 4A 57 0A 60 0C 2F 99 60 06 57 0A 60 73 CA 67 60 04 57 0A 60 0C 2F 98 60 04 57 0A 60 0C 2F 80 60 04 57 0A 60 22 91 74 60 04 57 0A 60 0C 2F 9B 60 04 57 0A 60 }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and filesize < 15MB and ( ( $rich1 at 128 ) or ( $rich2 at 128 ) or ( $rich3 at 128 ) or ( $rich4 at 128 ) )
}

rule Trojan_Win_Generic_101 : hardened
{
	meta:
		description = "Detects FireEye Windows trojan"
		date = "2020-11-25"
		modified = "2020-11-25"
		md5 = "2e67c62bd0307c04af469ee8dcb220f2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "0290aaea-d65b-5883-97f9-549d107e3e1f"

	strings:
		$s0 = { 2A [1-16] 17 [1-16] 02 04 00 00 [1-16] FF 15 }
		$s1 = { 81 7? [1-3] 02 04 00 00 7? [1-3] 83 7? [1-3] 17 7? [1-3] 83 7? [1-3] 2A 7? }
		$s2 = { FF 15 [4-16] FF D? [1-16] 3D [1-24] 89 [1-8] E8 [4-16] 89 [1-8] F3 A4 [1-24] E8 }
		$si1 = {50 65 65 6b 4d 65 73 73 61 67 65 41}
		$si2 = {50 6f 73 74 54 68 72 65 61 64 4d 65 73 73 61 67 65 41}

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and @s0 [ 1 ] < @s1 [ 1 ] and @s1 [ 1 ] < @s2 [ 1 ] and all of them
}

rule Loader_MSIL_CSharpSectionInjection_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'C_Sharp_SectionInjection' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "ca5bf5cd-1950-53ed-8984-e880a15e658e"

	strings:
		$typelibguid0 = {((64 37 37 31 33 35 64 61 2d 30 34 39 36 2d 34 62 35 63 2d 39 61 66 65 2d 65 31 35 39 30 61 34 63 31 33 36 61) | (64 00 37 00 37 00 31 00 33 00 35 00 64 00 61 00 2d 00 30 00 34 00 39 00 36 00 2d 00 34 00 62 00 35 00 63 00 2d 00 39 00 61 00 66 00 65 00 2d 00 65 00 31 00 35 00 39 00 30 00 61 00 34 00 63 00 31 00 33 00 36 00 61 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule APT_HackTool_MSIL_SHARPWEBCRAWLER_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpwebcrawler' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "29b2a410-bcc4-58df-b192-7a413b3db1c0"

	strings:
		$typelibguid0 = {((63 66 32 37 61 62 66 34 2d 65 66 33 35 2d 34 36 63 64 2d 38 64 30 63 2d 37 35 36 36 33 30 63 36 38 36 66 31) | (63 00 66 00 32 00 37 00 61 00 62 00 66 00 34 00 2d 00 65 00 66 00 33 00 35 00 2d 00 34 00 36 00 63 00 64 00 2d 00 38 00 64 00 30 00 63 00 2d 00 37 00 35 00 36 00 36 00 33 00 30 00 63 00 36 00 38 00 36 00 66 00 31 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule Trojan_Win64_Generic_22 : hardened
{
	meta:
		description = "Detects FireEye's Windows Trojan"
		date = "2020-11-26"
		modified = "2020-11-26"
		md5 = "f7d9961463b5110a3d70ee2e97842ed3"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "e79661a8-5254-5e8e-b92b-edf1ddb072ff"

	strings:
		$api1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78}
		$api2 = {55 70 64 61 74 65 50 72 6f 63 54 68 72 65 61 64 41 74 74 72 69 62 75 74 65}
		$api3 = {44 75 70 6c 69 63 61 74 65 54 6f 6b 65 6e 45 78}
		$api4 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 41 73 55 73 65 72 41}
		$inject = { C7 44 24 20 40 00 00 00 33 D2 41 B9 00 30 00 00 41 B8 [4] 48 8B CB FF 15 [4] 48 8B F0 48 85 C0 74 ?? 4C 89 74 24 20 41 B9 [4] 4C 8D 05 [4] 48 8B D6 48 8B CB FF 15 [4] 85 C0 75 [5-10] 4C 8D 0C 3E 48 8D 44 24 ?? 48 89 44 24 30 44 89 74 24 28 4C 89 74 24 20 33 D2 41 B8 [4] 48 8B CB FF 15 }
		$process = { 89 74 24 30 ?? 8D 4C 24 [2] 89 74 24 28 33 D2 41 B8 00 00 02 00 48 C7 44 24 20 08 00 00 00 48 8B CF FF 15 [4] 85 C0 0F 84 [4] 48 8B [2-3] 48 8D 45 ?? 48 89 44 24 50 4C 8D 05 [4] 48 8D 45 ?? 48 89 7D 08 48 89 44 24 48 45 33 C9 ?? 89 74 24 40 33 D2 ?? 89 74 24 38 C7 44 24 30 04 00 08 00 [0-1] 89 74 24 28 ?? 89 74 24 20 FF 15 }
		$token = { FF 15 [4] 4C 8D 44 24 ?? BA 0A 00 00 00 48 8B C8 FF 15 [4] 85 C0 0F 84 [4] 48 8B 4C 24 ?? 48 8D [2-3] 41 B9 02 00 00 00 48 89 44 24 28 45 33 C0 C7 44 24 20 02 00 00 00 41 8D 51 09 FF 15 [4] 85 C0 0F 84 [4] 45 33 C0 4C 8D 4C 24 ?? 33 C9 41 8D 50 01 FF 15 }

	condition:
		(( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) ) and all of them
}

rule Loader_Win_Generic_19 : hardened
{
	meta:
		description = "Detects generic Windows loader"
		date = "2020-12-02"
		modified = "2020-12-02"
		md5 = "3fb9341fb11eca439b50121c6f7c59c7"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "4f4427ee-0f7d-5442-98a6-402d8b797289"

	strings:
		$s0 = { 8B [1-16] 89 [1-16] E8 [4-32] F3 A4 [0-16] 89 [1-8] E8 }
		$s1 = { 83 EC [1-16] 04 00 00 00 [1-24] 00 30 00 00 [1-24] FF 15 [4-16] EB [16-64] 20 00 00 00 [0-8] FF 15 [4-32] C7 44 24 ?? 00 00 00 00 [0-8] C7 44 24 ?? 00 00 00 00 [0-16] FF 15 }
		$si1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74}
		$si2 = {6d 61 6c 6c 6f 63}

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule APT_Builder_PY_REDFLARE_1 : hardened
{
	meta:
		description = "Detects FireEye's Python Redflar"
		date = "2020-11-27"
		modified = "2020-11-27"
		md5 = "d0a830403e56ebaa4bfbe87dbfdee44f"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "3b5ad25d-ce66-572e-9a91-40a73b8fd447"

	strings:
		$1 = {4c 4f 41 44 5f 4f 46 46 53 45 54 5f 33 32 20 3d 20 30 78 36 31 32}
		$2 = {4c 4f 41 44 5f 4f 46 46 53 45 54 5f 36 34 20 3d 20 30 78 36 31 31}
		$3 = {63 6c 61 73 73 20 52 43 34 3a}
		$4 = {73 74 72 75 63 74 2e 70 61 63 6b 28 27 3c 51 27 20 69 66 20 69 73 36 34 62 20 65 6c 73 65 20 27 3c 4c 27}
		$5 = {73 74 61 67 65 72 43 6f 6e 66 69 67 5b 27 63 6f 6d 6d 73 27 5d 5b 27 63 6f 6e 66 69 67 27 5d}
		$6 = {5f 78 38 36 2e 64 6c 6c}
		$7 = {5f 78 36 34 2e 64 6c 6c}

	condition:
		all of them and @1 [ 1 ] < @2 [ 1 ] and @2 [ 1 ] < @3 [ 1 ] and @3 [ 1 ] < @4 [ 1 ] and @4 [ 1 ] < @5 [ 1 ]
}

rule HackTool_PY_ImpacketObfuscation_2 : hardened limited
{
	meta:
		description = "Detects FireEye's wmiexec impacket obfuscation"
		date = "2020-12-01"
		modified = "2020-12-01"
		md5 = "f3dd8aa567a01098a8a610529d892485"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "f1059f66-eaff-5866-bafb-c94236cf96a0"

	strings:
		$s1 = {69 6d 70 6f 72 74 20 72 61 6e 64 6f 6d}
		$s2 = {63 6c 61 73 73 20 57 4d 49 45 58 45 43}
		$s3 = {63 6c 61 73 73 20 52 65 6d 6f 74 65 53 68 65 6c 6c}
		$s4 = /=[\x09\x20]{0,32}str\(int\(time\.time\(\)\)[\x09\x20]{0,32}-[\x09\x20]{0,32}random\.randint\(\d{1,10}[\x09\x20]{0,32},[\x09\x20]{0,32}\d{1,10}\)\)[\x09\x20]{0,32}\+[\x09\x20]{0,32}str\(uuid\.uuid4\(\)\)\.split\([\x22\x27]\-[\x22\x27]\)\[0\]/
		$s5 = /self\.__shell[\x09\x20]{0,32}=[\x09\x20]{0,32}[\x22\x27]cmd.exe[\x09\x20]{1,32}\/q[\x09\x20]{1,32}\/K [\x22\x27]/ nocase

	condition:
		all of them
}

rule APT_Loader_MSIL_PGF_2 : hardened
{
	meta:
		date = "2020-11-25"
		modified = "2020-11-25"
		description = "base.js, ./lib/payload/techniques/jscriptdotnet/jscriptdotnet_payload.py"
		md5 = "7c2a06ceb29cdb25f24c06f2a8892fba"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "c5f2ec90-cd9b-53ce-893b-e44192fcd507"

	strings:
		$sb1 = { 2? 00 10 00 00 0A 1? 40 0? 72 [4] 0? 0? 28 [2] 00 0A 0? 03 28 [2] 00 0A 74 [2] 00 01 6F [2] 00 0A 03 1? 0? 74 [2] 00 01 28 [2] 00 0A 6? 0? 0? 28 [2] 00 06 D0 [2] 00 01 28 [2] 00 0A 1? 28 [2] 00 0A 79 [2] 00 01 71 [2] 00 01 13 ?? 0? 1? 11 ?? 0? 74 [2] 00 01 28 [2] 00 0A 28 [2] 00 0A 7E [2] 00 0A 13 ?? 1? 13 ?? 7E [2] 00 0A 13 ?? 03 28 [2] 00 0A 74 [2] 00 01 6F [2] 00 0A 03 1? 1? 11 ?? 11 ?? 1? 11 ?? 28 [2] 00 06 }
		$ss1 = {00 43 72 65 61 74 65 54 68 72 65 61 64 00}
		$ss2 = {00 53 63 72 69 70 74 4f 62 6a 65 63 74 53 74 61 63 6b 54 6f 70 00}
		$ss3 = {00 4d 69 63 72 6f 73 6f 66 74 2e 4a 53 63 72 69 70 74 00}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule APT_HackTool_MSIL_SHARPSQLCLIENT_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpsqlclient' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "4d526c36-f56f-53cf-9bdf-b7a15619eb41"

	strings:
		$typelibguid0 = {((31 33 65 64 30 33 63 64 2d 37 34 33 30 2d 34 31 30 64 2d 61 30 36 39 2d 63 66 33 37 37 31 36 35 66 62 66 64) | (31 00 33 00 65 00 64 00 30 00 33 00 63 00 64 00 2d 00 37 00 34 00 33 00 30 00 2d 00 34 00 31 00 30 00 64 00 2d 00 61 00 30 00 36 00 39 00 2d 00 63 00 66 00 33 00 37 00 37 00 31 00 36 00 35 00 66 00 62 00 66 00 64 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule Methodology_OLE_CHARENCODING_2 : hardened
{
	meta:
		description = "Looking for suspicious char encoding"
		md5 = "41b70737fa8dda75d5e95c82699c2e9b"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "7abd1a11-7a55-50ac-aa6b-537e7c59a5ab"

	strings:
		$echo1 = {((31 30 31 3b 39 39 3b 31 30 34 3b 31 31 31 3b 33 32 3b 31 31 31 3b 31 30 32 3b 31 30 32 3b) | (31 00 30 00 31 00 3b 00 39 00 39 00 3b 00 31 00 30 00 34 00 3b 00 31 00 31 00 31 00 3b 00 33 00 32 00 3b 00 31 00 31 00 31 00 3b 00 31 00 30 00 32 00 3b 00 31 00 30 00 32 00 3b 00))}
		$echo2 = {((31 30 31 3a 39 39 3a 31 30 34 3a 31 31 31 3a 33 32 3a 31 31 31 3a 31 30 32 3a 31 30 32 3a) | (31 00 30 00 31 00 3a 00 39 00 39 00 3a 00 31 00 30 00 34 00 3a 00 31 00 31 00 31 00 3a 00 33 00 32 00 3a 00 31 00 31 00 31 00 3a 00 31 00 30 00 32 00 3a 00 31 00 30 00 32 00 3a 00))}
		$echo3 = {((31 30 31 78 39 39 78 31 30 34 78 31 31 31 78 33 32 78 31 31 31 78 31 30 32 78 31 30 32 78) | (31 00 30 00 31 00 78 00 39 00 39 00 78 00 31 00 30 00 34 00 78 00 31 00 31 00 31 00 78 00 33 00 32 00 78 00 31 00 31 00 31 00 78 00 31 00 30 00 32 00 78 00 31 00 30 00 32 00 78 00))}
		$pe1 = {((37 37 3b 39 30 3b 31 34 34 3b) | (37 00 37 00 3b 00 39 00 30 00 3b 00 31 00 34 00 34 00 3b 00))}
		$pe2 = {((37 37 3a 39 30 3a 31 34 34 3a) | (37 00 37 00 3a 00 39 00 30 00 3a 00 31 00 34 00 34 00 3a 00))}
		$pe3 = {((37 37 78 39 30 78 31 34 34 78) | (37 00 37 00 78 00 39 00 30 00 78 00 31 00 34 00 34 00 78 00))}
		$pk1 = {((38 30 3b 37 35 3b 33 3b 34 3b) | (38 00 30 00 3b 00 37 00 35 00 3b 00 33 00 3b 00 34 00 3b 00))}
		$pk2 = {((38 30 3a 37 35 3a 33 3a 34 3a) | (38 00 30 00 3a 00 37 00 35 00 3a 00 33 00 3a 00 34 00 3a 00))}
		$pk3 = {((38 30 78 37 35 78 33 78 34 78) | (38 00 30 00 78 00 37 00 35 00 78 00 33 00 78 00 34 00 78 00))}

	condition:
		( uint32( 0 ) == 0xe011cfd0 ) and filesize < 10MB and any of them
}

rule HackTool_MSIL_SharpHound_3 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public SharpHound3 project."
		md5 = "eeedc09570324767a3de8205f66a5295"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "456b3208-1e8d-5eb7-81ee-39f1c886c5a7"

	strings:
		$typelibguid1 = {((41 35 31 37 41 38 44 45 2d 35 38 33 34 2d 34 31 31 44 2d 41 42 44 41 2d 32 44 30 45 31 37 36 36 35 33 39 43) | (41 00 35 00 31 00 37 00 41 00 38 00 44 00 45 00 2d 00 35 00 38 00 33 00 34 00 2d 00 34 00 31 00 31 00 44 00 2d 00 41 00 42 00 44 00 41 00 2d 00 32 00 44 00 30 00 45 00 31 00 37 00 36 00 36 00 35 00 33 00 39 00 43 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and $typelibguid1
}

rule CredTheft_MSIL_TitoSpecial_2 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the TitoSpecial project. There are 2 GUIDs in this rule as the x86 and x64 versions of this tool use a different ProjectGuid."
		md5 = "4bf96a7040a683bd34c618431e571e26"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "0262c720-e6b8-5bf2-a242-19a7f044973f"

	strings:
		$typelibguid1 = {((43 36 44 39 34 42 34 43 2d 42 30 36 33 2d 34 44 45 42 2d 41 38 33 41 2d 33 39 37 42 41 30 38 35 31 35 44 33) | (43 00 36 00 44 00 39 00 34 00 42 00 34 00 43 00 2d 00 42 00 30 00 36 00 33 00 2d 00 34 00 44 00 45 00 42 00 2d 00 41 00 38 00 33 00 41 00 2d 00 33 00 39 00 37 00 42 00 41 00 30 00 38 00 35 00 31 00 35 00 44 00 33 00))}
		$typelibguid2 = {((33 62 35 33 32 30 63 66 2d 37 34 63 31 2d 34 39 34 65 2d 62 32 63 38 2d 61 39 34 61 32 34 33 38 30 65 36 30) | (33 00 62 00 35 00 33 00 32 00 30 00 63 00 66 00 2d 00 37 00 34 00 63 00 31 00 2d 00 34 00 39 00 34 00 65 00 2d 00 62 00 32 00 63 00 38 00 2d 00 61 00 39 00 34 00 61 00 32 00 34 00 33 00 38 00 30 00 65 00 36 00 30 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( $typelibguid1 or $typelibguid2 )
}

rule CredTheft_MSIL_WCMDump_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'WCMDump' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "22796ccb-a01e-59d8-8c3a-6cbb62899940"

	strings:
		$typelibguid0 = {((32 31 65 33 32 32 66 32 2d 34 35 38 36 2d 34 61 65 62 2d 62 31 65 64 2d 64 32 34 30 65 32 61 37 39 65 31 39) | (32 00 31 00 65 00 33 00 32 00 32 00 66 00 32 00 2d 00 34 00 35 00 38 00 36 00 2d 00 34 00 61 00 65 00 62 00 2d 00 62 00 31 00 65 00 64 00 2d 00 64 00 32 00 34 00 30 00 65 00 32 00 61 00 37 00 39 00 65 00 31 00 39 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule APT_Builder_Win64_MATRYOSHKA_1 : hardened
{
	meta:
		date = "2020-12-02"
		modified = "2020-12-02"
		description = "Detects builder matryoshka_pe_to_shellcode.rs"
		md5 = "8d949c34def898f0f32544e43117c057"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "0afcf13e-5cd3-5c1c-897e-b6d0c283ab0f"

	strings:
		$sb1 = { 4D 5A 45 52 [0-32] E8 [0-32] 00 00 00 00 [0-32] 5B 48 83 EB 09 53 48 81 [0-32] C3 [0-32] FF D3 [0-32] C3 }
		$ss1 = {00 53 74 75 62 20 53 69 7a 65 3a 20}
		$ss2 = {00 45 78 65 63 75 74 61 62 6c 65 20 53 69 7a 65 3a 20}
		$ss3 = {00 5b 2b 5d 20 57 72 69 74 69 6e 67 20 6f 75 74 20 74 6f 20 66 69 6c 65}

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) and all of them
}

rule Trojan_Win64_Generic_23 : hardened
{
	meta:
		description = "Detects FireEye's Windows trojan"
		date = "2020-12-02"
		modified = "2020-12-02"
		md5 = "b66347ef110e60b064474ae746701d4a"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "470bfeed-e000-58c6-b115-dfa8aea25bef"

	strings:
		$api1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78}
		$api2 = {55 70 64 61 74 65 50 72 6f 63 54 68 72 65 61 64 41 74 74 72 69 62 75 74 65}
		$api3 = {44 75 70 6c 69 63 61 74 65 54 6f 6b 65 6e 45 78}
		$api4 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 41 73 55 73 65 72 41}
		$inject = { 8B 85 [4] C7 44 24 20 40 00 00 00 41 B9 00 30 00 00 44 8B C0 33 D2 48 8B 8D [4] FF 15 [4] 48 89 45 ?? 48 83 7D ?? 00 75 ?? 48 8B 45 ?? E9 [4] 8B 85 [4] 48 C7 44 24 20 00 00 00 00 44 8B C8 4C 8B 85 [4] 48 8B 55 ?? 48 8B 8D [4] FF 15 [4] 85 C0 75 ?? 48 8B 45 ?? EB ?? 8B 85 [4] 48 8B 4D ?? 48 03 C8 48 8B C1 48 89 45 48 48 8D 85 [4] 48 89 44 24 30 C7 44 24 28 00 00 00 00 48 8B 85 [4] 48 89 44 24 20 4C 8B 4D ?? 41 B8 00 00 10 00 33 D2 48 8B 8D [4] FF 15 }
		$process = { 48 C7 44 24 30 00 00 00 00 48 C7 44 24 28 00 00 00 00 48 C7 44 24 20 08 00 00 00 4C 8D 8D [4] 41 B8 00 00 02 00 33 D2 48 8B 8D [4] FF 15 [4] 85 C0 75 ?? E9 [4] 48 8B 85 [4] 48 89 85 [4] 48 8D 85 [4] 48 89 44 24 50 48 8D 85 [4] 48 89 44 24 48 48 C7 44 24 40 00 00 00 00 48 C7 44 24 38 00 00 00 00 C7 44 24 30 04 00 08 00 C7 44 24 28 00 00 00 00 48 C7 44 24 20 00 00 00 00 45 33 C9 4C 8D 05 [4] 33 D2 48 8B [2-5] FF 15 }
		$token = { FF 15 [4] 4C 8D 45 ?? BA 0A 00 00 00 48 8B C8 FF 15 [4] 85 C0 75 ?? E9 [4] 48 8D [2-5] 48 89 44 24 28 C7 44 24 20 02 00 00 00 41 B9 02 00 00 00 45 33 C0 BA 0B 00 00 00 48 8B 4D ?? FF 15 [4] 85 C0 75 ?? E9 [4] 4C 8D 8D [4] 45 33 C0 BA 01 00 00 00 33 C9 FF 15 }

	condition:
		(( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) ) and all of them
}

rule HackTool_MSIL_KeePersist_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'KeePersist' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "950a4744-2696-5eb7-8524-7f689cb5dbb0"

	strings:
		$typelibguid0 = {((31 64 66 34 37 64 62 32 2d 37 62 62 38 2d 34 37 63 32 2d 39 64 38 35 2d 35 66 38 64 33 66 30 34 61 38 38 34) | (31 00 64 00 66 00 34 00 37 00 64 00 62 00 32 00 2d 00 37 00 62 00 62 00 38 00 2d 00 34 00 37 00 63 00 32 00 2d 00 39 00 64 00 38 00 35 00 2d 00 35 00 66 00 38 00 64 00 33 00 66 00 30 00 34 00 61 00 38 00 38 00 34 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule Tool_MSIL_CSharpUtils_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'CSharpUtils' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "a0e8c45a-759a-5611-aa2a-3113a75fb651"

	strings:
		$typelibguid0 = {((32 31 33 30 62 63 64 39 2d 37 64 64 38 2d 34 35 36 35 2d 38 34 31 34 2d 33 32 33 65 63 35 33 33 34 34 38 64) | (32 00 31 00 33 00 30 00 62 00 63 00 64 00 39 00 2d 00 37 00 64 00 64 00 38 00 2d 00 34 00 35 00 36 00 35 00 2d 00 38 00 34 00 31 00 34 00 2d 00 33 00 32 00 33 00 65 00 63 00 35 00 33 00 33 00 34 00 34 00 38 00 64 00))}
		$typelibguid1 = {((33 31 39 32 32 38 66 30 2d 32 63 35 35 2d 34 63 65 31 2d 61 65 38 37 2d 39 65 32 31 64 37 64 62 31 65 34 30) | (33 00 31 00 39 00 32 00 32 00 38 00 66 00 30 00 2d 00 32 00 63 00 35 00 35 00 2d 00 34 00 63 00 65 00 31 00 2d 00 61 00 65 00 38 00 37 00 2d 00 39 00 65 00 32 00 31 00 64 00 37 00 64 00 62 00 31 00 65 00 34 00 30 00))}
		$typelibguid2 = {((34 34 37 31 66 65 66 39 2d 38 34 66 35 2d 34 64 64 64 2d 62 63 30 63 2d 33 31 66 32 66 33 65 30 64 62 39 65) | (34 00 34 00 37 00 31 00 66 00 65 00 66 00 39 00 2d 00 38 00 34 00 66 00 35 00 2d 00 34 00 64 00 64 00 64 00 2d 00 62 00 63 00 30 00 63 00 2d 00 33 00 31 00 66 00 32 00 66 00 33 00 65 00 30 00 64 00 62 00 39 00 65 00))}
		$typelibguid3 = {((35 63 33 62 66 39 64 62 2d 31 31 36 37 2d 34 65 66 37 2d 62 30 34 63 2d 31 64 39 30 61 30 39 34 66 35 63 33) | (35 00 63 00 33 00 62 00 66 00 39 00 64 00 62 00 2d 00 31 00 31 00 36 00 37 00 2d 00 34 00 65 00 66 00 37 00 2d 00 62 00 30 00 34 00 63 00 2d 00 31 00 64 00 39 00 30 00 61 00 30 00 39 00 34 00 66 00 35 00 63 00 33 00))}
		$typelibguid4 = {((65 61 33 38 33 61 30 66 2d 38 31 64 35 2d 34 66 61 38 2d 38 63 35 37 2d 61 39 35 30 64 61 31 37 65 30 33 31) | (65 00 61 00 33 00 38 00 33 00 61 00 30 00 66 00 2d 00 38 00 31 00 64 00 35 00 2d 00 34 00 66 00 61 00 38 00 2d 00 38 00 63 00 35 00 37 00 2d 00 61 00 39 00 35 00 30 00 64 00 61 00 31 00 37 00 65 00 30 00 33 00 31 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule Trojan_MSIL_GORAT_Module_PowerShell_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'RedFlare - Module - PowerShell' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "b0fba130-9cd9-5b7f-a806-9ff8099f5731"

	strings:
		$typelibguid0 = {((33 38 64 38 39 30 33 34 2d 32 64 64 39 2d 34 33 36 37 2d 38 61 36 65 2d 35 34 30 39 38 32 37 61 32 34 33 61) | (33 00 38 00 64 00 38 00 39 00 30 00 33 00 34 00 2d 00 32 00 64 00 64 00 39 00 2d 00 34 00 33 00 36 00 37 00 2d 00 38 00 61 00 36 00 65 00 2d 00 35 00 34 00 30 00 39 00 38 00 32 00 37 00 61 00 32 00 34 00 33 00 61 00))}
		$typelibguid1 = {((38 34 35 65 65 39 64 63 2d 39 37 63 39 2d 34 63 34 38 2d 38 33 34 65 2d 64 63 33 31 65 65 30 30 37 63 32 35) | (38 00 34 00 35 00 65 00 65 00 39 00 64 00 63 00 2d 00 39 00 37 00 63 00 39 00 2d 00 34 00 63 00 34 00 38 00 2d 00 38 00 33 00 34 00 65 00 2d 00 64 00 63 00 33 00 31 00 65 00 65 00 30 00 30 00 37 00 63 00 32 00 35 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HackTool_MSIL_PuppyHound_1 : hardened
{
	meta:
		description = "This is a modification of an existing FireEye detection for SharpHound. However, it looks for the string 'PuppyHound' instead of 'SharpHound' as this is all that was needed to detect the PuppyHound variant of SharpHound."
		md5 = "eeedc09570324767a3de8205f66a5295"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "1155f959-c8bc-597a-8a80-abee8d95b6ec"

	strings:
		$1 = {50 75 70 70 79 48 6f 75 6e 64}
		$2 = {55 73 65 72 44 6f 6d 61 69 6e 4b 65 79}
		$3 = {4c 64 61 70 42 75 69 6c 64 65 72}
		$init = { 28 [2] 00 0A 0A 72 [2] 00 70 1? ?? 28 [2] 00 0A 72 [2] 00 70 1? ?? 28 [2] 00 0A 28 [2] 00 0A 0B 1F 2D }
		$msil = /\x00_Cor(Exe|Dll)Main\x00/

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule APT_Builder_PY_MATRYOSHKA_1 : hardened
{
	meta:
		description = "Detects FireEye's Python MATRYOSHKA tool"
		date = "2020-12-02"
		modified = "2020-12-02"
		md5 = "25a97f6dba87ef9906a62c1a305ee1dd"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "0135f3bb-28b3-5fc4-85a2-b12c46c8bc45"

	strings:
		$s1 = {2e 70 6f 70 28 30 29 5d 29}
		$s2 = {5b 31 5d 2e 72 65 70 6c 61 63 65 28 27 75 6e 73 69 67 6e 65 64 20 63 68 61 72 20 62 75 66 5b 5d 20 3d 20 22 27}
		$s3 = {62 69 6e 61 73 63 69 69 2e 68 65 78 6c 69 66 79 28 66 2e 72 65 61 64 28 29 29 2e 64 65 63 6f 64 65 28}
		$s4 = {6f 73 2e 73 79 73 74 65 6d 28 22 63 61 72 67 6f 20 62 75 69 6c 64 20 7b 30 7d 20 2d 2d 62 69 6e 20 7b 31 7d 22 2e 66 6f 72 6d 61 74 28}
		$s5 = {73 68 75 74 69 6c 2e 77 68 69 63 68 28 27 72 75 73 74 63 27 29}
		$s6 = {7e 2f 2e 63 61 72 67 6f 2f 62 69 6e}
		$s7 = /[\x22\x27]\\\\x[\x22\x27]\.join\(\[\w{1,64}\[\w{1,64}:\w{1,64}[\x09\x20]{0,32}\+[\x09\x20]{0,32}2\]/

	condition:
		all of them
}

rule Loader_MSIL_RuralBishop_1b : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public RuralBishop project."
		md5 = "09bdbad8358b04994e2c04bb26a160ef"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "55a060ef-74e2-50d9-9090-558aaa04d97d"

	strings:
		$typelibguid1 = {((46 45 34 34 31 34 44 39 2d 31 44 37 45 2d 34 45 45 42 2d 42 37 38 31 2d 44 32 37 38 46 45 37 41 35 36 31 39) | (46 00 45 00 34 00 34 00 31 00 34 00 44 00 39 00 2d 00 31 00 44 00 37 00 45 00 2d 00 34 00 45 00 45 00 42 00 2d 00 42 00 37 00 38 00 31 00 2d 00 44 00 32 00 37 00 38 00 46 00 45 00 37 00 41 00 35 00 36 00 31 00 39 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and $typelibguid1
}

rule APT_HackTool_MSIL_NOAMCI_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'noamci' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "48066258-528f-5a70-81e1-15d6dfd9ff4f"

	strings:
		$typelibguid0 = {((37 62 63 63 63 66 32 31 2d 37 65 63 64 2d 34 66 64 34 2d 38 66 37 37 2d 30 36 64 34 36 31 66 64 34 64 35 31) | (37 00 62 00 63 00 63 00 63 00 66 00 32 00 31 00 2d 00 37 00 65 00 63 00 64 00 2d 00 34 00 66 00 64 00 34 00 2d 00 38 00 66 00 37 00 37 00 2d 00 30 00 36 00 64 00 34 00 36 00 31 00 66 00 64 00 34 00 64 00 35 00 31 00))}
		$typelibguid1 = {((65 66 38 36 32 31 34 65 2d 35 34 64 65 2d 34 31 63 33 2d 62 32 37 66 2d 65 66 63 36 31 64 30 61 63 63 63 33) | (65 00 66 00 38 00 36 00 32 00 31 00 34 00 65 00 2d 00 35 00 34 00 64 00 65 00 2d 00 34 00 31 00 63 00 33 00 2d 00 62 00 32 00 37 00 66 00 2d 00 65 00 66 00 63 00 36 00 31 00 64 00 30 00 61 00 63 00 63 00 63 00 33 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HackTool_MSIL_PXELOOT_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the PXE And Loot project."
		md5 = "82e33011ac34adfcced6cddc8ea56a81"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "5a72a6ff-bae4-57f5-a19b-a4595ac57293"

	strings:
		$typelibguid1 = {((37 38 42 32 31 39 37 42 2d 32 45 35 36 2d 34 32 35 41 2d 39 35 38 35 2d 35 36 45 44 43 32 43 37 39 37 44 36) | (37 00 38 00 42 00 32 00 31 00 39 00 37 00 42 00 2d 00 32 00 45 00 35 00 36 00 2d 00 34 00 32 00 35 00 41 00 2d 00 39 00 35 00 38 00 35 00 2d 00 35 00 36 00 45 00 44 00 43 00 32 00 43 00 37 00 39 00 37 00 44 00 36 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and $typelibguid1
}

rule APT_HackTool_MSIL_ADPassHunt_2 : hardened
{
	meta:
		description = "Detects FireEye's ADPassHunt tool"
		date = "2020-12-02"
		modified = "2020-12-02"
		md5 = "6efb58cf54d1bb45c057efcfbbd68a93"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "a3b12fd7-e82d-5ef0-9125-7c069cd9bec4"

	strings:
		$s1 = {4c 00 44 00 41 00 50 00 3a 00 2f 00 2f 00}
		$s2 = {5b 00 47 00 50 00 50 00 5d 00 20 00 53 00 65 00 61 00 72 00 63 00 68 00 69 00 6e 00 67 00 20 00 66 00 6f 00 72 00 20 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 73 00 20 00 6e 00 6f 00 77 00 2e 00 2e 00 2e 00}
		$s3 = {53 00 65 00 61 00 72 00 63 00 68 00 69 00 6e 00 67 00 20 00 47 00 72 00 6f 00 75 00 70 00 20 00 50 00 6f 00 6c 00 69 00 63 00 79 00 20 00 50 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 73 00 20 00 28 00 47 00 65 00 74 00 2d 00 47 00 50 00 50 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 73 00 20 00 2b 00 20 00 47 00 65 00 74 00 2d 00 47 00 50 00 50 00 41 00 75 00 74 00 6f 00 6c 00 6f 00 67 00 6f 00 6e 00 73 00 29 00 21 00}
		$s4 = {70 00 6f 00 73 00 73 00 69 00 62 00 69 00 6c 00 69 00 74 00 69 00 65 00 73 00 20 00 73 00 6f 00 20 00 66 00 61 00 72 00 29 00 2e 00 2e 00 2e 00}
		$s5 = {5c 00 67 00 72 00 6f 00 75 00 70 00 73 00 2e 00 78 00 6d 00 6c 00}
		$s6 = {46 00 6f 00 75 00 6e 00 64 00 20 00 69 00 6e 00 74 00 65 00 72 00 65 00 73 00 74 00 69 00 6e 00 67 00 20 00 66 00 69 00 6c 00 65 00 3a 00}
		$s7 = {00 47 65 74 44 69 72 65 63 74 6f 72 69 65 73 00}
		$s8 = {00 44 69 72 65 63 74 6f 72 79 49 6e 66 6f 00}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule APT_HackTool_MSIL_ADPassHunt_1 : hardened
{
	meta:
		description = "Detects FireEye's ADPassHunt tool"
		date = "2020-12-02"
		modified = "2020-12-02"
		md5 = "6efb58cf54d1bb45c057efcfbbd68a93"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "736b5300-215b-5314-9234-69ff0050b73e"

	strings:
		$sb1 = { 73 [2] 00 0A 0A 02 6F [2] 00 0A 0B 38 [4] 12 ?? 28 [2] 00 0A 0? 73 [2] 00 0A 0? 0? 0? 6F [2] 00 0A 1? 13 ?? 72 [4] 13 ?? 0? 6F [2] 00 0A 72 [4] 6F [2] 00 0A 1? 3B [4] 11 ?? 72 [4] 28 [2] 00 0A 13 ?? 0? 72 [4] 6F [2] 00 0A 6F [2] 00 0A 13 ?? 38 [4] 11 ?? 6F [2] 00 0A 74 [2] 00 01 13 ?? 11 ?? 72 [4] 6F [2] 00 0A 2C ?? 11 ?? 72 [4] 11 ?? 6F [2] 00 0A 72 [4] 6F [2] 00 0A 6F [2] 00 0A 72 [4] 28 [2] 00 0A }
		$sb2 = { 02 1? 8D [2] 00 01 [0-32] 1? 1F 2E 9D 6F [2] 00 0A 72 [4] 0A 0B 1? 0? 2B 2E 0? 0? 9A 0? 0? 72 [4] 6F [2] 00 0A 2D ?? 06 72 [4] 28 [2] 00 0A 0A 06 72 [4] 0? 28 [2] 00 0A 0A 0? 1? 58 0? 0? 0? 8E 69 32 CC 06 2A }

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule APT_HackTool_MSIL_SHARPSACK_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpsack' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "8e344acb-73c4-5509-be9d-85cf6fe94445"

	strings:
		$typelibguid0 = {((31 39 34 36 38 30 38 61 2d 31 61 30 31 2d 34 30 63 35 2d 39 34 37 62 2d 38 62 34 63 33 33 37 37 66 37 34 32) | (31 00 39 00 34 00 36 00 38 00 30 00 38 00 61 00 2d 00 31 00 61 00 30 00 31 00 2d 00 34 00 30 00 63 00 35 00 2d 00 39 00 34 00 37 00 62 00 2d 00 38 00 62 00 34 00 63 00 33 00 33 00 37 00 37 00 66 00 37 00 34 00 32 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule APT_Loader_Win64_PGF_5 : hardened
{
	meta:
		description = "PGF payload, generated rule based on symfunc/8167a6d94baca72bac554299d7c7f83c"
		md5 = "150224a0ccabce79f963795bf29ec75b"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "4fa4a1d6-cb63-582d-801c-b4c89c44d9ca"

	strings:
		$cond1 = { 4C 89 44 24 18 89 54 24 10 48 89 4C 24 08 48 83 EC 38 48 8B 4C 24 40 FF 15 13 FA FF FF 8B 44 24 48 89 44 24 20 83 7C 24 20 01 74 02 EB 17 48 8B 44 24 40 48 89 05 66 23 00 00 48 8B 4C 24 40 FF 15 EB F9 FF FF B8 01 00 00 00 48 83 C4 38 C3 }
		$cond2 = { 4C 89 44 24 18 89 54 24 10 48 89 4C 24 08 48 83 EC 38 48 8B 4C 24 40 FF 15 A3 FA FF FF 8B 44 24 48 89 44 24 20 83 7C 24 20 01 74 02 EB 17 48 8B 44 24 40 48 89 05 F6 20 00 00 48 8B 4C 24 40 FF 15 7B FA FF FF B8 01 00 00 00 48 83 C4 38 C3 }
		$cond3 = { 4C 89 44 24 18 89 54 24 10 48 89 4C 24 08 48 83 EC 38 48 8B 4C 24 40 FF ?? ?? ?? ?? ?? 8B 44 24 48 89 44 24 20 83 7C 24 2? ?1 74 ?? EB ?? 48 8B 44 24 40 48 ?? ?? ?? ?? ?? ?? 48 8B 4C 24 40 FF ?? ?? ?? ?? ?? B8 01 ?? ?? ?? 48 83 C4 38 C3 }
		$cond4 = { 4C 89 44 24 ?? 89 54 24 ?? 48 89 4C 24 ?? 48 83 EC 38 48 8B 4C 24 ?? FF 15 ?? ?? ?? ?? 8B 44 24 ?? 89 44 24 ?? 83 7C 24 ?? 01 74 ?? EB ?? 48 8B 44 24 ?? 48 89 05 ?? ?? ?? ?? 48 8B 4C 24 ?? FF 15 ?? ?? ?? ?? B8 01 00 00 00 48 83 C4 38 C3 }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) and any of them
}

rule APT_Trojan_Win_REDFLARE_2 : hardened
{
	meta:
		description = "Detects FireEye's REDFLARE tool"
		date = "2020-11-27"
		modified = "2020-11-27"
		md5 = "9529c4c9773392893a8a0ab8ce8f8ce1,05b99d438dac63a5a993cea37c036673"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "84881e5c-05df-5911-af42-ec82e559588c"

	strings:
		$1 = {69 6e 69 74 69 61 6c 69 7a 65}
		$2 = {67 65 74 44 61 74 61}
		$3 = {70 75 74 44 61 74 61}
		$4 = {66 69 6e 69}
		$5 = {43 6f 6f 6b 69 65 3a 20 53 49 44 31 3d 25 73}

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule APT_HackTool_MSIL_DTRIM_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'dtrim' project, which is a modified version of SharpSploit."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "9be695a1-6d18-5952-974c-96a30f035e7a"

	strings:
		$typelibguid0 = {((37 37 36 30 32 34 38 66 2d 39 32 34 37 2d 34 32 30 36 2d 62 65 34 32 2d 61 36 39 35 32 61 61 34 36 64 61 32) | (37 00 37 00 36 00 30 00 32 00 34 00 38 00 66 00 2d 00 39 00 32 00 34 00 37 00 2d 00 34 00 32 00 30 00 36 00 2d 00 62 00 65 00 34 00 32 00 2d 00 61 00 36 00 39 00 35 00 32 00 61 00 61 00 34 00 36 00 64 00 61 00 32 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HackTool_MSIL_SharPivot_2 : hardened
{
	meta:
		description = "Detects FireEye's SharPivot tool"
		md5 = "e4efa759d425e2f26fbc29943a30f5bd"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "8d6d28ce-de3a-5a38-b654-ba1372d47568"

	strings:
		$s1 = {63 6f 73 74 75 72 61}
		$s2 = {63 00 6d 00 64 00 5f 00 73 00 63 00 68 00 74 00 61 00 73 00 6b 00}
		$s3 = {63 00 6d 00 64 00 5f 00 77 00 6d 00 69 00}
		$s4 = {63 00 6d 00 64 00 5f 00 72 00 70 00 63 00}
		$s5 = {47 00 6f 00 6f 00 67 00 6c 00 65 00 55 00 70 00 64 00 61 00 74 00 65 00 54 00 61 00 73 00 6b 00 4d 00 61 00 63 00 68 00 69 00 6e 00 65 00 55 00 41 00}
		$s6 = {73 00 65 00 72 00 76 00 69 00 63 00 65 00 68 00 69 00 6a 00 61 00 63 00 6b 00}
		$s7 = {70 00 6f 00 69 00 73 00 6f 00 6e 00 68 00 61 00 6e 00 64 00 6c 00 65 00 72 00}

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule APT_HackTool_MSIL_REVOLVER_1 : hardened limited
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'revolver' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "8fa5adb7-dc66-51bc-9f60-2308515f33a8"

	strings:
		$typelibguid0 = {((61 38 62 64 62 62 61 34 2d 37 32 39 31 2d 34 39 64 31 2d 39 61 31 62 2d 33 37 32 64 65 34 35 61 39 64 38 38) | (61 00 38 00 62 00 64 00 62 00 62 00 61 00 34 00 2d 00 37 00 32 00 39 00 31 00 2d 00 34 00 39 00 64 00 31 00 2d 00 39 00 61 00 31 00 62 00 2d 00 33 00 37 00 32 00 64 00 65 00 34 00 35 00 61 00 39 00 64 00 38 00 38 00))}
		$typelibguid1 = {((62 32 31 34 64 39 36 32 2d 37 35 39 35 2d 34 34 30 62 2d 61 62 65 66 2d 66 38 33 65 63 64 62 39 39 39 64 32) | (62 00 32 00 31 00 34 00 64 00 39 00 36 00 32 00 2d 00 37 00 35 00 39 00 35 00 2d 00 34 00 34 00 30 00 62 00 2d 00 61 00 62 00 65 00 66 00 2d 00 66 00 38 00 33 00 65 00 63 00 64 00 62 00 39 00 39 00 39 00 64 00 32 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule APT_Keylogger_Win64_REDFLARE_1 : hardened
{
	meta:
		date = "2020-12-01"
		modified = "2020-12-01"
		md5 = "fbefb4074f1672a3c29c1a47595ea261"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "3c980f5a-c775-5c25-ba28-91a93a1b9a85"

	strings:
		$create_window = { 41 B9 00 00 CF 00 [4-40] 33 C9 [2-10] 00 00 00 80 [2-10] 00 00 00 80 [2-10] 00 00 00 80 [2-10] 00 00 00 80 FF 15 }
		$keys_check = { B9 14 00 00 00 FF 15 [4-8] B9 10 00 00 00 FF 15 [4] BE 00 80 FF FF 66 85 C6 75 ?? B9 A0 00 00 00 FF 15 [4] 66 85 C6 75 ?? B9 A1 00 00 00 FF 15 [4] 66 85 C6 74 }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) and all of them
}

rule APT_HackTool_Win64_EXCAVATOR_1 : hardened
{
	meta:
		date = "2020-11-30"
		modified = "2020-11-30"
		md5 = "6a9a114928554c26675884eeb40cc01b"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "e593b589-747d-53c2-a39a-57485e4f7641"

	strings:
		$api1 = {50 73 73 43 61 70 74 75 72 65 53 6e 61 70 73 68 6f 74}
		$api2 = {4d 69 6e 69 44 75 6d 70 57 72 69 74 65 44 75 6d 70}
		$dump = { BA FD 03 00 AC [0-8] 41 B8 1F 00 10 00 48 8B ?? FF 15 [4] 85 C0 0F 85 [2] 00 00 [0-2] 48 8D 05 [5] 89 ?? 24 30 ( C7 44 24 28 80 00 00 00 48 8D 0D ?? ?? ?? ?? | 48 8D 0D ?? ?? ?? ?? C7 44 24 28 80 00 00 00 ) 45 33 C9 [0-5] 45 33 C0 C7 44 24 20 01 00 00 00 BA 00 00 00 10 [0-10] FF 15 [4] 48 8B ?? 48 83 F8 FF ( 74 | 0F 84 ) [1-4] 48 8B 4C 24 ?? 48 8D 44 24 ?? 48 89 44 24 30 ( 41 B9 02 00 00 00 | 44 8D 4D 02 ) ?? 89 ?? 24 28 4C 8B ?? 8B [2] 89 ?? 24 20 FF 15 [4] 48 8B ?? FF 15 [4] 48 8B ?? FF 15 [4] FF 15 [4] 48 8B 54 24 ?? 48 8B C8 FF 15 }
		$lsass = { 6C 73 61 73 [6] 73 2E 65 78 [6] 65 }

	condition:
		(( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) ) and all of them
}

rule APT_Loader_Win64_MATRYOSHKA_2 : hardened
{
	meta:
		date = "2020-12-02"
		modified = "2020-12-02"
		description = "matryoshka.rs"
		md5 = "7f8102b789303b7861a03290c79feba0"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		id = "25f916bc-6ee1-5175-903c-4266b0a086e1"

	strings:
		$sb1 = { 4D [2] 00 49 [2] 08 B? 02 00 00 00 31 ?? E8 [4] 48 89 ?? 48 89 ?? 4C 89 ?? 49 89 ?? E8 [4] 4C 89 ?? 48 89 ?? E8 [4] 83 [2] 01 0F 84 [4] 48 89 ?? 48 8B [2] 48 8B [2] 48 89 [5] 48 89 [5] 48 89 [5] 41 B? [4] 4C 89 ?? 31 ?? E8 [4] C7 45 [5] 48 89 ?? 4C 89 ?? E8 [4] 85 C0 }
		$sb2 = { 4C [2] 0F 83 [4] 41 0F [3] 01 41 32 [2] 00 48 8B [5] 48 3B [5] 75 ?? 41 B? 01 00 00 00 4C 89 ?? E8 [4] E9 }
		$si1 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74}
		$si2 = {50 72 6f 63 65 73 73 33 32 4e 65 78 74}

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) and all of them
}

