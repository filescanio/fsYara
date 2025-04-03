rule TA17_293A_malware_1 : hardened
{
	meta:
		description = "inveigh pen testing tools & related artifacts"
		author = "US-CERT Code Analysis Team (modified by Florian Roth)"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
		date = "2017/07/17"
		hash0 = "61C909D2F625223DB2FB858BBDF42A76"
		hash1 = "A07AA521E7CAFB360294E56969EDA5D6"
		hash2 = "BA756DD64C1147515BA2298B6A760260"
		hash3 = "8943E71A8C73B5E343AA9D2E19002373"
		hash4 = "04738CA02F59A5CD394998A99FCD9613"
		hash5 = "038A97B4E2F37F34B255F0643E49FC9D"
		hash6 = "65A1A73253F04354886F375B59550B46"
		hash7 = "AA905A3508D9309A93AD5C0EC26EBC9B"
		hash8 = "5DBEF7BDDAF50624E840CCBCE2816594"
		hash9 = "722154A36F32BA10E98020A8AD758A7A"
		hash10 = "4595DBE00A538DF127E0079294C87DA0"
		id = "297611c9-f4b1-5618-bd43-5a7444365727"

	strings:
		$n1 = {66 69 6c 65 3a 2f 2f}
		$ax1 = {31 38 34 2e 31 35 34 2e 31 35 30 2e 36 36}
		$ax2 = {35 2e 31 35 33 2e 35 38 2e 34 35}
		$ax3 = {36 32 2e 38 2e 31 39 33 2e 32 30 36}
		$ax4 = {2f 70 73 68 61 72 65 31 2f 69 63 6f 6e}
		$ax5 = {2f 61 6d 65 5f 69 63 6f 6e 2e 70 6e 67}
		$ax6 = {2f 31 2f 72 65 65 5f 73 74 61 74 2f 70}
		$s1 = {28 67 2e 63 68 61 72 43 6f 64 65 41 74 28 63 29 5e 6c 5b 28 6c 5b 62 5d 2b 6c 5b 65 5d 29 25 32 35 36 5d 29}
		$s2 = {66 6f 72 28 62 3d 30 3b 32 35 36 3e 62 3b 62 2b 2b 29 6b 5b 62 5d 3d 62 3b 66 6f 72 28 62 3d 30 3b 32 35 36 3e 62 3b 62 2b 2b 29}
		$s3 = {56 58 4e 45 53 57 4a 66 53 6a 59 33 67 72 4b 45 6b 45 6b 52 75 5a 65 53 76 6b 45 3d}
		$s4 = {4e 6c 5a 7a 53 5a 6b 3d}
		$s5 = {57 6c 4a 54 62 31 71 35 6b 61 78 71 5a 61 52 6e 73 65 72 33 73 77 3d 3d}
		$x1 = { 87D081F60C67F5086A003315D49A4000F7D6E8EB12000081F7F01BDD21F7DE }
		$x2 = { 33C42BCB333DC0AD400043C1C61A33C3F7DE33F042C705B5AC400026AF2102 }
		$x3 = {66 72 6f 6d 43 68 61 72 43 6f 64 65 28 64 2e 63 68 61 72 43 6f 64 65 41 74 28 65 29 5e 6b 5b 28 6b 5b 62 5d 2b 6b 5b 68 5d 29 25 32 35 36 5d 29}
		$x4 = {70 73 2e 65 78 65 20 2d 61 63 63 65 70 74 65 75 6c 61 20 5c 25 77 73 25 20 2d 75 20 25 75 73 65 72 25 20 2d 70 20 25 70 61 73 73 25 20 2d 73 20 63 6d 64 20 2f 63 20 6e 65 74 73 74 61 74}
		$x5 = { 22546F6B656E733D312064656C696D733D5C5C222025254920494E20286C6973742E74787429 }
		$x6 = { 68656C6C2E657865202D6E6F65786974202D657865637574696F6E706F6C69637920627970617373202D636F6D6D616E6420222E202E5C496E76656967682E70 }
		$x7 = { 476F206275696C642049443A202266626433373937623163313465306531 }
		$x8 = { 24696E76656967682E7374617475735F71756575652E4164642822507265737320616E79206B657920746F2073746F70207265616C2074696D65 }
		$x9 = { 2F73657474696E67732E786D6CB456616FDB3613FEFE02EF7F10F4798E64C54D06A14ED125F19A225E87C9FD0194485B }
		$x10 = { 6C732F73657474696E67732E786D6C2E72656C7355540500010076A41275780B0001040000000004000000008D90B94E03311086EBF014D6F4D87B48214471D2 }
		$x11 = { 8D90B94E03311086EBF014D6F4D87B48214471D210A41450A0E50146EBD943F8923D41C9DBE3A54A240ACA394A240ACA39 }
		$x12 = { 8C90CD4EEB301085D7BD4F61CDFEDA092150A1BADD005217B040E10146F124B1F09FEC01B56F8FC3AA9558B0B4 }
		$x13 = { 8C90CD4EEB301085D7BD4F61CDFEDA092150A1BADD005217B040E10146F124B1F09FEC01B56F8FC3AA9558B0B4 }
		$x14 = {68 74 74 70 3a 2f 2f 62 69 74 2e 6c 79 2f 32 6d 30 78 38 49 48}

	condition:
		($n1 and 1 of ( $ax* ) ) or 2 of ( $s* ) or 1 of ( $x* )
}

rule TA17_293A_energetic_bear_api_hashing_tool : hardened limited
{
	meta:
		description = "Energetic Bear API Hashing Tool"
		assoc_report = "DHS Report TA17-293A"
		author = "CERT RE Team"
		version = "2"
		id = "4e58800a-9618-5d8b-954c-e843be6002c2"

	strings:
		$api_hash_func_v1 = { 8A 08 84 C9 74 ?? 80 C9 60 01 CB C1 E3 01 03 45 10 EB ED }
		$api_hash_func_v2 = { 8A 08 84 C9 74 ?? 80 C9 60 01 CB C1 E3 01 03 44 24 14 EB EC }
		$api_hash_func_x64 = { 8A 08 84 C9 74 ?? 80 C9 60 48 01 CB 48 C1 E3 01 48 03 45 20 EB EA }
		$http_push = {58 2d 6d 6f 64 65 3a 20 70 75 73 68}
		$http_pop = {58 2d 6d 6f 64 65 3a 20 70 6f 70}

	condition:
		$api_hash_func_v1 or $api_hash_func_v2 or $api_hash_func_x64 and ( uint16( 0 ) == 0x5a4d or $http_push or $http_pop )
}

rule TA17_293A_Query_XML_Code_MAL_DOC_PT_2 : hardened
{
	meta:
		name = "Query_XML_Code_MAL_DOC_PT_2"
		author = "other (modified by Florian Roth)"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
		id = "82b0f28a-94b6-52ab-8fd6-cdc05823ac34"

	strings:
		$dir1 = {77 6f 72 64 2f 5f 72 65 6c 73 2f 73 65 74 74 69 6e 67 73 2e 78 6d 6c 2e 72 65 6c 73}
		$bytes = {8c 90 cd 4e eb 30 10 85 d7}

	condition:
		uint32( 0 ) == 0x04034b50 and $dir1 and $bytes
}

rule TA17_293A_Query_XML_Code_MAL_DOC : hardened
{
	meta:
		name = "Query_XML_Code_MAL_DOC"
		author = "other (modified by Florian Roth)"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
		id = "82b0f28a-94b6-52ab-8fd6-cdc05823ac34"

	strings:
		$dir = {77 6f 72 64 2f 5f 72 65 6c 73 2f}
		$dir2 = {77 6f 72 64 2f 74 68 65 6d 65 2f 74 68 65 6d 65 31 2e 78 6d 6c}
		$style = {77 6f 72 64 2f 73 74 79 6c 65 73 2e 78 6d 6c}

	condition:
		uint32( 0 ) == 0x04034b50 and $dir at 0x0145 and $dir2 at 0x02b7 and $style at 0x08fd
}

rule TA17_293A_Query_Javascript_Decode_Function : hardened
{
	meta:
		name = "Query_Javascript_Decode_Function"
		author = "other (modified by Florian Roth)"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
		id = "bc206ab3-a86b-5abe-ae84-15abab838d4e"

	strings:
		$decode1 = {72 65 70 6C 61 63 65 28 2F 5B 5E 41 2D 5A 61 2D 7A 30 2D 39 5C 2B 5C 2F 5C 3D 5D 2F 67 2C 22 22 29 3B}
		$decode2 = {22 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50 51 52 53 54 55 56 57 58 59 5A 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76 77 78 79 7A 30 31 32 33 34 35 36 37 38 39 2B 2F 3D 22 2E 69 6E 64 65 78 4F 66 28 ?? 2E 63 68 61 72 41 74 28 ?? 2B 2B 29 29}
		$decode3 = {3D ?? 3C 3C 32 7C ?? 3E 3E 34 2C ?? 3D 28 ?? 26 31 35 29 3C 3C 34 7C ?? 3E 3E 32 2C ?? 3D 28 ?? 26 33 29 3C 3C 36 7C ?? 2C ?? 2B 3D [1-2] 53 74 72 69 6E 67 2E 66 72 6F 6D 43 68 61 72 43 6F 64 65 28 ?? 29 2C 36 34 21 3D ?? 26 26 28 ?? 2B 3D 53 74 72 69 6E 67 2E 66 72 6F 6D 43 68 61 72 43 6F 64 65 28 ?? 29}
		$decode4 = {73 75 62 73 74 72 69 6E 67 28 34 2C ?? 2E 6C 65 6E 67 74 68 29}

	condition:
		filesize < 20KB and all of ( $decode* )
}

rule TA17_293A_Hacktool_PS_1 : hardened limited
{
	meta:
		description = "Auto-generated rule"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
		date = "2017-10-21"
		hash1 = "72a28efb6e32e653b656ca32ccd44b3111145a695f6f6161965deebbdc437076"
		id = "e4b92536-fa9a-5a65-8bd6-84c037dfbdce"

	strings:
		$x1 = {24 48 61 73 68 46 6f 72 6d 61 74 20 3d 20 27 24 6b 72 62 35 74 67 73 24 32 33 24 2a 49 44 23 31 32 34 5f 44 49 53 54 49 4e 47 55 49 53 48 45 44 20 4e 41 4d 45 3a 20 43 4e 3d 66 61 6b 65 73 76 63 2c 4f 55 3d 53 65 72 76 69 63 65 2c 4f 55 3d 41 63 63 6f 75 6e 74 73 2c 4f 55 3d 45 6e 74 65 72 70 72 69 73 65 4f 62 6a 65 63 74 73 2c 44 43 3d 61 73 64 66 2c 44 43 3d 70 64 2c 44 43 3d 66}
		$x2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 7d 20 7c 20 57 68 65 72 65 2d 4f 62 6a 65 63 74 20 7b 24 5f 2e 53 61 6d 41 63 63 6f 75 6e 74 4e 61 6d 65 20 2d 6e 6f 74 6d 61 74 63 68 20 27 6b 72 62 74 67 74 27 7d 20 7c 20 47 65 74 2d 53 50 4e 54 69 63 6b 65 74 20 40 47 65 74 53 50 4e 54 69 63 6b 65 74 41 72 67 75 6d 65 6e 74 73 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		( filesize < 80KB and 1 of them )
}

rule TA17_293A_Hacktool_Touch_MAC_modification : hardened limited
{
	meta:
		description = "Auto-generated rule"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
		date = "2017-10-21"
		hash1 = "070d7082a5abe1112615877214ec82241fd17e5bd465e24d794a470f699af88e"
		id = "69240cc0-a04e-544a-b7e3-c5a08c062055"

	strings:
		$s1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 2d 74 20 74 69 6d 65 20 2d 20 75 73 65 20 74 68 65 20 74 69 6d 65 20 73 70 65 63 69 66 69 65 64 20 74 6f 20 75 70 64 61 74 65 20 74 68 65 20 61 63 63 65 73 73 20 61 6e 64 20 6d 6f 64 69 66 69 63 61 74 69 6f 6e 20 74 69 6d 65 73 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 46 61 69 6c 65 64 20 74 6f 20 73 65 74 20 66 69 6c 65 20 74 69 6d 65 73 20 66 6f 72 20 25 73 2e 20 45 72 72 6f 72 3a 20 25 78 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 74 6f 75 63 68 20 5b 2d 61 63 6d 5d 5b 20 2d 72 20 72 65 66 5f 66 69 6c 65 20 7c 20 2d 74 20 74 69 6d 65 5d 20 66 69 6c 65 2e 2e 2e (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s4 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 2d 6d 20 2d 20 63 68 61 6e 67 65 20 74 68 65 20 6d 6f 64 69 66 69 63 61 74 69 6f 6e 20 74 69 6d 65 20 6f 6e 6c 79 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 100KB and 1 of them )
}

rule TA17_293A_Hacktool_Exploit_MS16_032 : hardened limited
{
	meta:
		description = "Auto-generated rule"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
		date = "2017-10-21"
		hash1 = "9b97290300abb68fb48480718e6318ee2cdd4f099aa6438010fb2f44803e0b58"
		id = "4c5838d7-9956-564e-a25c-f2ba5641ac03"

	strings:
		$x1 = {5b 3f 5d 20 54 68 72 65 61 64 20 62 65 6c 6f 6e 67 73 20 74 6f 3a 20 24 28 24 28 47 65 74 2d 50 72 6f 63 65 73 73 20 2d 50 49 44 20 24 28 5b 4b 65 72 6e 65 6c 33 32 5d 3a 3a 47 65 74 50 72 6f 63 65 73 73 49 64 4f 66 54 68 72 65 61 64 28 24 54 68 72 65 61 64 29 29 29}
		$x2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 30 78 30 30 30 30 30 30 30 32 2c 20 22 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 63 6d 64 2e 65 78 65 22 2c 20 22 22 2c (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$x3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 50 6f 77 65 72 53 68 65 6c 6c 20 69 6d 70 6c 65 6d 65 6e 74 61 74 69 6f 6e 20 6f 66 20 4d 53 31 36 2d 30 33 32 2e 20 54 68 65 20 65 78 70 6c 6f 69 74 20 74 61 72 67 65 74 73 20 61 6c 6c 20 76 75 6c 6e 65 72 61 62 6c 65 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$x4 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 49 66 20 77 65 20 63 61 6e 27 74 20 6f 70 65 6e 20 74 68 65 20 70 72 6f 63 65 73 73 20 74 6f 6b 65 6e 20 69 74 27 73 20 61 20 53 59 53 54 45 4d 20 73 68 65 6c 6c 21 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		( filesize < 40KB and 1 of them )
}

import "pe"

rule Imphash_UPX_Packed_Malware_1_TA17_293A : hardened
{
	meta:
		description = "Detects malware based on Imphash of malware used in TA17-293A"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
		date = "2017-10-21"
		hash1 = "a278256fbf2f061cfded7fdd58feded6765fade730374c508adad89282f67d77"
		id = "3ff28f06-8b69-5e8f-ab45-dfa4f6e69812"

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 5000KB and pe.imphash ( ) == "d7d745ea39c8c5b82d5e153d3313096c" )
}

import "pe"

rule Imphash_Malware_2_TA17_293A : HIGHVOL hardened
{
	meta:
		description = "Detects malware based on Imphash of malware used in TA17-293A"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
		date = "2017-10-21"
		score = 60
		id = "5c9f32a3-8c50-5d46-929b-bbe14697540e"

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 5000KB and pe.imphash ( ) == "a8f69eb2cf9f30ea96961c86b4347282" )
}

