rule SUSP_LNK_Embedded_WordDoc : hardened
{
	meta:
		author = "Greg Lesnewich"
		description = "check for LNK files with indications of the Word program or an embedded doc"
		date = "2023-01-02"
		version = "1.0"
		hash = "120ca851663ef0ebef585d716c9e2ba67bd4870865160fec3b853156be1159c5"
		DaysofYARA = "2/100"
		id = "9677d41a-9d29-510c-98cd-122dc0ca9606"

	strings:
		$doc_header = {D0 CF 11 E0 A1 B1 1A E1}
		$icon_loc = {((43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 4d 69 63 72 6f 73 6f 66 74 20 4f 66 66 69 63 65 5c 4f 66 66 69 63 65 31 36 5c 57 49 4e 57 4f 52 44 2e 65 78 65) | (43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 4f 00 66 00 66 00 69 00 63 00 65 00 5c 00 4f 00 66 00 66 00 69 00 63 00 65 00 31 00 36 00 5c 00 57 00 49 00 4e 00 57 00 4f 00 52 00 44 00 2e 00 65 00 78 00 65 00))}

	condition:
		uint32be( 0x0 ) == 0x4C000000 and filesize > 10KB and any of them
}

rule SUSP_LNK_SmallScreenSize : hardened
{
	meta:
		author = "Greg Lesnewich"
		description = "check for LNKs that have a screen buffer size and WindowSize dimensions of 1x1"
		date = "2023-01-01"
		version = "1.0"
		DaysofYARA = "1/100"
		id = "6194a76b-36d6-51d1-8d53-2e11172e29d2"

	strings:
		$dimensions = {02 00 00 A0 ?? 00 ?? ?? 01 00 01 00 01}

	condition:
		uint32be( 0x0 ) == 0x4c000000 and all of them
}

rule MAL_Janicab_LNK : hardened
{
	meta:
		author = "Greg Lesnewich"
		description = "detect LNK files used in Janicab infection chain"
		date = "2023-01-01"
		version = "1.0"
		hash = "0c7e8427ee61672568983e51bf03e0bcf6f2e9c01d2524d82677b20264b23a3f"
		hash = "22ede766fba7551ad0b71ef568d0e5022378eadbdff55c4a02b42e63fcb3b17c"
		hash = "4920e6506ca557d486e6785cb5f7e4b0f4505709ffe8c30070909b040d3c3840"
		hash = "880607cc2da4c3213ea687dabd7707736a879cc5f2f1d4accf79821e4d24d870"
		hash = "f4610b65eba977b3d13eba5da0e38788a9e796a3e9775dd2b8e37b3085c2e1af"
		DaysofYARA = "1/100"
		id = "c21844d3-eeee-530e-a69c-b7f604616f0b"

	strings:
		$j_pdf1 = {((25 50 44 46 2d 31 2e 35) | (25 00 50 00 44 00 46 00 2d 00 31 00 2e 00 35 00))}
		$j_cmd = {((5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 63 6d 64 2e 65 78 65) | (5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00))}
		$j_pdf_stream = {((65 6e 64 73 74 72 65 61 6d) | (65 00 6e 00 64 00 73 00 74 00 72 00 65 00 61 00 6d 00))}
		$j_pdb_obj = {((65 6e 64 6f 62 6a) | (65 00 6e 00 64 00 6f 00 62 00 6a 00))}
		$dimensions = {02 00 00 A0 ?? 00 ?? ?? 01 00 01 00 01}

	condition:
		uint32be( 0x0 ) == 0x4C000000 and $dimensions and 2 of ( $j_* )
}

rule SUSP_ELF_Invalid_Version : hardened
{
	meta:
		desc = "Identify ELF file that has mangled header info."
		author = "@shellcromancer"
		version = "0.1"
		score = 55
		last_modified = "2023.01.01"
		reference = "https://n0.lol/ebm/1.html"
		reference = "https://tmpout.sh/1/1.html"
		hash = "05379bbf3f46e05d385bbd853d33a13e7e5d7d50"
		id = "5bd97fdd-0912-5f9b-877c-91fff9b98dea"

	condition:
		( uint32( 0 ) == 0x464c457f and uint8( 0x6 ) > 1 )
}

rule MAL_ELF_TorchTriton : hardened
{
	meta:
		author = "Silas Cutler"
		description = "Detection for backdoor (TorchTriton) distributed with a nightly build of PyTorch"
		date = "2023-01-02"
		version = "1.0"
		hash = "2385b29489cd9e35f92c072780f903ae2e517ed422eae67246ae50a5cc738a0e"
		reference = "https://www.bleepingcomputer.com/news/security/pytorch-discloses-malicious-dependency-chain-compromise-over-holidays/"
		DaysofYARA = "2/100"
		id = "85e98ee7-30bf-554f-a0ac-9df263e6dfe4"

	strings:
		$error = {66 61 69 6c 65 64 20 74 6f 20 73 65 6e 64 20 70 61 63 6b 65 74}
		$aes_key = {67 49 64 6b 38 74 7a 72 48 4c 4f 4d 29 6d 50 59 2d 52 29 51 67 47 5b 3b 79 52 58 59 43 5a 46 55}
		$aes_iv = {3f 42 56 73 4e 71 4c 5d 53 2e 4e 69}
		$func01 = {73 70 6c 69 74 49 6e 74 6f 44 6f 6d 61 69 6e 73 28}
		$func02 = {70 61 63 6b 61 67 65 46 6f 72 54 72 61 6e 73 70 6f 72 74}
		$func03 = {67 61 74 68 65 72 46 69 6c 65 73}
		$func04 = {76 6f 69 64 20 73 65 6e 64 46 69 6c 65 28}
		$domain = {26 7a 2d 25 60 2d 28 2a}

	condition:
		uint32( 0 ) == 0x464c457f and ( ( all of ( $aes_* ) ) or ( all of ( $func* ) and $error ) or ( $domain and 2 of them ) )
}

rule MAL_GOLDBACKDOOR_LNK : hardened
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-01-02"
		version = "1.0"
		hash = "120ca851663ef0ebef585d716c9e2ba67bd4870865160fec3b853156be1159c5"
		reference = "https://stairwell.com/wp-content/uploads/2022/04/Stairwell-threat-report-The-ink-stained-trail-of-GOLDBACKDOOR.pdf"
		DaysofYARA = "2/100"
		id = "9a80f875-4843-535c-9f2b-b04da55713b1"

	strings:
		$doc_header = {D0 CF 11 E0 A1 B1 1A E1}
		$doc_icon_loc = {((43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 4d 69 63 72 6f 73 6f 66 74 20 4f 66 66 69 63 65 5c 4f 66 66 69 63 65 31 36 5c 57 49 4e 57 4f 52 44 2e 65 78 65) | (43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 4f 00 66 00 66 00 69 00 63 00 65 00 5c 00 4f 00 66 00 66 00 69 00 63 00 65 00 31 00 36 00 5c 00 57 00 49 00 4e 00 57 00 4f 00 52 00 44 00 2e 00 65 00 78 00 65 00))}
		$script_apionedrivecom_hex_enc_str = {36 00 31 00 37 00 30 00 36 00 39 00 32 00 65 00 36 00 66 00 36 00 65 00 36 00 35 00 36 00 34 00 37 00 32 00 36 00 39 00 37 00 36 00 36 00 35 00 32 00 65 00 36 00 33 00 36 00 66 00 36 00 64 00}
		$script_kernel32dll_hex_enc_str = {36 00 62 00 36 00 35 00 37 00 32 00 36 00 65 00 36 00 35 00 36 00 63 00 33 00 33 00 33 00 32 00 32 00 65 00 36 00 34 00 36 00 63 00 36 00 63 00}
		$script_GlobalAlloc_hex_enc_str = {34 00 37 00 36 00 63 00 36 00 66 00 36 00 32 00 36 00 31 00 36 00 63 00 34 00 31 00 36 00 63 00 36 00 63 00 36 00 66 00 36 00 33 00}
		$script_VirtualProtect_hex_enc_str = {35 00 36 00 36 00 39 00 37 00 32 00 37 00 34 00 37 00 35 00 36 00 31 00 36 00 63 00 35 00 30 00 37 00 32 00 36 00 66 00 37 00 34 00 36 00 35 00 36 00 33 00 37 00 34 00}
		$script_WriteByte_hex_enc_str = {35 00 37 00 37 00 32 00 36 00 39 00 37 00 34 00 36 00 35 00 34 00 32 00 37 00 39 00 37 00 34 00 36 00 35 00}
		$script_CreateThread_hex_enc_str = {34 00 33 00 37 00 32 00 36 00 35 00 36 00 31 00 37 00 34 00 36 00 35 00 35 00 34 00 36 00 38 00 37 00 32 00 36 00 35 00 36 00 31 00 36 00 34 00}

	condition:
		uint32be( 0x0 ) == 0x4C000000 and 1 of ( $doc* ) and 2 of ( $script* )
}

rule MAL_EXE_LockBit_v2 : hardened
{
	meta:
		author = "Silas Cutler, modified by Florian Roth"
		description = "Detection for LockBit version 2.x from 2011"
		date = "2023-01-01"
		modified = "2023-01-06"
		version = "1.0"
		score = 80
		hash = "00260c390ffab5734208a7199df0e4229a76261c3f5b7264c4515acb8eb9c2f8"
		DaysofYARA = "1/100"
		id = "a2c27110-e63b-5f93-88a0-98c12811e8b4"

	strings:
		$s_ransom_note01 = {74 00 68 00 61 00 74 00 20 00 69 00 73 00 20 00 6c 00 6f 00 63 00 61 00 74 00 65 00 64 00 20 00 69 00 6e 00 20 00 65 00 76 00 65 00 72 00 79 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 66 00 6f 00 6c 00 64 00 65 00 72 00 2e 00}
		$s_ransom_note02 = {57 00 6f 00 75 00 6c 00 64 00 20 00 79 00 6f 00 75 00 20 00 6c 00 69 00 6b 00 65 00 20 00 74 00 6f 00 20 00 65 00 61 00 72 00 6e 00 20 00 6d 00 69 00 6c 00 6c 00 69 00 6f 00 6e 00 73 00 20 00 6f 00 66 00 20 00 64 00 6f 00 6c 00 6c 00 61 00 72 00 73 00 3f 00}
		$x_ransom_tox = {33 00 30 00 38 00 35 00 42 00 38 00 39 00 41 00 30 00 43 00 35 00 31 00 35 00 44 00 32 00 46 00 42 00 31 00 32 00 34 00 44 00 36 00 34 00 35 00 39 00 30 00 36 00 46 00 35 00 44 00 33 00 44 00 41 00 35 00 43 00 42 00 39 00 37 00 43 00 45 00 42 00 45 00 41 00 39 00 37 00 35 00 39 00 35 00 39 00 41 00 45 00 34 00 46 00 39 00 35 00 33 00 30 00 32 00 41 00 30 00 34 00 45 00 31 00 44 00 37 00 30 00 39 00 43 00 33 00 43 00 34 00 41 00 45 00 39 00 42 00 37 00}
		$x_ransom_url = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6c 00 6f 00 63 00 6b 00 62 00 69 00 74 00 61 00 70 00 74 00 36 00 76 00 78 00 35 00 37 00 74 00 33 00 65 00 65 00 71 00 6a 00 6f 00 66 00 77 00 67 00 63 00 67 00 6c 00 6d 00 75 00 74 00 72 00 33 00 61 00 33 00 35 00 6e 00 79 00 67 00 76 00 6f 00 6b 00 6a 00 61 00 35 00 75 00 75 00 63 00 63 00 69 00 70 00 34 00 79 00 6b 00 79 00 64 00 2e 00 6f 00 6e 00 69 00 6f 00 6e 00}
		$s_str1 = {41 00 63 00 74 00 69 00 76 00 65 00 3a 00 5b 00 20 00 25 00 64 00 20 00 5b 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 43 00 6f 00 6d 00 70 00 6c 00 65 00 74 00 65 00 64 00 3a 00 5b 00 20 00 25 00 64 00}
		$x_str2 = {((5c 4c 6f 63 6b 42 69 74 5f 52 61 6e 73 6f 6d 77 61 72 65 2e 68 74 61) | (5c 00 4c 00 6f 00 63 00 6b 00 42 00 69 00 74 00 5f 00 52 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 2e 00 68 00 74 00 61 00))}
		$s_str2 = {((52 61 6e 73 6f 6d 77 61 72 65 2e 68 74 61) | (52 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 2e 00 68 00 74 00 61 00))}

	condition:
		uint16( 0 ) == 0x5A4D and ( 1 of ( $x* ) or 2 of them ) or 3 of them
}

import "pe"

rule MAL_EXE_PrestigeRansomware : hardened
{
	meta:
		author = "Silas Cutler, modfied by Florian Roth"
		description = "Detection for Prestige Ransomware"
		date = "2023-01-04"
		modified = "2023-01-06"
		version = "1.0"
		score = 80
		reference = "https://www.microsoft.com/en-us/security/blog/2022/10/14/new-prestige-ransomware-impacts-organizations-in-ukraine-and-poland/"
		hash = "5fc44c7342b84f50f24758e39c8848b2f0991e8817ef5465844f5f2ff6085a57"
		DaysofYARA = "4/100"
		id = "5ac8033a-8b15-5abe-89d5-018a4fef9ab5"

	strings:
		$x_ransom_email = {50 00 72 00 65 00 73 00 74 00 69 00 67 00 65 00 2e 00 72 00 61 00 6e 00 75 00 73 00 6f 00 6d 00 65 00 77 00 61 00 72 00 65 00 40 00 50 00 72 00 6f 00 74 00 6f 00 6e 00 2e 00 6d 00 65 00}
		$x_reg_ransom_note = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 72 00 65 00 67 00 2e 00 65 00 78 00 65 00 20 00 61 00 64 00 64 00 20 00 48 00 4b 00 43 00 52 00 5c 00 65 00 6e 00 63 00 5c 00 73 00 68 00 65 00 6c 00 6c 00 5c 00 6f 00 70 00 65 00 6e 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00 2f 00 76 00 65 00 20 00 2f 00 74 00 20 00 52 00 45 00 47 00 5f 00 53 00 5a 00 20 00 2f 00 64 00 20 00 22 00 43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 4e 00 6f 00 74 00 65 00 70 00 61 00 64 00 2e 00 65 00 78 00 65 00 20 00 43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 50 00 75 00 62 00 6c 00 69 00 63 00 5c 00 52 00 45 00 41 00 44 00 4d 00 45 00 22 00 20 00 2f 00 66 00}
		$ransom_message01 = {54 00 6f 00 20 00 64 00 65 00 63 00 72 00 79 00 70 00 74 00 20 00 61 00 6c 00 6c 00 20 00 74 00 68 00 65 00 20 00 64 00 61 00 74 00 61 00 2c 00 20 00 79 00 6f 00 75 00 20 00 77 00 69 00 6c 00 6c 00 20 00 6e 00 65 00 65 00 64 00 20 00 74 00 6f 00 20 00 70 00 75 00 72 00 63 00 68 00 61 00 73 00 65 00 20 00 6f 00 75 00 72 00 20 00 64 00 65 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 20 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 2e 00}
		$ransom_message02 = {43 00 6f 00 6e 00 74 00 61 00 63 00 74 00 20 00 75 00 73 00 20 00 7b 00 7d 00 2e 00 20 00 49 00 6e 00 20 00 74 00 68 00 65 00 20 00 6c 00 65 00 74 00 74 00 65 00 72 00 2c 00 20 00 74 00 79 00 70 00 65 00 20 00 79 00 6f 00 75 00 72 00 20 00 49 00 44 00 20 00 3d 00 20 00 7b 00 3a 00 58 00 7d 00 2e 00}
		$ransom_message03 = {2d 00 20 00 44 00 6f 00 20 00 6e 00 6f 00 74 00 20 00 74 00 72 00 79 00 20 00 74 00 6f 00 20 00 64 00 65 00 63 00 72 00 79 00 70 00 74 00 20 00 79 00 6f 00 75 00 72 00 20 00 64 00 61 00 74 00 61 00 20 00 75 00 73 00 69 00 6e 00 67 00 20 00 74 00 68 00 69 00 72 00 64 00 20 00 70 00 61 00 72 00 74 00 79 00 20 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 2c 00 20 00 69 00 74 00 20 00 6d 00 61 00 79 00 20 00 63 00 61 00 75 00 73 00 65 00 20 00 70 00 65 00 72 00 6d 00 61 00 6e 00 65 00 6e 00 74 00 20 00 64 00 61 00 74 00 61 00 20 00 6c 00 6f 00 73 00 73 00 2e 00}
		$ransom_message04 = {2d 00 20 00 44 00 6f 00 20 00 6e 00 6f 00 74 00 20 00 6d 00 6f 00 64 00 69 00 66 00 79 00 20 00 6f 00 72 00 20 00 72 00 65 00 6e 00 61 00 6d 00 65 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 66 00 69 00 6c 00 65 00 73 00 2e 00 20 00 59 00 6f 00 75 00 20 00 77 00 69 00 6c 00 6c 00 20 00 6c 00 6f 00 73 00 65 00 20 00 74 00 68 00 65 00 6d 00 2e 00}

	condition:
		uint16( 0 ) == 0x5A4D and ( 1 of ( $x* ) or 2 of them or pe.imphash ( ) == "a32bbc5df4195de63ea06feb46cd6b55" )
}

rule MAL_EXE_RoyalRansomware : hardened
{
	meta:
		author = "Silas Cutler, modfied by Florian Roth"
		description = "Detection for Royal Ransomware seen Dec 2022"
		date = "2023-01-03"
		version = "1.0"
		hash = "a8384c9e3689eb72fa737b570dbb53b2c3d103c62d46747a96e1e1becf14dfea"
		DaysofYARA = "3/100"
		score = 100
		id = "f83316f7-b8c4-5907-a38e-80535215e7ef"

	strings:
		$x_ext = {2e 00 72 00 6f 00 79 00 61 00 6c 00 5f 00}
		$x_fname = {72 6f 79 61 6c 5f 64 6c 6c 2e 64 6c 6c}
		$s_readme = {52 00 45 00 41 00 44 00 4d 00 45 00 2e 00 54 00 58 00 54 00}
		$s_cli_flag01 = {2d 00 6e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 6f 00 6e 00 6c 00 79 00}
		$s_cli_flag02 = {2d 00 6c 00 6f 00 63 00 61 00 6c 00 6f 00 6e 00 6c 00 79 00}
		$x_ransom_msg01 = {49 66 20 79 6f 75 20 61 72 65 20 72 65 61 64 69 6e 67 20 74 68 69 73 2c 20 69 74 20 6d 65 61 6e 73 20 74 68 61 74 20 79 6f 75 72 20 73 79 73 74 65 6d 20 77 65 72 65 20 68 69 74 20 62 79 20 52 6f 79 61 6c 20 72 61 6e 73 6f 6d 77 61 72 65 2e}
		$x_ransom_msg02 = {54 72 79 20 52 6f 79 61 6c 20 74 6f 64 61 79 20 61 6e 64 20 65 6e 74 65 72 20 74 68 65 20 6e 65 77 20 65 72 61 20 6f 66 20 64 61 74 61 20 73 65 63 75 72 69 74 79 21}
		$x_onion_site = {68 74 74 70 3a 2f 2f 72 6f 79 61 6c 32 78 74 68 69 67 33 6f 75 35 68 64 37 7a 73 6c 69 71 61 67 79 36 79 79 67 6b 32 63 64 65 6c 61 78 74 6e 69 32 66 79 61 64 36 64 70 6d 70 78 65 64 69 64 2e 6f 6e 69 6f 6e 2f}

	condition:
		uint16( 0 ) == 0x5A4D and ( 2 of ( $x* ) or 5 of them )
}

rule MAL_PY_Dimorf : hardened
{
	meta:
		author = "Silas Cutler"
		description = "Detection for Dimorf ransomeware"
		date = "2023-01-03"
		version = "1.0"
		reference = "https://github.com/Ort0x36/Dimorf"
		id = "78b53433-6926-58cd-8ec0-2195af803aab"

	strings:
		$func01 = {64 65 66 20 66 69 6e 64 5f 61 6e 64 5f 65 6e 63 72 79 70 74}
		$func02 = {64 65 66 20 63 68 65 63 6b 5f 6f 73}
		$comment01 = {63 68 65 63 6b 73 20 69 66 20 74 68 65 20 75 73 65 72 20 68 61 73 20 70 65 72 6d 69 73 73 69 6f 6e 20 6f 6e 20 74 68 65 20 66 69 6c 65 2e}
		$misc01 = {6c 6f 67 5f 64 69 6d 6f 72 66 2e 6c 6f 67}
		$misc02 = {2e 64 69 6d 6f 72 66}

	condition:
		all of them
}

