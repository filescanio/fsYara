rule APT_HiddenCobra_enc_PK_header : hardened
{
	meta:
		author = "NCCIC trusted 3rd party - Edit: Tobias Michalski"
		incident = "10135536"
		date = "2018-04-12"
		category = "hidden_cobra"
		family = "TYPEFRAME"
		hash0 = "3229a6cea658b1b3ca5ca9ad7b40d8d4"
		reference = "https://www.us-cert.gov/ncas/analysis-reports/AR18-165A"
		description = "Hidden Cobra - Detects trojan with encrypted header"
		id = "5d7001b3-162c-5a97-a740-1b8e33d4aa9e"

	strings:
		$s0 = { 5f a8 80 c5 a0 87 c7 f0 9e e6 }
		$s1 = { 95 f1 6e 9c 3f c1 2c 88 a0 5a }
		$s2 = { ae 1d af 74 c0 f5 e1 02 50 10 }

	condition:
		( uint16( 0 ) == 0x5A4D and uint16( uint32( 0x3c ) ) == 0x4550 ) and any of them
}

rule APT_HiddenCobra_import_obfuscation_2 : hardened
{
	meta:
		author = "NCCIC trusted 3rd party - Edit: Tobias Michalski"
		incident = "10135536"
		date = "2018-04-12"
		category = "hidden_cobra"
		family = "TYPEFRAME"
		hash0 = "bfb41bc0c3856aa0a81a5256b7b8da51"
		reference = "https://www.us-cert.gov/ncas/analysis-reports/AR18-165A"
		description = "Hidden Cobra - Detects remote access trojan"
		id = "bc139580-a55b-514f-8a4e-ca1402ce3ad9"

	strings:
		$s0 = {A6 D6 02 EB 4E B2 41 EB C3 EF 1F}
		$s1 = {B6 DF 01 FD 48 B5 }
		$s2 = {B6 D5 0E F3 4E B5 }
		$s3 = {B7 DF 0E EE }
		$s4 = {B6 DF 03 FC }
		$s5 = {A7 D3 03 FC }

	condition:
		( uint16( 0 ) == 0x5A4D and uint16( uint32( 0x3c ) ) == 0x4550 ) and all of them
}

rule APT_NK_AR18_165A_HiddenCobra_import_deob : hardened
{
	meta:
		author = "NCCIC trusted 3rd party - Edit: Tobias Michalski"
		incident = "10135536"
		date = "2018-04-12"
		category = "hidden_cobra"
		family = "TYPEFRAME"
		md5 = "ae769e62fef4a1709c12c9046301aa5d"
		md5 = "e48fe20eblf5a5887f2ac631fed9ed63"
		reference = "https://www.us-cert.gov/ncas/analysis-reports/AR18-165A"
		description = "Hidden Cobra - Detects installed proxy module as a service"
		id = "f403d589-be35-57a7-9675-f92657c11acc"

	strings:
		$ = { 8a 01 3c 62 7c 0a 3c 79 7f 06 b2 db 2a d0 88 11 8a 41 01 41 84 c0 75 e8}
		$ = { 8A 08 80 F9 62 7C 0B 80 F9 79 7F 06 82 DB 2A D1 88 10 8A 48 01 40 84 C9 75 E6}

	condition:
		( uint16( 0 ) == 0x5A4D and uint16( uint32( 0x3c ) ) == 0x4550 ) and any of them
}

rule APT_NK_AR18_165A_1 : hardened limited
{
	meta:
		description = "Detects APT malware from AR18-165A report by US CERT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.us-cert.gov/ncas/analysis-reports/AR18-165A"
		date = "2018-06-15"
		hash1 = "089e49de61701004a5eff6de65476ed9c7632b6020c2c0f38bb5761bca897359"
		id = "45f5205d-7f69-5646-aef8-f95d139f9720"

	strings:
		$s1 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 6e 00 65 00 74 00 73 00 68 00 2e 00 65 00 78 00 65 00 20 00 61 00 64 00 76 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 20 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 20 00 61 00 64 00 64 00 20 00 72 00 75 00 6c 00 65 00 20 00 6e 00 61 00 6d 00 65 00 3d 00 22 00 50 00 6f 00 72 00 74 00 4f 00 70 00 65 00 6e 00 6e 00 69 00 6e 00 67 00 22 00 20 00 64 00 69 00 72 00 3d 00 69 00 6e 00 20 00 70 00 72 00 6f 00 74 00 6f 00 63 00 6f 00 6c 00 3d 00 74 00 63 00 70 00 20 00 6c 00 6f 00 63 00 61 00 6c 00 70 00 6f 00 72 00 74 00 3d 00 25 00 64 00 20 00 61 00 63 00 74 00 69 00 6f 00 6e 00 3d 00 61 00 6c 00 6c 00 6f 00 77 00 20 00 65 00 6e 00 61 00 62 00 6c 00 65 00 3d 00 79 00 65 00 73 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s2 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 6e 00 65 00 74 00 73 00 68 00 2e 00 65 00 78 00 65 00 20 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 20 00 61 00 64 00 64 00 20 00 70 00 6f 00 72 00 74 00 6f 00 70 00 65 00 6e 00 69 00 6e 00 67 00 20 00 54 00 43 00 50 00 20 00 25 00 64 00 20 00 22 00 50 00 6f 00 72 00 74 00 4f 00 70 00 65 00 6e 00 6e 00 69 00 6e 00 67 00 22 00 20 00 65 00 6e 00 61 00 62 00 6c 00 65 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 2000KB and 1 of them
}

