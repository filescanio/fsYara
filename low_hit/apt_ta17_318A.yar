rule TA17_318A_rc4_stack_key_fallchill : hardened
{
	meta:
		description = "HiddenCobra FallChill - rc4_stack_key"
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-318B"
		date = "2017-11-15"
		id = "0a2afcab-f540-592f-aa75-64c0a13d26f3"

	strings:
		$stack_key = { 0d 06 09 2a ?? ?? ?? ?? 86 48 86 f7 ?? ?? ?? ?? 0d 01 01 01 ?? ?? ?? ?? 05 00 03 82 41 8b c9 41 8b d1 49 8b 40 08 48 ff c2 88 4c 02 ff ff c1 81 f9 00 01 00 00 7c eb }

	condition:
		( uint16( 0 ) == 0x5A4D and uint16( uint32( 0x3c ) ) == 0x4550 ) and $stack_key
}

rule TA17_318A_success_fail_codes_fallchill : hardened
{
	meta:
		description = "HiddenCobra FallChill - success_fail_codes"
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-318B"
		date = "2017-11-15"
		id = "f2390b03-238e-5ae6-af85-e5dd5790362f"

	strings:
		$s0 = { 68 7a 34 12 00 }
		$s1 = { ba 7a 34 12 00 }
		$f0 = { 68 5c 34 12 00 }
		$f1 = { ba 5c 34 12 00 }

	condition:
		( uint16( 0 ) == 0x5A4D and uint16( uint32( 0x3c ) ) == 0x4550 ) and ( ( $s0 and $f0 ) or ( $s1 and $f1 ) )
}

import "pe"

rule HiddenCobra_FallChill_1 : hardened
{
	meta:
		description = "Auto-generated rule"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-318A"
		date = "2017-11-15"
		hash1 = "a606716355035d4a1ea0b15f3bee30aad41a2c32df28c2d468eafd18361d60d6"
		id = "5bbeb5ba-93d7-5903-9132-749afe5776ae"

	strings:
		$s1 = {52 00 45 00 47 00 53 00 56 00 52 00 33 00 32 00 2e 00 45 00 58 00 45 00 2e 00 4d 00 55 00 49 00}
		$s2 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 20 00 41 00 6c 00 6c 00 20 00 72 00 69 00 67 00 68 00 74 00 73 00 20 00 72 00 65 00 73 00 65 00 72 00 76 00 65 00 64 00 2e 00}
		$s3 = {63 00 25 00 73 00 64 00 2e 00 65 00 25 00 73 00 63 00 20 00 25 00 73 00 20 00 3e 00 20 00 22 00 25 00 73 00 22 00 20 00 32 00 3e 00 26 00 31 00}
		$s4 = {22 20 67 6f 74 6f 20 4c 6f 6f 70}
		$e1 = {78 6f 6c 68 76 68 6c 78 70 76 67}
		$e2 = {74 76 67 73 6c 68 67 79 62 6d 61 6e 76}
		$e3 = {43 69 76 61 67 76 54 6c 6c 6f 73 76 6f 6b 33 32 53 6d 61 6b 68 73 6c 67}
		$e4 = {47 76 67 43 66 69 69 76 6d 67 44 72 69 76 78 67 6c 69 62 57}
		$e5 = {4f 6b 76 6d 50 69 6c 78 76 68 68 54 6c 70 76 6d}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 300KB and ( pe.imphash ( ) == "6135d9bc3591ae7bc72d070eadd31755" or 3 of ( $s* ) or 4 of them )
}

import "pe"

rule HiddenCobra_FallChill_2 : hardened
{
	meta:
		description = "Auto-generated rule"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-318A"
		date = "2017-11-15"
		hash1 = "0a118eb23399000d148186b9079fa59caf4c3faa7e7a8f91533e467ac9b6ff41"
		id = "c343e8e4-0785-5a47-99c1-98b189f4aaa0"

	strings:
		$s1 = {25 00 73 00 5c 00 25 00 73 00 2e 00 64 00 6c 00 6c 00}
		$s2 = {79 75 72 64 6b 72 2e 64 6c 6c}
		$s3 = {63 00 25 00 73 00 64 00 2e 00 65 00 25 00 73 00 63 00 20 00 25 00 73 00 20 00 3e 00 20 00 22 00 25 00 73 00 22 00 20 00 32 00 3e 00 26 00 31 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 500KB and ( pe.imphash ( ) == "cb36dcb9909e29a38c387b8a87e7e4ed" or ( 2 of them ) )
}

