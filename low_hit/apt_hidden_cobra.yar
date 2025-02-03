rule HiddenCobra_Rule_1 : hardened
{
	meta:
		description = "Detects Hidden Cobra Malware"
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-164A"
		date = "2017-06-13"
		id = "921c027e-fac3-5419-b0a6-5043f5cde466"

	strings:
		$rsaKey = {7B 4E 1E A7 E9 3F 36 4C DE F4 F0 99 C4 D9 B7 94
            A1 FF F2 97 D3 91 13 9D C0 12 02 E4 4C BB 6C 77
            48 EE 6F 4B 9B 53 60 98 45 A5 28 65 8A 0B F8 39
            73 D7 1A 44 13 B3 6A BB 61 44 AF 31 47 E7 87 C2
            AE 7A A7 2C 3A D9 5C 2E 42 1A A6 78 FE 2C AD ED
            39 3F FA D0 AD 3D D9 C5 3D 28 EF 3D 67 B1 E0 68
            3F 58 A0 19 27 CC 27 C9 E8 D8 1E 7E EE 91 DD 13
            B3 47 EF 57 1A CA FF 9A 60 E0 64 08 AA E2 92 D0}

	condition:
		all of them
}

rule HiddenCobra_Rule_3 : hardened
{
	meta:
		description = "Detects Hidden Cobra Malware"
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-164A"
		date = "2017-06-13"
		id = "39c7e039-4b07-575d-a93a-539ecc4e63d8"

	strings:
		$randomUrlBuilder = { 83 EC 48 53 55 56 57 8B 3D ?? ?? ?? ?? 33 C0 C7
         44 24 28 B4 6F 41 00 C7 44 24 2C B0 6F 41 00 C7 44 24 30 AC 6F 41
         00 C7 44 24 34 A8 6F 41 00 C7 44 24 38 A4 6F 41 00 C7 44 24 3C A0
         6F 41 00 C7 44 24 40 9C 6F 41 00 C7 44 24 44 94 6F 41 00 C7 44 24
         48 8C 6F 41 00 C7 44 24 4C 88 6F 41 00 C7 44 24 50 80 6F 41 00 89
         44 24 54 C7 44 24 10 7C 6F 41 00 C7 44 24 14 78 6F 41 00 C7 44 24
         18 74 6F 41 00 C7 44 24 1C 70 6F 41 00 C7 44 24 20 6C 6F 41 00 89
         44 24 24 FF D7 99 B9 0B 00 00 00 F7 F9 8B 74 94 28 BA 9C 6F 41 00
         66 8B 06 66 3B 02 74 34 8B FE 83 C9 FF 33 C0 8B 54 24 60 F2 AE 8B
         6C 24 5C A1 ?? ?? ?? ?? F7 D1 49 89 45 00 8B FE 33 C0 8D 5C 11 05
         83 C9 FF 03 DD F2 AE F7 D1 49 8B FE 8B D1 EB 78 FF D7 99 B9 05 00
         00 00 8B 6C 24 5C F7 F9 83 C9 FF 33 C0 8B 74 94 10 8B 54 24 60 8B
         FE F2 AE F7 D1 49 BF 60 6F 41 00 8B D9 83 C9 FF F2 AE F7 D1 8B C2
         49 03 C3 8B FE 8D 5C 01 05 8B 0D ?? ?? ?? ?? 89 4D 00 83 C9 FF 33
         C0 03 DD F2 AE F7 D1 49 8D 7C 2A 05 8B D1 C1 E9 02 F3 A5 8B CA 83
         E1 03 F3 A4 BF 60 6F 41 00 83 C9 FF F2 AE F7 D1 49 BE 60 6F 41 00
         8B D1 8B FE 83 C9 FF 33 C0 F2 AE F7 D1 49 8B FB 2B F9 8B CA 8B C1
         C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8B 7C 24 60 8D 75 04 57 56 E8
         ?? ?? ?? ?? 83 C4 08 C6 04 3E 2E 8B C5 C6 03 00 5F 5E 5D 5B 83 C4
         48 C3 }

	condition:
		$randomUrlBuilder
}

rule APT_HiddenCobra_GhostSecret_1 : hardened
{
	meta:
		description = "Detects Hidden Cobra Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securingtomorrow.mcafee.com/mcafee-labs/analyzing-operation-ghostsecret-attack-seeks-to-steal-data-worldwide/"
		date = "2018-08-11"
		hash1 = "05a567fe3f7c22a0ef78cc39dcf2d9ff283580c82bdbe880af9549e7014becfc"
		id = "d6955294-84a4-5694-87c9-b5b1c39e0fae"

	strings:
		$s1 = {25 00 73 00 5c 00 25 00 73 00 2e 00 64 00 6c 00 6c 00}
		$s2 = {50 52 4f 58 59 5f 53 56 43 5f 44 4c 4c 2e 64 6c 6c}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 3000KB and all of them
}

rule APT_HiddenCobra_GhostSecret_2 : hardened
{
	meta:
		description = "Detects Hidden Cobra Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securingtomorrow.mcafee.com/mcafee-labs/analyzing-operation-ghostsecret-attack-seeks-to-steal-data-worldwide/"
		date = "2018-08-11"
		hash1 = "45e68dce0f75353c448865b9abafbef5d4ed6492cd7058f65bf6aac182a9176a"
		id = "dab5b0ec-ae89-521e-bbb9-15602db9ed6c"

	strings:
		$s1 = {70 00 69 00 6e 00 67 00 20 00 31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 20 00 2d 00 6e 00 20 00 33 00}
		$s2 = {50 72 6f 63 65 73 73 33 32}
		$s11 = {25 32 64 25 32 64 25 32 64 25 32 64 25 32 64 25 32 64}
		$s12 = {64 00 65 00 6c 00 20 00 2f 00 61 00 20 00 22 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 400KB and all of them
}

rule APT_MAL_HOPLIGHT_NK_HiddenCobra_Apr19_1 : hardened
{
	meta:
		description = "Detects HOPLIGHT malware used by HiddenCobra APT group"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.us-cert.gov/ncas/analysis-reports/AR19-100A"
		date = "2019-04-13"
		hash1 = "d77fdabe17cdba62a8e728cbe6c740e2c2e541072501f77988674e07a05dfb39"
		id = "923a0812-f375-5c0c-a22c-fc71ddcad4e3"

	strings:
		$s1 = {77 77 77 2e 6e 61 76 65 72 2e 63 6f 6d}
		$s2 = {50 6f 6c 61 72 53 53 4c 20 54 65 73 74 20 43 41 30}

	condition:
		filesize < 1000KB and all of them
}

rule APT_MAL_HOPLIGHT_NK_HiddenCobra_Apr19_2 : hardened
{
	meta:
		description = "Detects HOPLIGHT malware used by HiddenCobra APT group"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.us-cert.gov/ncas/analysis-reports/AR19-100A"
		date = "2019-04-13"
		hash1 = "70034b33f59c6698403293cdc28676c7daa8c49031089efa6eefce41e22dccb3"
		id = "9c7fd381-272a-5cfc-a7ee-7f0f9221fa04"

	strings:
		$s1 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 6d 64 6e 65 74 75 73 65}
		$s2 = {25 73 5c 68 69 64 2e 64 6c 6c}
		$s3 = {25 53 79 73 74 65 6d 72 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c}
		$s4 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 73 65 72 76 69 63 65 73 5c 25 73 5c 50 61 72 61 6d 65 74 65 72 73}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 800KB and all of them
}

rule APT_MAL_HOPLIGHT_NK_HiddenCobra_Apr19_3 : hardened
{
	meta:
		description = "Detects HOPLIGHT malware used by HiddenCobra APT group"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.us-cert.gov/ncas/analysis-reports/AR19-100A"
		date = "2019-04-13"
		hash1 = "2151c1977b4555a1761c12f151969f8e853e26c396fa1a7b74ccbaf3a48f4525"
		hash2 = "05feed9762bc46b47a7dc5c469add9f163c16df4ddaafe81983a628da5714461"
		hash3 = "ddea408e178f0412ae78ff5d5adf2439251f68cad4fd853ee466a3c74649642d"
		id = "683b4d64-575a-5bdb-9ad8-e10a60037032"

	strings:
		$s1 = {4f 6c 65 61 75 74 33 32 2e 64 6c 6c}
		$s2 = {50 72 6f 63 65 73 73 33 32 4e 65 78 74 41}
		$s3 = {50 72 6f 63 65 73 73 33 32 46 69 72 73 74 41}
		$s4 = {25 73 52 53 41 20 6b 65 79 20 73 69 7a 65 20 20 3a 20 25 64 20 62 69 74 73}
		$s5 = {65 6d 61 69 6c 41 64 64 72 65 73 73 3d}
		$s6 = {25 73 63 65 72 74 2e 20 76 65 72 73 69 6f 6e 20 3a 20 25 64}
		$s7 = {77 77 77 2e 6e 61 76 65 72 2e 63 6f 6d}
		$x1 = {7a 74 72 65 74 72 74 69 72 65 6f 74 72 65 6f 74 69 65 72 6f 70 74 6b 69 65 72 65 72 74}
		$x2 = {72 65 79 6b 66 67 6b 6f 64 66 67 6b 66 64 73 6b 67 64 66 6f 67 70 64 6f 6b 67 73 64 66 70 67}
		$x3 = {66 6a 69 65 6a 66 66 6e 64 78 6b 6c 66 73 64 6b 66 6a 73 61 61 64 69 65 70 77 6e}
		$x4 = {66 67 77 6c 6a 75 73 6a 70 64 6a 61 68}
		$x5 = {75 64 62 63 67 69 75 74 2e 64 61 74}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 800KB and ( 1 of ( $x* ) or 6 of ( $s* ) )
}

