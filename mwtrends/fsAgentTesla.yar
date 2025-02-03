rule AgentTesla : hardened
{
	meta:
		author = "kevoreilly"
		description = "AgentTesla Payload"
		cape_type = "AgentTesla Payload"
		ruleset = "AgentTesla.yar"
		repository = "kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/9c8d6da44b595f8140a5cd76edd8101f6812c3b0/data/yara/CAPE/AgentTesla.yar"
		license = "Other"
		score = 75

	strings:
		$string1 = {73 00 6d 00 74 00 70 00}
		$string2 = {61 00 70 00 70 00 64 00 61 00 74 00 61 00}
		$string3 = {37 00 36 00 34 00 38 00 37 00 2d 00 33 00 33 00 37 00 2d 00 38 00 34 00 32 00 39 00 39 00 35 00 35 00 2d 00 32 00 32 00 36 00 31 00 34 00}
		$string4 = {79 00 79 00 79 00 79 00 2d 00 4d 00 4d 00 2d 00 64 00 64 00 20 00 48 00 48 00 3a 00 6d 00 6d 00 3a 00 73 00 73 00}
		$string6 = {77 00 65 00 62 00 70 00 61 00 6e 00 65 00 6c 00}
		$string7 = {3c 00 62 00 72 00 3e 00 55 00 73 00 65 00 72 00 4e 00 61 00 6d 00 65 00 26 00 6e 00 62 00 73 00 70 00 3b 00 26 00 6e 00 62 00 73 00 70 00 3b 00 26 00 6e 00 62 00 73 00 70 00 3b 00 26 00 6e 00 62 00 73 00 70 00 3b 00 26 00 6e 00 62 00 73 00 70 00 3b 00 26 00 6e 00 62 00 73 00 70 00 3b 00 3a 00}
		$string8 = {3c 00 62 00 72 00 3e 00 49 00 50 00 20 00 41 00 64 00 64 00 72 00 65 00 73 00 73 00 26 00 6e 00 62 00 73 00 70 00 3b 00 26 00 6e 00 62 00 73 00 70 00 3b 00 3a 00}
		$agt1 = {49 45 4c 69 62 72 61 72 79 2e 64 6c 6c}
		$agt2 = {43 3a 5c 55 73 65 72 73 5c 41 64 6d 69 6e 5c 44 65 73 6b 74 6f 70 5c 49 45 4c 69 62 72 61 72 79 5c 49 45 4c 69 62 72 61 72 79 5c 6f 62 6a 5c 44 65 62 75 67 5c 49 45 4c 69 62 72 61 72 79 2e 70 64 62}
		$agt3 = {47 65 74 53 61 76 65 64 50 61 73 73 77 6f 72 64 73}
		$agt4 = {47 65 74 53 61 76 65 64 43 6f 6f 6b 69 65 73}

	condition:
		uint16( 0 ) == 0x5A4D and ( all of ( $string* ) or 3 of ( $agt* ) )
}

rule AgentTeslaV2 : hardened
{
	meta:
		author = "ditekshen"
		description = "AgenetTesla Type 2 Keylogger payload"
		cape_type = "AgentTesla Payload"
		ruleset = "AgentTesla.yar"
		repository = "kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/9c8d6da44b595f8140a5cd76edd8101f6812c3b0/data/yara/CAPE/AgentTesla.yar"
		license = "Other"
		score = 75

	strings:
		$s1 = {67 65 74 5f 6b 62 48 6f 6f 6b}
		$s2 = {47 65 74 50 72 69 76 61 74 65 50 72 6f 66 69 6c 65 53 74 72 69 6e 67}
		$s3 = {67 65 74 5f 4f 53 46 75 6c 6c 4e 61 6d 65}
		$s4 = {67 65 74 5f 50 61 73 73 77 6f 72 64 48 61 73 68}
		$s5 = {72 65 6d 6f 76 65 5f 4b 65 79}
		$s6 = {46 74 70 57 65 62 52 65 71 75 65 73 74}
		$s7 = {6c 00 6f 00 67 00 69 00 6e 00 73 00}
		$s8 = {6b 00 65 00 79 00 6c 00 6f 00 67 00}
		$s9 = {31 00 2e 00 38 00 35 00 20 00 28 00 48 00 61 00 73 00 68 00 2c 00 20 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 20 00 32 00 2c 00 20 00 6e 00 61 00 74 00 69 00 76 00 65 00 20 00 62 00 79 00 74 00 65 00 2d 00 6f 00 72 00 64 00 65 00 72 00 29 00}
		$cl1 = {50 6f 73 74 62 6f 78}
		$cl2 = {42 6c 61 63 6b 48 61 77 6b}
		$cl3 = {57 61 74 65 72 46 6f 78}
		$cl4 = {43 79 62 65 72 46 6f 78}
		$cl5 = {49 63 65 44 72 61 67 6f 6e}
		$cl6 = {54 68 75 6e 64 65 72 62 69 72 64}

	condition:
		( uint16( 0 ) == 0x5a4d and 6 of ( $s* ) ) or ( 6 of ( $s* ) and 2 of ( $cl* ) )
}

rule AgentTeslaV3 : hardened
{
	meta:
		author = "ditekshen"
		description = "AgentTeslaV3 infostealer payload"
		cape_type = "AgentTesla payload"
		ruleset = "AgentTesla.yar"
		repository = "kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/9c8d6da44b595f8140a5cd76edd8101f6812c3b0/data/yara/CAPE/AgentTesla.yar"
		license = "Other"
		score = 75

	strings:
		$s1 = {67 65 74 5f 6b 62 6f 6b}
		$s2 = {67 65 74 5f 43 48 6f 6f}
		$s3 = {73 65 74 5f 70 61 73 73 77 6f 72 64 49 73 53 65 74}
		$s4 = {67 65 74 5f 65 6e 61 62 6c 65 4c 6f 67}
		$s5 = {62 00 6f 00 74 00 25 00 74 00 65 00 6c 00 65 00 67 00 72 00 61 00 6d 00 61 00 70 00 69 00 25 00}
		$s6 = {4b 69 6c 6c 54 6f 72 50 72 6f 63 65 73 73}
		$s7 = {47 65 74 4d 6f 7a 69 6c 6c 61}
		$s8 = {74 00 6f 00 72 00 62 00 72 00 6f 00 77 00 73 00 65 00 72 00}
		$s9 = {25 00 63 00 68 00 61 00 74 00 69 00 64 00 25 00}
		$s10 = {6c 00 6f 00 67 00 69 00 6e 00 73 00}
		$s11 = {63 00 72 00 65 00 64 00 65 00 6e 00 74 00 69 00 61 00 6c 00}
		$s12 = {41 00 63 00 63 00 6f 00 75 00 6e 00 74 00 43 00 6f 00 6e 00 66 00 69 00 67 00 75 00 72 00 61 00 74 00 69 00 6f 00 6e 00 2b 00}
		$s13 = {3c 00 61 00 2e 00 2b 00 3f 00 68 00 72 00 65 00 66 00 5c 00 73 00 2a 00 3d 00 5c 00 73 00 2a 00 28 00 5b 00 22 00 27 00 5d 00 29 00 28 00 3f 00 3c 00 68 00 72 00 65 00 66 00 3e 00 2e 00 2b 00 3f 00 29 00 5c 00 31 00 5b 00 5e 00 3e 00 5d 00 2a 00 3e 00}
		$s14 = {73 65 74 5f 4c 65 6e 67 68 74}
		$s15 = {67 65 74 5f 4b 65 79 73}
		$s16 = {73 65 74 5f 41 6c 6c 6f 77 41 75 74 6f 52 65 64 69 72 65 63 74}
		$s17 = {73 65 74 5f 77 74 71 51 65}
		$s18 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65}
		$s19 = {73 65 74 5f 49 73 42 6f 64 79 48 74 6d 6c}
		$s20 = {73 65 74 5f 46 45 6c 76 4d 6e}
		$s21 = {73 65 74 5f 52 65 64 69 72 65 63 74 53 74 61 6e 64 61 72 64 4f 75 74 70 75 74}
		$g1 = {67 65 74 5f 43 6c 69 70 62 6f 61 72 64}
		$g2 = {67 65 74 5f 4b 65 79 62 6f 61 72 64}
		$g3 = {67 65 74 5f 50 61 73 73 77 6f 72 64}
		$g4 = {67 65 74 5f 43 74 72 6c 4b 65 79 44 6f 77 6e}
		$g5 = {67 65 74 5f 53 68 69 66 74 4b 65 79 44 6f 77 6e}
		$g6 = {67 65 74 5f 41 6c 74 4b 65 79 44 6f 77 6e}
		$m1 = {79 79 79 79 2d 4d 4d 2d 64 64 20 68 68 2d 6d 6d 2d 73 73 43 6f 6f 6b 69 65 61 70 70 6c 69 63 61 74 69 6f 6e 2f 7a 69 70 53 43 53 43 5f 2e 6a 70 65 67 53 63 72 65 65 6e 73 68 6f 74 69 6d 61 67 65 2f 6a 70 65 67 2f 6c 6f 67 2e 74 6d 70 4b 4c 4b 4c 5f 2e 68 74 6d 6c 3c 68 74 6d 6c 3e 3c 2f 68 74 6d 6c 3e 4c 6f 67 74 65 78 74 2f 68 74 6d 6c 5b 5d 54 69 6d 65}
		$m2 = {25 69 6d 61 67 65 2f 6a 70 67 3a 5a 6f 6e 65 2e 49 64 65 6e 74 69 66 69 65 72 5c 74 6d 70 47 2e 74 6d 70 25 75 72 6c 6b 65 79 25 2d 66 20 5c 44 61 74 61 5c 54 6f 72 5c 74 6f 72 72 63 70 3d 25 50 6f 73 74 55 52 4c 25 31 32 37 2e 30 2e 30 2e 31 50 4f 53 54 2b 25 32 42}
		$m3 = {3e 7b 43 54 52 4c 7d 3c 2f 66 6f 6e 74 3e 57 69 6e 64 6f 77 73 20 52 44 50 63 72 65 64 65 6e 74 69 61 6c 70 6f 6c 69 63 79 62 6c 6f 62 72 64 67 63 68 72 6f 6d 65 7b 7b 7b 30 7d 7d 7d 43 6f 70 79 54 6f 43 6f 6d 70 75 74 65 48 61 73 68 73 68 61 35 31 32 43 6f 70 79 53 79 73 74 65 6d 44 72 69 76 65 5c 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 52 65 67 52 65 61 64 67 34 30 31}
		$m4 = {25 73 74 61 72 74 75 70 66 6f 6c 64 65 72 25 5c 25 69 6e 73 66 6f 6c 64 65 72 25 5c 25 69 6e 73 6e 61 6d 65 25 2f 5c 25 69 6e 73 66 6f 6c 64 65 72 25 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 25 69 6e 73 72 65 67 6e 61 6d 65 25 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 74 61 72 74 75 70 41 70 70 72 6f 76 65 64 5c 52 75 6e 54 72 75 65 68 74 74 70}
		$m5 = {5c 57 69 6e 64 6f 77 73 4c 6f 61 64 25 66 74 70 68 6f 73 74 25 2f 25 66 74 70 75 73 65 72 25 25 66 74 70 70 61 73 73 77 6f 72 64 25 53 54 4f 52 4c 65 6e 67 74 68 57 72 69 74 65 43 6c 6f 73 65 47 65 74 42 79 74 65 73 4f 70 65 72 61}

	condition:
		( uint16( 0 ) == 0x5a4d and ( 8 of ( $s* ) or ( 6 of ( $s* ) and 4 of ( $g* ) ) ) ) or ( 2 of ( $m* ) )
}

rule AgentTeslaXor : hardened
{
	meta:
		author = "kevoreilly"
		description = "AgentTesla xor-based config decoding"
		cape_type = "AgentTesla Payload"
		ruleset = "AgentTesla.yar"
		repository = "kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/9c8d6da44b595f8140a5cd76edd8101f6812c3b0/data/yara/CAPE/AgentTesla.yar"
		license = "Other"
		score = 75

	strings:
		$decode = {06 91 06 61 20 [4] 61 D2 9C 06 17 58 0A 06 7E [4] 8E 69 FE 04 2D ?? 2A}

	condition:
		uint16( 0 ) == 0x5A4D and any of them
}

rule AgentTeslaV4 : hardened
{
	meta:
		author = "kevoreilly"
		description = "AgentTesla Payload"
		cape_type = "AgentTesla Payload"
		packed = "7f8a95173e17256698324886bb138b7936b9e8c5b9ab8fffbfe01080f02f286c"
		ruleset = "AgentTesla.yar"
		repository = "kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/9c8d6da44b595f8140a5cd76edd8101f6812c3b0/data/yara/CAPE/AgentTesla.yar"
		license = "Other"
		score = 75

	strings:
		$decode1 = {(07|FE 0C 01 00) (07|FE 0C 01 00) 8E 69 (17|20 01 00 00 00) 63 8F ?? 00 00 01 25 47 (06|FE 0C 00 00) (1A|20 04 00 00 00) 58 4A D2 61 D2 52}
		$decode2 = {(07|FE 0C 01 00) (08|FE 0C 02 00) 8F ?? 00 00 01 25 47 (07|FE 0C 01 00) (11 07|FE 0C 07 00) 91 (06|FE 0C 00 00) (1A|20 04 00 00 00) 58 4A 61 D2 61 D2 52}
		$decode3 = {(07|FE 0C 01 00) (11 07|FE 0C 07 00) 8F ?? 00 00 01 25 47 (07|FE 0C 01 00) (08|FE 0C 02 00) 91 61 D2 52}

	condition:
		uint16( 0 ) == 0x5A4D and all of them
}

rule AgentTeslaV4JIT : hardened
{
	meta:
		author = "kevoreilly"
		description = "AgentTesla JIT-compiled native code"
		cape_type = "AgentTesla Payload"
		packed = "7f8a95173e17256698324886bb138b7936b9e8c5b9ab8fffbfe01080f02f286c"
		ruleset = "AgentTesla.yar"
		repository = "kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/9c8d6da44b595f8140a5cd76edd8101f6812c3b0/data/yara/CAPE/AgentTesla.yar"
		license = "Other"
		score = 75

	strings:
		$decode1 = {8B 01 8B 40 3C FF 50 10 8B C8 E8 [4] 89 45 CC B8 1A 00 00 00}
		$decode2 = {83 F8 18 75 2? 8B [2-5] D1 F8}
		$decode3 = {8D 4C 0? 08 0F B6 01 [0-3] 0F B6 5? 04 33 C2 88 01 B8 19 00 00 00}

	condition:
		2 of them
}

rule AgentTeslaV5 : hardened
{
	meta:
		author = "ClaudioWayne"
		description = "AgentTeslaV5 infostealer payload"
		cape_type = "AgentTesla payload"
		sample = "893f4dc8f8a1dcee05a0840988cf90bc93c1cda5b414f35a6adb5e9f40678ce9"
		ruleset = "AgentTesla.yar"
		repository = "kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/9c8d6da44b595f8140a5cd76edd8101f6812c3b0/data/yara/CAPE/AgentTesla.yar"
		license = "Other"
		score = 75

	strings:
		$template1 = {3c 00 62 00 72 00 3e 00 55 00 73 00 65 00 72 00 20 00 4e 00 61 00 6d 00 65 00 3a 00 20 00}
		$template2 = {3c 00 62 00 72 00 3e 00 55 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 3a 00 20 00}
		$template3 = {3c 00 62 00 72 00 3e 00 52 00 41 00 4d 00 3a 00 20 00}
		$template4 = {3c 00 62 00 72 00 3e 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 3a 00 20 00}
		$template5 = {3c 00 62 00 72 00 3e 00 4f 00 53 00 46 00 75 00 6c 00 6c 00 4e 00 61 00 6d 00 65 00 3a 00 20 00}
		$template6 = {3c 00 62 00 72 00 3e 00 3c 00 68 00 72 00 3e 00 43 00 6f 00 70 00 69 00 65 00 64 00 20 00 54 00 65 00 78 00 74 00 3a 00 20 00 3c 00 62 00 72 00 3e 00}
		$template7 = {3c 00 62 00 72 00 3e 00 43 00 50 00 55 00 3a 00 20 00}
		$template8 = {3c 00 62 00 72 00 3e 00 43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 20 00 4e 00 61 00 6d 00 65 00 3a 00 20 00}
		$template9 = {3c 00 62 00 72 00 3e 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 3a 00 20 00}
		$chromium_browser1 = {43 00 6f 00 6d 00 6f 00 64 00 6f 00 5c 00 44 00 72 00 61 00 67 00 6f 00 6e 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00}
		$chromium_browser2 = {46 00 65 00 6e 00 72 00 69 00 72 00 20 00 49 00 6e 00 63 00 5c 00 53 00 6c 00 65 00 69 00 70 00 6e 00 69 00 72 00 35 00 5c 00 73 00 65 00 74 00 74 00 69 00 6e 00 67 00 5c 00 6d 00 6f 00 64 00 75 00 6c 00 65 00 73 00 5c 00 43 00 68 00 72 00 6f 00 6d 00 69 00 75 00 6d 00 56 00 69 00 65 00 77 00 65 00 72 00}
		$chromium_browser3 = {47 00 6f 00 6f 00 67 00 6c 00 65 00 5c 00 43 00 68 00 72 00 6f 00 6d 00 65 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00}
		$chromium_browser4 = {45 00 6c 00 65 00 6d 00 65 00 6e 00 74 00 73 00 20 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00}
		$chromium_browser5 = {59 00 61 00 6e 00 64 00 65 00 78 00 5c 00 59 00 61 00 6e 00 64 00 65 00 78 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00}
		$chromium_browser6 = {4d 00 61 00 70 00 6c 00 65 00 53 00 74 00 75 00 64 00 69 00 6f 00 5c 00 43 00 68 00 72 00 6f 00 6d 00 65 00 50 00 6c 00 75 00 73 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00}
		$mozilla_browser1 = {5c 00 4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 5c 00 53 00 65 00 61 00 4d 00 6f 00 6e 00 6b 00 65 00 79 00 5c 00}
		$mozilla_browser2 = {5c 00 4b 00 2d 00 4d 00 65 00 6c 00 65 00 6f 00 6e 00 5c 00}
		$mozilla_browser3 = {5c 00 4e 00 45 00 54 00 47 00 41 00 54 00 45 00 20 00 54 00 65 00 63 00 68 00 6e 00 6f 00 6c 00 6f 00 67 00 69 00 65 00 73 00 5c 00 42 00 6c 00 61 00 63 00 6b 00 48 00 61 00 77 00 6b 00 5c 00}
		$mozilla_browser4 = {5c 00 54 00 68 00 75 00 6e 00 64 00 65 00 72 00 62 00 69 00 72 00 64 00 5c 00}
		$mozilla_browser5 = {5c 00 38 00 70 00 65 00 63 00 78 00 73 00 74 00 75 00 64 00 69 00 6f 00 73 00 5c 00 43 00 79 00 62 00 65 00 72 00 66 00 6f 00 78 00 5c 00}
		$mozilla_browser6 = {33 00 36 00 30 00 43 00 68 00 72 00 6f 00 6d 00 65 00 5c 00 43 00 68 00 72 00 6f 00 6d 00 65 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00}
		$mozilla_browser7 = {5c 00 4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 5c 00 46 00 69 00 72 00 65 00 66 00 6f 00 78 00 5c 00}
		$database1 = {42 00 65 00 72 00 6b 00 65 00 6c 00 65 00 74 00 20 00 44 00 42 00}
		$database2 = {20 00 31 00 2e 00 38 00 35 00 20 00 28 00 48 00 61 00 73 00 68 00 2c 00 20 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 20 00 32 00 2c 00 20 00 6e 00 61 00 74 00 69 00 76 00 65 00 20 00 62 00 79 00 74 00 65 00 2d 00 6f 00 72 00 64 00 65 00 72 00 29 00}
		$database3 = {30 00 30 00 30 00 36 00 31 00 35 00 36 00 31 00}
		$database4 = {6b 00 65 00 79 00 34 00 2e 00 64 00 62 00}
		$database5 = {6b 00 65 00 79 00 33 00 2e 00 64 00 62 00}
		$database6 = {67 00 6c 00 6f 00 62 00 61 00 6c 00 2d 00 73 00 61 00 6c 00 74 00}
		$database7 = {70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 2d 00 63 00 68 00 65 00 63 00 6b 00}
		$software1 = {5c 00 46 00 69 00 6c 00 65 00 5a 00 69 00 6c 00 6c 00 61 00 5c 00 72 00 65 00 63 00 65 00 6e 00 74 00 73 00 65 00 72 00 76 00 65 00 72 00 73 00 2e 00 78 00 6d 00 6c 00}
		$software2 = {5c 00 56 00 69 00 72 00 74 00 75 00 61 00 6c 00 53 00 74 00 6f 00 72 00 65 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 20 00 28 00 78 00 38 00 36 00 29 00 5c 00 46 00 54 00 50 00 20 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 65 00 72 00 5c 00 46 00 74 00 70 00 6c 00 69 00 73 00 74 00 2e 00 74 00 78 00 74 00}
		$software3 = {5c 00 54 00 68 00 65 00 20 00 42 00 61 00 74 00 21 00}
		$software4 = {5c 00 41 00 70 00 70 00 6c 00 65 00 20 00 43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 5c 00 50 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 73 00 5c 00 6b 00 65 00 79 00 63 00 68 00 61 00 69 00 6e 00 2e 00 70 00 6c 00 69 00 73 00 74 00}
		$software5 = {5c 00 4d 00 79 00 53 00 51 00 4c 00 5c 00 57 00 6f 00 72 00 6b 00 62 00 65 00 6e 00 63 00 68 00 5c 00 77 00 6f 00 72 00 6b 00 62 00 65 00 6e 00 63 00 68 00 5f 00 75 00 73 00 65 00 72 00 5f 00 64 00 61 00 74 00 61 00 2e 00 64 00 61 00 74 00}
		$software6 = {5c 00 54 00 72 00 69 00 6c 00 6c 00 69 00 61 00 6e 00 5c 00 75 00 73 00 65 00 72 00 73 00 5c 00 67 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 61 00 63 00 63 00 6f 00 75 00 6e 00 74 00 73 00 2e 00 64 00 61 00 74 00}
		$software7 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 61 00 72 00 74 00 69 00 6e 00 20 00 50 00 72 00 69 00 6b 00 72 00 79 00 6c 00 5c 00 57 00 69 00 6e 00 53 00 43 00 50 00 20 00 32 00 5c 00 53 00 65 00 73 00 73 00 69 00 6f 00 6e 00 73 00}
		$software8 = {46 00 54 00 50 00 20 00 4e 00 61 00 76 00 69 00 67 00 61 00 74 00 6f 00 72 00 5c 00 46 00 74 00 70 00 6c 00 69 00 73 00 74 00 2e 00 74 00 78 00 74 00}
		$software9 = {4e 00 6f 00 72 00 64 00 56 00 50 00 4e 00}
		$software10 = {4a 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 72 00 20 00 32 00 2e 00 30 00 5c 00 63 00 66 00 67 00}

	condition:
		uint16( 0 ) == 0x5a4d and 4 of ( $template* ) and 3 of ( $chromium_browser* ) and 3 of ( $mozilla_browser* ) and 3 of ( $database* ) and 5 of ( $software* )
}

rule Windows_Trojan_AgentTesla_d3ac2b2f : hardened
{
	meta:
		author = "Elastic Security"
		id = "d3ac2b2f-14fc-4851-8a57-41032e386aeb"
		fingerprint = "cbbb56fe6cd7277ae9595a10e05e2ce535a4e6bf205810be0bbce3a883b6f8bc"
		creation_date = "2021-03-22"
		last_modified = "2022-06-20"
		threat_name = "Windows.Trojan.AgentTesla"
		reference = "https://www.elastic.co/security-labs/attack-chain-leads-to-xworm-and-agenttesla"
		reference_sample = "65463161760af7ab85f5c475a0f7b1581234a1e714a2c5a555783bdd203f85f4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_AgentTesla.yar"
		repository = "elastic/protections-artifacts"
		source_url = "https://github.com/elastic/protections-artifacts/blob/3bbef930abab9814b2fdb4704be075ab1daf2ea0/yara/rules/Windows_Trojan_AgentTesla.yar"
		score = 75

	strings:
		$a1 = {47 65 74 4d 6f 7a 69 6c 6c 61 46 72 6f 6d 4c 6f 67 69 6e 73}
		$a2 = {41 00 63 00 63 00 6f 00 75 00 6e 00 74 00 43 00 6f 00 6e 00 66 00 69 00 67 00 75 00 72 00 61 00 74 00 69 00 6f 00 6e 00 2b 00 75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00}
		$a3 = {4d 61 69 6c 41 63 63 6f 75 6e 74 43 6f 6e 66 69 67 75 72 61 74 69 6f 6e}
		$a4 = {4b 69 6c 6c 54 6f 72 50 72 6f 63 65 73 73}
		$a5 = {53 6d 74 70 41 63 63 6f 75 6e 74 43 6f 6e 66 69 67 75 72 61 74 69 6f 6e}
		$a6 = {47 65 74 4d 6f 7a 69 6c 6c 61 46 72 6f 6d 53 51 4c 69 74 65}
		$a7 = {50 00 72 00 6f 00 78 00 79 00 2d 00 41 00 67 00 65 00 6e 00 74 00 3a 00 20 00 48 00 54 00 6f 00 53 00 35 00 78 00}
		$a8 = {73 65 74 5f 42 69 6e 64 69 6e 67 41 63 63 6f 75 6e 74 43 6f 6e 66 69 67 75 72 61 74 69 6f 6e}
		$a9 = {64 6f 55 73 65 72 6e 61 6d 65 50 61 73 73 77 6f 72 64 41 75 74 68}
		$a10 = {53 61 66 61 72 69 44 65 63 72 79 70 74 6f 72}
		$a11 = {67 65 74 5f 73 65 63 75 72 69 74 79 50 72 6f 66 69 6c 65}
		$a12 = {67 65 74 5f 75 73 65 53 65 70 61 72 61 74 65 46 6f 6c 64 65 72 54 72 65 65}
		$a13 = {67 65 74 5f 44 6e 73 52 65 73 6f 6c 76 65 72}
		$a14 = {67 65 74 5f 61 72 63 68 69 76 69 6e 67 53 63 6f 70 65}
		$a15 = {67 65 74 5f 70 72 6f 76 69 64 65 72 4e 61 6d 65}
		$a16 = {67 65 74 5f 43 6c 69 70 62 6f 61 72 64 48 6f 6f 6b}
		$a17 = {67 65 74 5f 70 72 69 6f 72 69 74 79}
		$a18 = {67 65 74 5f 61 64 76 61 6e 63 65 64 50 61 72 61 6d 65 74 65 72 73}
		$a19 = {67 65 74 5f 64 69 73 61 62 6c 65 64 42 79 52 65 73 74 72 69 63 74 69 6f 6e}
		$a20 = {67 65 74 5f 4c 61 73 74 41 63 63 65 73 73 65 64}
		$a21 = {67 65 74 5f 61 76 61 74 61 72 54 79 70 65}
		$a22 = {67 65 74 5f 73 69 67 6e 61 74 75 72 65 50 72 65 73 65 74 73}
		$a23 = {67 65 74 5f 65 6e 61 62 6c 65 4c 6f 67}
		$a24 = {54 65 6c 65 67 72 61 6d 4c 6f 67}
		$a25 = {67 65 6e 65 72 61 74 65 4b 65 79 56 37 35}
		$a26 = {73 65 74 5f 61 63 63 6f 75 6e 74 4e 61 6d 65}
		$a27 = {73 65 74 5f 49 6e 74 65 72 6e 61 6c 53 65 72 76 65 72 50 6f 72 74}
		$a28 = {73 65 74 5f 62 69 6e 64 69 6e 67 43 6f 6e 66 69 67 75 72 61 74 69 6f 6e 55 49 44}
		$a29 = {73 65 74 5f 49 64 6e 41 64 64 72 65 73 73}
		$a30 = {73 65 74 5f 47 75 69 64 4d 61 73 74 65 72 4b 65 79}
		$a31 = {73 65 74 5f 75 73 65 72 6e 61 6d 65}
		$a32 = {73 65 74 5f 76 65 72 73 69 6f 6e}
		$a33 = {67 65 74 5f 43 6c 69 70 62 6f 61 72 64}
		$a34 = {67 65 74 5f 4b 65 79 62 6f 61 72 64}
		$a35 = {67 65 74 5f 53 68 69 66 74 4b 65 79 44 6f 77 6e}
		$a36 = {67 65 74 5f 41 6c 74 4b 65 79 44 6f 77 6e}
		$a37 = {67 65 74 5f 50 61 73 73 77 6f 72 64}
		$a38 = {67 65 74 5f 50 61 73 73 77 6f 72 64 48 61 73 68}
		$a39 = {67 65 74 5f 44 65 66 61 75 6c 74 43 72 65 64 65 6e 74 69 61 6c 73}

	condition:
		8 of ( $a* )
}

rule Windows_Trojan_AgentTesla_e577e17e : hardened
{
	meta:
		author = "Elastic Security"
		id = "e577e17e-5c42-4431-8c2d-0c1153128226"
		fingerprint = "009cb27295a1aa0dde84d29ee49b8fa2e7a6cec75eccb7534fec3f5c89395a9d"
		creation_date = "2022-03-11"
		last_modified = "2022-04-12"
		threat_name = "Windows.Trojan.AgentTesla"
		reference = "https://www.elastic.co/security-labs/attack-chain-leads-to-xworm-and-agenttesla"
		reference_sample = "ed43ddb536e6c3f8513213cd6eb2e890b73e26d5543c0ba1deb2690b5c0385b6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_AgentTesla.yar"
		repository = "elastic/protections-artifacts"
		source_url = "https://github.com/elastic/protections-artifacts/blob/3bbef930abab9814b2fdb4704be075ab1daf2ea0/yara/rules/Windows_Trojan_AgentTesla.yar"
		score = 75

	strings:
		$a = { 20 4D 27 00 00 33 DB 19 0B 00 07 17 FE 01 2C 02 18 0B 00 07 }

	condition:
		all of them
}

rule Windows_Trojan_AgentTesla_f2a90d14 : hardened
{
	meta:
		author = "Elastic Security"
		id = "f2a90d14-7212-41a5-a2cd-a6a6dedce96e"
		fingerprint = "829c827069846ba1e1378aba8ee6cdc801631d769dc3dce15ccaacd4068a88a6"
		creation_date = "2022-03-11"
		last_modified = "2022-04-12"
		threat_name = "Windows.Trojan.AgentTesla"
		reference = "https://www.elastic.co/security-labs/attack-chain-leads-to-xworm-and-agenttesla"
		reference_sample = "ed43ddb536e6c3f8513213cd6eb2e890b73e26d5543c0ba1deb2690b5c0385b6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_AgentTesla.yar"
		repository = "elastic/protections-artifacts"
		source_url = "https://github.com/elastic/protections-artifacts/blob/3bbef930abab9814b2fdb4704be075ab1daf2ea0/yara/rules/Windows_Trojan_AgentTesla.yar"
		score = 75

	strings:
		$a = { 0B FE 01 2C 0B 07 16 7E 08 00 00 04 A2 1F 0C 0C 00 08 1F 09 FE 01 }

	condition:
		all of them
}

rule Windows_Trojan_AgentTesla_a2d69e48 : hardened
{
	meta:
		author = "Elastic Security"
		id = "a2d69e48-b114-4128-8c2f-6fabee49e152"
		fingerprint = "bd46dd911aadf8691516a77f3f4f040e6790f36647b5293050ecb8c25da31729"
		creation_date = "2023-05-01"
		last_modified = "2023-06-13"
		threat_name = "Windows.Trojan.AgentTesla"
		reference = "https://www.elastic.co/security-labs/attack-chain-leads-to-xworm-and-agenttesla"
		reference_sample = "edef51e59d10993155104d90fcd80175daa5ade63fec260e3272f17b237a6f44"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_AgentTesla.yar"
		repository = "elastic/protections-artifacts"
		source_url = "https://github.com/elastic/protections-artifacts/blob/3bbef930abab9814b2fdb4704be075ab1daf2ea0/yara/rules/Windows_Trojan_AgentTesla.yar"
		score = 75

	strings:
		$a1 = { 00 03 08 08 10 08 10 18 09 00 04 08 18 08 10 08 10 18 0E 00 08 }
		$a2 = { 00 06 17 5F 16 FE 01 16 FE 01 2A 00 03 30 03 00 B1 00 00 00 }

	condition:
		all of them
}

rule Windows_Trojan_AgentTesla_ebf431a8 : hardened
{
	meta:
		author = "Elastic Security"
		id = "ebf431a8-45e8-416c-a355-4ac1db2d133a"
		fingerprint = "2d95dbe502421d862eee33ba819b41cb39cf77a44289f4de4a506cad22f3fddb"
		creation_date = "2023-12-01"
		last_modified = "2024-01-12"
		threat_name = "Windows.Trojan.AgentTesla"
		reference = "https://www.elastic.co/security-labs/attack-chain-leads-to-xworm-and-agenttesla"
		reference_sample = "0cb3051a80a0515ce715b71fdf64abebfb8c71b9814903cb9abcf16c0403f62b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_AgentTesla.yar"
		repository = "elastic/protections-artifacts"
		source_url = "https://github.com/elastic/protections-artifacts/blob/3bbef930abab9814b2fdb4704be075ab1daf2ea0/yara/rules/Windows_Trojan_AgentTesla.yar"
		score = 75

	strings:
		$a1 = {4d 6f 7a 69 6c 6c 61 42 72 6f 77 73 65 72 4c 69 73 74}
		$a2 = {45 6e 61 62 6c 65 53 63 72 65 65 6e 4c 6f 67 67 65 72}
		$a3 = {56 61 75 6c 74 47 65 74 49 74 65 6d 5f 57 49 4e 37}
		$a4 = {50 75 62 6c 69 63 49 70 41 64 64 72 65 73 73 47 72 61 62}
		$a5 = {45 6e 61 62 6c 65 54 6f 72 50 61 6e 65 6c}
		$a6 = {67 65 74 5f 47 75 69 64 4d 61 73 74 65 72 4b 65 79}

	condition:
		4 of them
}

rule Win32_Trojan_AgentTesla : hardened
{
	meta:
		description = "Identifies AgentTesla samples."
		author = "Netskope Threat Labs"
		ruleset = "Win32_Trojan_AgentTesla.yar"
		repository = "netskopeoss/NetskopeThreatLabsIOCs"
		source_url = "https://github.com/netskopeoss/NetskopeThreatLabsIOCs/blob/52c780db6106d0c0e8deb04653e036cdd4408e56/Malware/AgentTesla/Yara/Win32_Trojan_AgentTesla.yar"
		license = "MIT License"
		score = 75

	strings:
		$bin00 = {23 42 6c 6f 62}
		$bin01 = {23 47 55 49 44}
		$bin02 = {23 53 74 72 69 6e 67 73}
		$str00 = {67 65 74 5f 41 63 63 6f 75 6e 74 43 72 65 64 65 6e 74 69 61 6c}
		$str01 = {67 65 74 5f 61 63 63 6f 75 6e 74 4e 61 6d 65}
		$str02 = {67 65 74 5f 41 64 64 72 65 73 73}
		$str03 = {67 65 74 5f 41 6c 74 4b 65 79 44 6f 77 6e}
		$str04 = {67 65 74 5f 41 73 73 65 6d 62 6c 79}
		$str05 = {67 65 74 5f 41 74 74 61 63 68 6d 65 6e 74 73}
		$str06 = {67 65 74 5f 43 6c 69 70 62 6f 61 72 64}
		$str07 = {67 65 74 5f 43 6f 6d 70 75 74 65 72}
		$str08 = {67 65 74 5f 43 6f 6d 70 75 74 65 72 4e 61 6d 65}
		$str09 = {67 65 74 5f 43 6f 6e 6e 65 63 74 65 64}
		$str10 = {67 65 74 5f 45 78 65 63 75 74 61 62 6c 65 50 61 74 68}
		$str11 = {67 65 74 5f 48 6f 73 74}
		$str12 = {67 65 74 5f 4b 65 79}
		$str13 = {67 65 74 5f 4b 65 79 62 6f 61 72 64}
		$str14 = {67 65 74 5f 50 72 6f 63 65 73 73 4e 61 6d 65}
		$str15 = {73 65 74 5f 55 73 65 72 41 67 65 6e 74}
		$str16 = {73 65 74 5f 55 73 65 72 4e 61 6d 65}
		$str17 = {73 65 74 5f 49 73 42 6f 64 79 48 74 6d 6c}
		$str18 = {73 65 74 5f 49 56}

	condition:
		uint16( 0 ) == 0x5a4d and all of ( $bin* ) and 10 of ( $str* )
}

rule agenttesla_smtp_variant : hardened
{
	meta:
		author = "J from THL <j@techhelplist.com> with thx to @Fumik0_ !!1!"
		date = "2018/2"
		reference1 = "https://www.virustotal.com/#/file/1198865bc928a7a4f7977aaa36af5a2b9d5a949328b89dd87c541758516ad417/detection"
		reference2 = "https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/tspy_negasteal.a"
		reference3 = "Agent Tesla == negasteal -- @coldshell"
		version = 1
		maltype = "Stealer"
		filetype = "memory"
		ruleset = "MALW_AgentTesla_SMTP.yar"
		repository = "Yara-Rules/rules"
		source_url = "https://github.com/Yara-Rules/rules/blob/0f93570194a80d2f2032869055808b0ddcdfb360/malware/MALW_AgentTesla_SMTP.yar"
		license = "GNU General Public License v2.0"
		score = 75

	strings:
		$a = {74 79 70 65 3d 7b}
		$b = {68 77 69 64 3d 7b}
		$c = {74 69 6d 65 3d 7b}
		$d = {70 63 6e 61 6d 65 3d 7b}
		$e = {6c 6f 67 64 61 74 61 3d 7b}
		$f = {73 63 72 65 65 6e 3d 7b}
		$g = {69 70 61 64 64 3d 7b}
		$h = {77 65 62 63 61 6d 5f 6c 69 6e 6b 3d 7b}
		$i = {73 63 72 65 65 6e 5f 6c 69 6e 6b 3d 7b}
		$j = {73 69 74 65 5f 75 73 65 72 6e 61 6d 65 3d 7b}
		$k = {5b 70 61 73 73 77 6f 72 64 73 5d}

	condition:
		6 of them
}

rule AgentTeslaV3_1 : hardened
{
	meta:
		author = "ditekshen"
		description = "AgentTeslaV3 infostealer payload"
		cape_type = "AgentTeslaV3 payload"
		original_yara_name = "AgentTeslaV3"
		ruleset = "CAPE_AgentTesla.yara"
		repository = "CYB3RMX/Qu1cksc0pe"
		source_url = "https://github.com/CYB3RMX/Qu1cksc0pe/blob/8d74a4116951b46b9284102850f28f1082c17c04/Systems/Windows/YaraRules_Windows/CAPE_AgentTesla.yara"
		license = "GNU General Public License v3.0"
		score = 75

	strings:
		$s1 = {67 65 74 5f 6b 62 6f 6b}
		$s2 = {67 65 74 5f 43 48 6f 6f}
		$s3 = {73 65 74 5f 70 61 73 73 77 6f 72 64 49 73 53 65 74}
		$s4 = {67 65 74 5f 65 6e 61 62 6c 65 4c 6f 67}
		$s5 = {62 00 6f 00 74 00 25 00 74 00 65 00 6c 00 65 00 67 00 72 00 61 00 6d 00 61 00 70 00 69 00 25 00}
		$s6 = {4b 69 6c 6c 54 6f 72 50 72 6f 63 65 73 73}
		$s7 = {47 65 74 4d 6f 7a 69 6c 6c 61}
		$s8 = {74 00 6f 00 72 00 62 00 72 00 6f 00 77 00 73 00 65 00 72 00}
		$s9 = {25 00 63 00 68 00 61 00 74 00 69 00 64 00 25 00}
		$s10 = {6c 00 6f 00 67 00 69 00 6e 00 73 00}
		$s11 = {63 00 72 00 65 00 64 00 65 00 6e 00 74 00 69 00 61 00 6c 00}
		$s12 = {41 00 63 00 63 00 6f 00 75 00 6e 00 74 00 43 00 6f 00 6e 00 66 00 69 00 67 00 75 00 72 00 61 00 74 00 69 00 6f 00 6e 00 2b 00}
		$s13 = {3c 00 61 00 2e 00 2b 00 3f 00 68 00 72 00 65 00 66 00 5c 00 73 00 2a 00 3d 00 5c 00 73 00 2a 00 28 00 5b 00 22 00 27 00 5d 00 29 00 28 00 3f 00 3c 00 68 00 72 00 65 00 66 00 3e 00 2e 00 2b 00 3f 00 29 00 5c 00 31 00 5b 00 5e 00 3e 00 5d 00 2a 00 3e 00}
		$g1 = {67 65 74 5f 43 6c 69 70 62 6f 61 72 64}
		$g2 = {67 65 74 5f 4b 65 79 62 6f 61 72 64}
		$g3 = {67 65 74 5f 50 61 73 73 77 6f 72 64}
		$g4 = {67 65 74 5f 43 74 72 6c 4b 65 79 44 6f 77 6e}
		$g5 = {67 65 74 5f 53 68 69 66 74 4b 65 79 44 6f 77 6e}
		$g6 = {67 65 74 5f 41 6c 74 4b 65 79 44 6f 77 6e}
		$m1 = {79 79 79 79 2d 4d 4d 2d 64 64 20 68 68 2d 6d 6d 2d 73 73 43 6f 6f 6b 69 65 61 70 70 6c 69 63 61 74 69 6f 6e 2f 7a 69 70 53 43 53 43 5f 2e 6a 70 65 67 53 63 72 65 65 6e 73 68 6f 74 69 6d 61 67 65 2f 6a 70 65 67 2f 6c 6f 67 2e 74 6d 70 4b 4c 4b 4c 5f 2e 68 74 6d 6c 3c 68 74 6d 6c 3e 3c 2f 68 74 6d 6c 3e 4c 6f 67 74 65 78 74 2f 68 74 6d 6c 5b 5d 54 69 6d 65}
		$m2 = {25 69 6d 61 67 65 2f 6a 70 67 3a 5a 6f 6e 65 2e 49 64 65 6e 74 69 66 69 65 72 5c 74 6d 70 47 2e 74 6d 70 25 75 72 6c 6b 65 79 25 2d 66 20 5c 44 61 74 61 5c 54 6f 72 5c 74 6f 72 72 63 70 3d 25 50 6f 73 74 55 52 4c 25 31 32 37 2e 30 2e 30 2e 31 50 4f 53 54 2b 25 32 42}
		$m3 = {3e 7b 43 54 52 4c 7d 3c 2f 66 6f 6e 74 3e 57 69 6e 64 6f 77 73 20 52 44 50 63 72 65 64 65 6e 74 69 61 6c 70 6f 6c 69 63 79 62 6c 6f 62 72 64 67 63 68 72 6f 6d 65 7b 7b 7b 30 7d 7d 7d 43 6f 70 79 54 6f 43 6f 6d 70 75 74 65 48 61 73 68 73 68 61 35 31 32 43 6f 70 79 53 79 73 74 65 6d 44 72 69 76 65 5c 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 52 65 67 52 65 61 64 67 34 30 31}
		$m4 = {25 73 74 61 72 74 75 70 66 6f 6c 64 65 72 25 5c 25 69 6e 73 66 6f 6c 64 65 72 25 5c 25 69 6e 73 6e 61 6d 65 25 2f 5c 25 69 6e 73 66 6f 6c 64 65 72 25 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 25 69 6e 73 72 65 67 6e 61 6d 65 25 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 74 61 72 74 75 70 41 70 70 72 6f 76 65 64 5c 52 75 6e 54 72 75 65 68 74 74 70}
		$m5 = {5c 57 69 6e 64 6f 77 73 4c 6f 61 64 25 66 74 70 68 6f 73 74 25 2f 25 66 74 70 75 73 65 72 25 25 66 74 70 70 61 73 73 77 6f 72 64 25 53 54 4f 52 4c 65 6e 67 74 68 57 72 69 74 65 43 6c 6f 73 65 47 65 74 42 79 74 65 73 4f 70 65 72 61}

	condition:
		( uint16( 0 ) == 0x5a4d and ( 8 of ( $s* ) or ( 6 of ( $s* ) and all of ( $g* ) ) ) ) or ( 2 of ( $m* ) )
}

rule Agenttesla_type1 : hardened
{
	meta:
		description = "detect Agenttesla in memory"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "memory scan"
		reference = "internal research"
		ruleset = "rule.yara"
		repository = "JPCERTCC/MalConfScan"
		source_url = "https://github.com/JPCERTCC/MalConfScan/blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara"
		license = "Other"
		score = 75

	strings:
		$iestr = {43 3a 5c 5c 55 73 65 72 73 5c 5c 41 64 6d 69 6e 5c 5c 44 65 73 6b 74 6f 70 5c 5c 49 45 4c 69 62 72 61 72 79 5c 5c 49 45 4c 69 62 72 61 72 79 5c 5c 6f 62 6a 5c 5c 44 65 62 75 67 5c 5c 49 45 4c 69 62 72 61 72 79 2e 70 64 62}
		$atstr = {43 3a 5c 5c 55 73 65 72 73 5c 5c 41 64 6d 69 6e 5c 5c 44 65 73 6b 74 6f 70 5c 5c 43 6f 6e 73 6f 6c 65 41 70 70 31 5c 5c 43 6f 6e 73 6f 6c 65 41 70 70 31 5c 5c 6f 62 6a 5c 5c 44 65 62 75 67 5c 5c 43 6f 6e 73 6f 6c 65 41 70 70 31 2e 70 64 62}
		$sqlitestr = {4e 00 6f 00 74 00 20 00 61 00 20 00 76 00 61 00 6c 00 69 00 64 00 20 00 53 00 51 00 4c 00 69 00 74 00 65 00 20 00 33 00 20 00 44 00 61 00 74 00 61 00 62 00 61 00 73 00 65 00 20 00 46 00 69 00 6c 00 65 00}

	condition:
		all of them
}

rule Agenttesla_type2 : hardened
{
	meta:
		description = "detect Agenttesla in memory"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "memory scan"
		reference = "internal research"
		hash1 = "670a00c65eb6f7c48c1e961068a1cb7fd3653bd29377161cd04bf15c9d010da2 "
		ruleset = "rule.yara"
		repository = "JPCERTCC/MalConfScan"
		source_url = "https://github.com/JPCERTCC/MalConfScan/blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara"
		license = "Other"
		score = 75

	strings:
		$type2db1 = {31 00 2e 00 38 00 35 00 20 00 28 00 48 00 61 00 73 00 68 00 2c 00 20 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 20 00 32 00 2c 00 20 00 6e 00 61 00 74 00 69 00 76 00 65 00 20 00 62 00 79 00 74 00 65 00 2d 00 6f 00 72 00 64 00 65 00 72 00 29 00}
		$type2db2 = {55 00 6e 00 6b 00 6e 00 6f 00 77 00 20 00 64 00 61 00 74 00 61 00 62 00 61 00 73 00 65 00 20 00 66 00 6f 00 72 00 6d 00 61 00 74 00}
		$type2db3 = {53 00 51 00 4c 00 69 00 74 00 65 00 20 00 66 00 6f 00 72 00 6d 00 61 00 74 00 20 00 33 00}
		$type2db4 = {42 00 65 00 72 00 6b 00 65 00 6c 00 65 00 74 00 20 00 44 00 42 00}

	condition:
		( uint16( 0 ) == 0x5A4D ) and 3 of them
}

rule Windows_Trojan_AgentTesla_d3ac2b2f_1 : hardened
{
	meta:
		id = "d3ac2b2f-14fc-4851-8a57-41032e386aeb"
		fingerprint = "60c031526f8c3099f324b9dccaad3e8e7fb60c85ef79237aa9917e128b072c14"
		creation_date = "2021-03-22"
		last_modified = "2021-04-12"
		os = "Windows"
		arch = "x86"
		category_type = "Trojan"
		family = "AgentTesla"
		threat_name = "Windows.Trojan.AgentTesla"
		source = "Manual"
		maturity = "Diagnostic"
		reference_sample = "65463161760af7ab85f5c475a0f7b1581234a1e714a2c5a555783bdd203f85f4"
		scan_type = "File, Memory"
		severity = 100
		original_yara_name = "Windows_Trojan_AgentTesla_d3ac2b2f"
		ruleset = "elastic-agent-rules.yara"
		repository = "SpecterOps/Nemesis"
		source_url = "https://github.com/SpecterOps/Nemesis/blob/84d5986f759161f60dc2e5b538ec88d95b289e43/cmd/enrichment/enrichment/lib/public_yara/elastic-agent-rules.yara"
		license = "Other"
		score = 75

	strings:
		$a1 = {47 65 74 4d 6f 7a 69 6c 6c 61 46 72 6f 6d 4c 6f 67 69 6e 73}
		$a2 = {41 00 63 00 63 00 6f 00 75 00 6e 00 74 00 43 00 6f 00 6e 00 66 00 69 00 67 00 75 00 72 00 61 00 74 00 69 00 6f 00 6e 00 2b 00 75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00}
		$a3 = {4d 61 69 6c 41 63 63 6f 75 6e 74 43 6f 6e 66 69 67 75 72 61 74 69 6f 6e}
		$a4 = {4b 69 6c 6c 54 6f 72 50 72 6f 63 65 73 73}
		$a5 = {53 6d 74 70 41 63 63 6f 75 6e 74 43 6f 6e 66 69 67 75 72 61 74 69 6f 6e}
		$a6 = {47 65 74 4d 6f 7a 69 6c 6c 61 46 72 6f 6d 53 51 4c 69 74 65}
		$a7 = {50 00 72 00 6f 00 78 00 79 00 2d 00 41 00 67 00 65 00 6e 00 74 00 3a 00 20 00 48 00 54 00 6f 00 53 00 35 00 78 00}
		$a8 = {73 65 74 5f 42 69 6e 64 69 6e 67 41 63 63 6f 75 6e 74 43 6f 6e 66 69 67 75 72 61 74 69 6f 6e}
		$a9 = {64 6f 55 73 65 72 6e 61 6d 65 50 61 73 73 77 6f 72 64 41 75 74 68}
		$a10 = {53 61 66 61 72 69 44 65 63 72 79 70 74 6f 72}
		$a11 = {67 65 74 5f 73 65 63 75 72 69 74 79 50 72 6f 66 69 6c 65}
		$a12 = {67 65 74 5f 75 73 65 53 65 70 61 72 61 74 65 46 6f 6c 64 65 72 54 72 65 65}
		$a13 = {67 65 74 5f 44 6e 73 52 65 73 6f 6c 76 65 72}
		$a14 = {67 65 74 5f 61 72 63 68 69 76 69 6e 67 53 63 6f 70 65}
		$a15 = {67 65 74 5f 70 72 6f 76 69 64 65 72 4e 61 6d 65}
		$a16 = {67 65 74 5f 43 6c 69 70 62 6f 61 72 64 48 6f 6f 6b}
		$a17 = {67 65 74 5f 70 72 69 6f 72 69 74 79}
		$a18 = {67 65 74 5f 61 64 76 61 6e 63 65 64 50 61 72 61 6d 65 74 65 72 73}
		$a19 = {67 65 74 5f 64 69 73 61 62 6c 65 64 42 79 52 65 73 74 72 69 63 74 69 6f 6e}
		$a20 = {67 65 74 5f 4c 61 73 74 41 63 63 65 73 73 65 64}
		$a21 = {67 65 74 5f 61 76 61 74 61 72 54 79 70 65}
		$a22 = {67 65 74 5f 73 69 67 6e 61 74 75 72 65 50 72 65 73 65 74 73}
		$a23 = {67 65 74 5f 65 6e 61 62 6c 65 4c 6f 67}
		$a24 = {54 65 6c 65 67 72 61 6d 4c 6f 67}
		$a25 = {67 65 6e 65 72 61 74 65 4b 65 79 56 37 35}
		$a26 = {73 65 74 5f 61 63 63 6f 75 6e 74 4e 61 6d 65}
		$a27 = {73 65 74 5f 49 6e 74 65 72 6e 61 6c 53 65 72 76 65 72 50 6f 72 74}
		$a28 = {73 65 74 5f 62 69 6e 64 69 6e 67 43 6f 6e 66 69 67 75 72 61 74 69 6f 6e 55 49 44}
		$a29 = {73 65 74 5f 49 64 6e 41 64 64 72 65 73 73}
		$a30 = {73 65 74 5f 47 75 69 64 4d 61 73 74 65 72 4b 65 79}
		$a31 = {6d 5f 4d 79 57 65 62 53 65 72 76 69 63 65 73 4f 62 6a 65 63 74 50 72 6f 76 69 64 65 72}
		$a32 = {6d 5f 55 73 65 72 4f 62 6a 65 63 74 50 72 6f 76 69 64 65 72}
		$a33 = {6d 5f 43 6f 6d 70 75 74 65 72 4f 62 6a 65 63 74 50 72 6f 76 69 64 65 72}
		$a34 = {6d 5f 54 68 72 65 61 64 53 74 61 74 69 63 56 61 6c 75 65}
		$a35 = {73 65 74 5f 75 73 65 72 6e 61 6d 65}
		$a36 = {73 65 74 5f 76 65 72 73 69 6f 6e}

	condition:
		8 of ( $a* )
}

rule fsAgentTesla : hardened
{
	meta:
		description = "FsYARA - Malware Trends"
		vetted_family = "agenttesla"
		score = 75

	condition:
		AgentTesla or AgentTeslaV2 or AgentTeslaV3 or AgentTeslaXor or AgentTeslaV4 or AgentTeslaV4JIT or AgentTeslaV5 or Windows_Trojan_AgentTesla_d3ac2b2f or Windows_Trojan_AgentTesla_e577e17e or Windows_Trojan_AgentTesla_f2a90d14 or Windows_Trojan_AgentTesla_a2d69e48 or Windows_Trojan_AgentTesla_ebf431a8 or Win32_Trojan_AgentTesla or agenttesla_smtp_variant or AgentTeslaV3_1 or Agenttesla_type1 or Agenttesla_type2 or Windows_Trojan_AgentTesla_d3ac2b2f_1
}

