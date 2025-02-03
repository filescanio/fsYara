rule StuxNet_Malware_1 : hardened
{
	meta:
		description = "Stuxnet Sample - file malware.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2016-07-09"
		hash1 = "9c891edb5da763398969b6aaa86a5d46971bd28a455b20c2067cb512c9f9a0f8"
		id = "1f475dc3-ebb3-508f-b696-3d9ea270b13d"

	strings:
		$op1 = { 8b 45 08 35 dd 79 19 ae 33 c9 8b 55 08 89 02 89 }
		$op2 = { 74 36 8b 7f 08 83 ff 00 74 2e 0f b7 1f 8b 7f 04 }
		$op3 = { 74 70 81 78 05 8d 54 24 04 75 1b 81 78 08 04 cd }

	condition:
		all of them
}

rule Stuxnet_Malware_2 : hardened
{
	meta:
		description = "Stuxnet Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2016-07-09"
		hash1 = "63e6b8136058d7a06dfff4034b4ab17a261cdf398e63868a601f77ddd1b32802"
		id = "2865353c-44c5-5280-878b-daadcef017b8"

	strings:
		$s1 = {5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 68 00 61 00 6c 00 2e 00 64 00 6c 00 6c 00}
		$s2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6a 6d 69 63 72 6f 6e 2e 63 6f 2e 74 77 30}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 70KB and all of them
}

rule StuxNet_dll : hardened
{
	meta:
		description = "Stuxnet Sample - file dll.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2016-07-09"
		hash1 = "9e392277f62206098cf794ddebafd2817483cfd57ec03c2e05e7c3c81e72f562"
		id = "92d812a6-2622-56e4-96c5-eb65ab7055b9"

	strings:
		$s1 = {53 55 43 4b 4d 33 20 46 52 4f 4d 20 45 58 50 4c 4f 52 45 52 2e 45 58 45 20 4d 4f 54 48 34 46 55 43 4b 41 20 23 40 21}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 100KB and $s1
}

rule Stuxnet_Shortcut_to : hardened
{
	meta:
		description = "Stuxnet Sample - file Copy of Shortcut to.lnk"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2016-07-09"
		hash1 = "801e3b6d84862163a735502f93b9663be53ccbdd7f12b0707336fecba3a829a2"
		id = "582ab12b-808e-5d5c-ba36-3bb987c4c552"

	strings:
		$x1 = {5c 00 5c 00 2e 00 5c 00 53 00 54 00 4f 00 52 00 41 00 47 00 45 00 23 00 56 00 6f 00 6c 00 75 00 6d 00 65 00 23 00 5f 00 3f 00 3f 00 5f 00 55 00 53 00 42 00 53 00 54 00 4f 00 52 00 23 00 44 00 69 00 73 00 6b 00 26 00 56 00 65 00 6e 00 5f 00 4b 00 69 00 6e 00 67 00 73 00 74 00 6f 00 6e 00 26 00 50 00 72 00 6f 00 64 00 5f 00 44 00 61 00 74 00 61 00 54 00 72 00 61 00 76 00 65 00 6c 00 65 00 72 00 5f 00 32 00 2e 00 30 00 26 00 52 00 65 00 76 00 5f 00 50 00 4d 00 41 00 50 00 23 00 35 00 42 00 36 00 42 00 30 00 39 00 38 00 42 00 39 00 37 00 42 00 45 00 26 00 30 00 23 00 7b 00 35 00 33 00 66 00 35 00 36 00 33 00 30 00 37 00 2d 00 62 00 36 00 62 00 66 00 2d 00 31 00 31 00 64 00 30 00 2d 00 39 00 34 00 66 00 32 00 2d 00 30 00 30 00 61 00 30 00 63 00}

	condition:
		uint16( 0 ) == 0x004c and filesize < 10KB and $x1
}

rule Stuxnet_Malware_3 : hardened
{
	meta:
		description = "Stuxnet Sample - file ~WTR4141.tmp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2016-07-09"
		hash1 = "6bcf88251c876ef00b2f32cf97456a3e306c2a263d487b0a50216c6e3cc07c6a"
		hash2 = "70f8789b03e38d07584f57581363afa848dd5c3a197f2483c6dfa4f3e7f78b9b"
		id = "1b0b301a-bf29-5080-a7d6-4d5f389bdf50"
		score = 75

	strings:
		$x1 = {53 00 48 00 45 00 4c 00 4c 00 33 00 32 00 2e 00 44 00 4c 00 4c 00 2e 00 41 00 53 00 4c 00 52 00 2e 00}
		$s1 = {7e 00 57 00 54 00 52 00 34 00 31 00 34 00 31 00 2e 00 74 00 6d 00 70 00}
		$s2 = {7e 00 57 00 54 00 52 00 34 00 31 00 33 00 32 00 2e 00 74 00 6d 00 70 00}
		$s3 = {74 00 6f 00 74 00 61 00 6c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00}
		$s4 = {77 00 69 00 6e 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00}
		$s5 = {68 74 74 70 3a 2f 2f 77 77 77 2e 72 65 61 6c 74 65 6b 2e 63 6f 6d 30}
		$s6 = {7b 00 25 00 30 00 38 00 78 00 2d 00 25 00 30 00 38 00 78 00 2d 00 25 00 30 00 38 00 78 00 2d 00 25 00 30 00 38 00 78 00 7d 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 150KB and ( $x1 or 3 of ( $s* ) ) ) or ( 5 of them )
}

rule Stuxnet_Malware_4 : hardened
{
	meta:
		description = "Stuxnet Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2016-07-09"
		hash1 = "0d8c2bcb575378f6a88d17b5f6ce70e794a264cdc8556c8e812f0b5f9c709198"
		hash2 = "1635ec04f069ccc8331d01fdf31132a4bc8f6fd3830ac94739df95ee093c555c"
		id = "fd3fa395-15f1-5a11-9740-03b897e4620b"

	strings:
		$x1 = {5c 6f 62 6a 66 72 65 5f 77 32 6b 5f 78 38 36 5c 69 33 38 36 5c 67 75 61 76 61 2e 70 64 62}
		$x2 = {4d 00 52 00 78 00 43 00 6c 00 73 00 2e 00 73 00 79 00 73 00}
		$x3 = {4d 00 52 00 58 00 4e 00 45 00 54 00 2e 00 53 00 79 00 73 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 80KB and 1 of them ) or ( all of them )
}

rule Stuxnet_maindll_decrypted_unpacked : hardened
{
	meta:
		description = "Stuxnet Sample - file maindll.decrypted.unpacked.dll_"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2016-07-09"
		hash1 = "4c3d7b38339d7b8adf73eaf85f0eb9fab4420585c6ab6950ebd360428af11712"
		id = "7009a41c-0588-5392-ae1c-045e0a5ee56b"

	strings:
		$s1 = {25 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 25 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 44 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 6d 00 72 00 78 00 73 00 6d 00 62 00 2e 00 73 00 79 00 73 00 3b 00 25 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 25 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 44 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 2a 00 2e 00 73 00 79 00 73 00}
		$s2 = {3c 00 41 00 63 00 74 00 69 00 6f 00 6e 00 73 00 20 00 43 00 6f 00 6e 00 74 00 65 00 78 00 74 00 3d 00 22 00 25 00 73 00 22 00 3e 00 3c 00 45 00 78 00 65 00 63 00 3e 00 3c 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 3e 00 25 00 73 00 3c 00 2f 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 3e 00 3c 00 41 00 72 00 67 00 75 00 6d 00 65 00 6e 00 74 00 73 00 3e 00 25 00 73 00 2c 00 23 00 25 00 75 00 3c 00 2f 00 41 00 72 00 67 00 75 00 6d 00 65 00 6e 00 74 00 73 00 3e 00 3c 00 2f 00 45 00 78 00 65 00 63 00 3e 00 3c 00 2f 00 41 00 63 00 74 00 69 00 6f 00 6e 00 73 00 3e 00}
		$s3 = {25 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 25 00 5c 00 69 00 6e 00 66 00 5c 00 6f 00 65 00 6d 00 37 00 41 00 2e 00 50 00 4e 00 46 00}
		$s4 = {25 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 25 00 5c 00 69 00 6e 00 66 00 5c 00 6d 00 64 00 6d 00 63 00 70 00 71 00 33 00 2e 00 50 00 4e 00 46 00}
		$s5 = {25 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 25 00 5c 00 69 00 6e 00 66 00 5c 00 6f 00 65 00 6d 00 36 00 43 00 2e 00 50 00 4e 00 46 00}
		$s6 = {40 00 61 00 62 00 66 00 20 00 76 00 61 00 72 00 62 00 69 00 6e 00 61 00 72 00 79 00 28 00 34 00 30 00 39 00 36 00 29 00 20 00 45 00 58 00 45 00 43 00 20 00 40 00 68 00 72 00 20 00 3d 00 20 00 73 00 70 00 5f 00 4f 00 41 00 43 00 72 00 65 00 61 00 74 00 65 00 20 00 27 00 41 00 44 00 4f 00 44 00 42 00 2e 00 53 00 74 00 72 00 65 00 61 00 6d 00 27 00 2c 00 20 00 40 00 61 00 6f 00 64 00 73 00 20 00 4f 00 55 00 54 00 20 00 49 00 46 00 20 00 40 00 68 00 72 00 20 00 3c 00 3e 00 20 00 30 00 20 00 47 00 4f 00 54 00 4f 00 20 00 65 00 6e 00 64 00 71 00 20 00 45 00 58 00 45 00 43 00 20 00 40 00 68 00 72 00 20 00 3d 00 20 00 73 00 70 00 5f 00 4f 00 41 00 53 00 65 00 74 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 79 00 20 00 40 00}
		$s7 = {53 00 54 00 4f 00 52 00 41 00 47 00 45 00 23 00 56 00 6f 00 6c 00 75 00 6d 00 65 00 23 00 31 00 26 00 31 00 39 00 66 00 37 00 65 00 35 00 39 00 63 00 26 00 30 00 26 00}
		$s8 = {76 69 65 77 20 4d 43 50 56 52 45 41 44 56 41 52 50 45 52 43 4f 4e 20 61 73 20 73 65 6c 65 63 74 20 56 41 52 49 41 42 4c 45 49 44 2c 56 41 52 49 41 42 4c 45 54 59 50 45 49 44 2c 46 4f 52 4d 41 54 46 49 54 54 49 4e 47 2c 53 43 41 4c 45 49 44 2c 56 41 52 49 41 42 4c 45 4e 41 4d 45 2c 41 44 44 52 45 53 53 50 41 52 41 4d 45 54 45 52 2c 50 52 4f 54 4f 4b 4f 4c 4c 2c 4d 41 58 4c 49 4d 49}

	condition:
		6 of them
}

rule Stuxnet_s7hkimdb : hardened
{
	meta:
		description = "Stuxnet Sample - file s7hkimdb.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2016-07-09"
		hash1 = "4071ec265a44d1f0d42ff92b2fa0b30aafa7f6bb2160ed1d0d5372d70ac654bd"
		id = "e4cb277f-5eee-5405-9d48-d06657392323"

	strings:
		$x1 = {53 00 37 00 48 00 4b 00 49 00 4d 00 44 00 58 00 2e 00 44 00 4c 00 4c 00}
		$op1 = { 8b 45 08 35 dd 79 19 ae 33 c9 8b 55 08 89 02 89 }
		$op2 = { 74 36 8b 7f 08 83 ff 00 74 2e 0f b7 1f 8b 7f 04 }
		$op3 = { 74 70 81 78 05 8d 54 24 04 75 1b 81 78 08 04 cd }

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 40KB and $x1 and all of ( $op* ) )
}

