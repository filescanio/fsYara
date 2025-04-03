rule dubseven_file_set : hardened
{
	meta:
		author = "Matt Brooks, @cmatthewbrooks"
		date = "2016/04/18"
		score = 75
		description = "Searches for service files loading UP007"
		id = "5b0a9cb9-aeef-5508-8854-51ad846b22c5"

	strings:
		$file1 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 63 6f 6e 68 6f 73 74 2e 65 78 65}
		$file2 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 64 6c 6c 32 2e 78 6f 72}
		$file3 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 48 4f 4f 4b 2e 44 4c 4c}
		$file4 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 6d 61 69 6e 2e 64 6c 6c}
		$file5 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 6e 76 73 76 63 2e 65 78 65}
		$file6 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 53 42 69 65 44 6c 6c 2e 64 6c 6c}
		$file7 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 6d 6f 6e}
		$file8 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 72 75 6e 61 73 2e 65 78 65}

	condition:
		uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 and 3 of ( $file* )
}

rule dubseven_dropper_registry_checks : hardened
{
	meta:
		author = "Matt Brooks, @cmatthewbrooks"
		date = "2016/04/18"
		score = 75
		description = "Searches for registry keys checked for by the dropper"
		id = "8369cdbb-53b8-5dc5-9181-fd49747042a7"

	strings:
		$reg1 = {53 4f 46 54 57 41 52 45 5c 33 36 30 53 61 66 65 5c 4c 69 76 65 75 70}
		$reg2 = {53 6f 66 74 77 61 72 65 5c 33 36 30 73 61 66 65}
		$reg3 = {53 4f 46 54 57 41 52 45 5c 6b 69 6e 67 73 6f 66 74 5c 41 6e 74 69 76 69 72 75 73}
		$reg4 = {53 4f 46 54 57 41 52 45 5c 41 76 69 72 61 5c 41 76 69 72 61 20 44 65 73 74 6f 70}
		$reg5 = {53 4f 46 54 57 41 52 45 5c 72 69 73 69 6e 67 5c 52 41 56}
		$reg6 = {53 4f 46 54 57 41 52 45 5c 4a 69 61 6e 67 4d 69 6e}
		$reg7 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 70 6f 69 6e 74 5c 41 6e 74 69 2d 41 74 74 61 63 6b}

	condition:
		uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 and all of ( $reg* )
}

rule dubseven_dropper_dialog_remains : hardened
{
	meta:
		author = "Matt Brooks, @cmatthewbrooks"
		date = "2016/04/18"
		score = 75
		description = "Searches for related dialog remnants. How rude."
		id = "6029ea74-26fc-57d1-aaed-be1ea2138844"

	strings:
		$dia1 = {66 00 75 00 63 00 6b 00 4d 00 65 00 73 00 73 00 61 00 67 00 65 00 42 00 6f 00 78 00 20 00 31 00 2e 00 30 00}
		$dia2 = {52 00 75 00 6e 00 64 00 6c 00 6c 00 20 00 31 00 2e 00 30 00}

	condition:
		uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 and any of them
}

rule maindll_mutex : hardened
{
	meta:
		author = "Matt Brooks, @cmatthewbrooks"
		date = "2016/04/18"
		score = 75
		description = "Matches on the maindll mutex"
		id = "7a89dae3-9e03-5803-9729-78e6e65e91d3"

	strings:
		$mutex = {68 33 31 34 31 35 39 32 37 74 74 74 74}

	condition:
		uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 and $mutex
}

rule SLServer_dialog_remains : hardened limited
{
	meta:
		author = "Matt Brooks, @cmatthewbrooks / modified by Florian Roth"
		date = "2016/04/18"
		score = 75
		description = "Searches for related dialog remnants."
		id = "cf199d25-ce5e-52c2-88de-32a48dee4c6f"

	strings:
		$slserver = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 53 00 4c 00 53 00 65 00 72 00 76 00 65 00 72 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$fp1 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 44 00 65 00 6c 00 6c 00 20 00 49 00 6e 00 63 00 2e 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$fp2 = {53 00 63 00 72 00 69 00 70 00 74 00 4c 00 6f 00 67 00 69 00 63 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00}
		$extra1 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 53 00 4c 00 53 00 45 00 52 00 56 00 45 00 52 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$extra2 = {5c 53 4c 53 65 72 76 65 72 2e 70 64 62}

	condition:
		uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 and not 1 of ( $fp* ) and 1 of ( $extra* ) and $slserver
}

rule SLServer_mutex : hardened
{
	meta:
		author = "Matt Brooks, @cmatthewbrooks"
		date = "2016/04/18"
		score = 75
		description = "Searches for the mutex."
		id = "decdefd0-fe20-5adf-9d8c-0e2b954481a0"

	strings:
		$mutex = {4d 26 47 58 5e 44 53 46 26 44 41 40 46}

	condition:
		uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 and $mutex
}

rule SLServer_command_and_control : hardened
{
	meta:
		author = "Matt Brooks, @cmatthewbrooks"
		date = "2016/04/18"
		score = 75
		description = "Searches for the C2 server."
		id = "e4fcda6c-1c9f-5b58-8b07-8d1a0dc4eaf6"

	strings:
		$c2 = {73 61 66 65 74 79 73 73 6c 2e 73 65 63 75 72 69 74 79 2d 63 65 6e 74 65 72 73 2e 63 6f 6d}

	condition:
		uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 and $c2
}

rule SLServer_campaign_code : hardened
{
	meta:
		author = "Matt Brooks, @cmatthewbrooks"
		date = "2016/04/18"
		score = 75
		description = "Searches for the related campaign code."
		id = "672f506e-0cc1-5b09-873b-c3d206486bac"

	strings:
		$campaign = {77 74 68 6b 64 6f 63 30 31 30 36}

	condition:
		uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 and $campaign
}

rule SLServer_unknown_string : hardened
{
	meta:
		author = "Matt Brooks, @cmatthewbrooks"
		date = "2016/04/18"
		score = 75
		description = "Searches for a unique string."
		id = "00341604-480f-59aa-9c18-009e7b53928e"

	strings:
		$string = {74 65 73 74 2d 62 37 66 61 38 33 35 61 33 39}

	condition:
		uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 and $string
}

