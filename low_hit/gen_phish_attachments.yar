rule SUSP_ZIP_LNK_PhishAttachment_Pattern_Jun22_1 : hardened
{
	meta:
		description = "Detects suspicious tiny ZIP files with phishing attachment characteristics"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2022-06-23"
		score = 65
		hash1 = "4edb41f4645924d8a73e7ac3e3f39f4db73e38f356bc994ad7d03728cd799a48"
		hash2 = "c4fec375b44efad2d45c49f30133efbf6921ce82dbb2d1a980f69ea6383b0ab4"
		hash3 = "9c70eeac97374213355ea8fa019a0e99e0e57c8efc43daa3509f9f98fa71c8e4"
		hash4 = "ddc20266e38a974a28af321ab82eedaaf51168fbcc63ac77883d8be5200dcaf9"
		hash5 = "b59788ae984d9e70b4f7f5a035b10e6537063f15a010652edd170fc6a7e1ea2f"
		id = "3537c4ea-a51d-5100-97d7-71a24da5ff43"

	strings:
		$sl1 = {2e 6c 6e 6b}

	condition:
		uint16( 0 ) == 0x4b50 and filesize < 2KB and $sl1 in ( filesize - 256 .. filesize )
}

rule SUSP_ZIP_ISO_PhishAttachment_Pattern_Jun22_1 : hardened
{
	meta:
		description = "Detects suspicious small base64 encoded ZIP files (MIME email attachments) with .iso files as content as often used in phishing attacks"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2022-06-23"
		score = 65
		id = "638541a6-d2d4-513e-978c-9d1b9f5e3b71"

	strings:
		$pkzip_base64_1 = { 0A 55 45 73 44 42 }
		$pkzip_base64_2 = { 0A 55 45 73 44 42 }
		$pkzip_base64_3 = { 0A 55 45 73 48 43 }
		$iso_1 = {4c 6d 6c 7a 62 31 42 4c}
		$iso_2 = {35 70 63 32 39 51 53}
		$iso_3 = {75 61 58 4e 76 55 45}

	condition:
		filesize < 2000KB and 1 of ( $pk* ) and 1 of ( $iso* )
}

rule SUSP_Archive_Phishing_Attachment_Characteristics_Jun22_1 : hardened
{
	meta:
		description = "Detects characteristics of suspicious file names or double extensions often found in phishing mail attachments"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/0xtoxin/status/1540524891623014400?s=12&t=IQ0OgChk8tAIdTHaPxh0Vg"
		date = "2022-06-29"
		score = 65
		hash1 = "caaa5c5733fca95804fffe70af82ee505a8ca2991e4cc05bc97a022e5f5b331c"
		hash2 = "a746d8c41609a70ce10bc69d459f9abb42957cc9626f2e83810c1af412cb8729"
		id = "3cb8c371-f40b-5773-84d1-3bce37da529e"

	strings:
		$sa01 = {49 4e 56 4f 49 43 45 2e 65 78 65 50 4b}
		$sa02 = {50 41 59 4d 45 4e 54 2e 65 78 65 50 4b}
		$sa03 = {52 45 51 55 45 53 54 2e 65 78 65 50 4b}
		$sa04 = {4f 52 44 45 52 2e 65 78 65 50 4b}
		$sa05 = {69 6e 76 6f 69 63 65 2e 65 78 65 50 4b}
		$sa06 = {70 61 79 6d 65 6e 74 2e 65 78 65 50 4b}
		$sa07 = {5f 72 65 71 75 65 73 74 2e 65 78 65 50 4b}
		$sa08 = {5f 6f 72 64 65 72 2e 65 78 65 50 4b}
		$sa09 = {2d 72 65 71 75 65 73 74 2e 65 78 65 50 4b}
		$sa10 = {2d 6f 72 64 65 72 2e 65 78 65 50 4b}
		$sa11 = {20 72 65 71 75 65 73 74 2e 65 78 65 50 4b}
		$sa12 = {20 6f 72 64 65 72 2e 65 78 65 50 4b}
		$sa14 = {2e 64 6f 63 2e 65 78 65 50 4b}
		$sa15 = {2e 64 6f 63 78 2e 65 78 65 50 4b}
		$sa16 = {2e 78 6c 73 2e 65 78 65 50 4b}
		$sa17 = {2e 78 6c 73 78 2e 65 78 65 50 4b}
		$sa18 = {2e 70 64 66 2e 65 78 65 50 4b}
		$sa19 = {2e 70 70 74 2e 65 78 65 50 4b}
		$sa20 = {2e 70 70 74 78 2e 65 78 65 50 4b}
		$sa21 = {2e 72 74 66 2e 65 78 65 50 4b}
		$sa22 = {2e 74 78 74 2e 65 78 65 50 4b}
		$sb01 = {53 55 35 57 54 30 6c 44 52 53 35 6c 65 47 56 51 53}
		$sb02 = {6c 4f 56 6b 39 4a 51 30 55 75 5a 58 68 6c 55 45}
		$sb03 = {4a 54 6c 5a 50 53 55 4e 46 4c 6d 56 34 5a 56 42 4c}
		$sb04 = {55 45 46 5a 54 55 56 4f 56 43 35 6c 65 47 56 51 53}
		$sb05 = {42 42 57 55 31 46 54 6c 51 75 5a 58 68 6c 55 45}
		$sb06 = {51 51 56 6c 4e 52 55 35 55 4c 6d 56 34 5a 56 42 4c}
		$sb07 = {55 6b 56 52 56 55 56 54 56 43 35 6c 65 47 56 51 53}
		$sb08 = {4a 46 55 56 56 46 55 31 51 75 5a 58 68 6c 55 45}
		$sb09 = {53 52 56 46 56 52 56 4e 55 4c 6d 56 34 5a 56 42 4c}
		$sb10 = {54 31 4a 45 52 56 49 75 5a 58 68 6c 55 45}
		$sb11 = {39 53 52 45 56 53 4c 6d 56 34 5a 56 42 4c}
		$sb12 = {50 55 6b 52 46 55 69 35 6c 65 47 56 51 53}
		$sb13 = {61 57 35 32 62 32 6c 6a 5a 53 35 6c 65 47 56 51 53}
		$sb14 = {6c 75 64 6d 39 70 59 32 55 75 5a 58 68 6c 55 45}
		$sb15 = {70 62 6e 5a 76 61 57 4e 6c 4c 6d 56 34 5a 56 42 4c}
		$sb16 = {63 47 46 35 62 57 56 75 64 43 35 6c 65 47 56 51 53}
		$sb17 = {42 68 65 57 31 6c 62 6e 51 75 5a 58 68 6c 55 45}
		$sb18 = {77 59 58 6c 74 5a 57 35 30 4c 6d 56 34 5a 56 42 4c}
		$sb19 = {58 33 4a 6c 63 58 56 6c 63 33 51 75 5a 58 68 6c 55 45}
		$sb20 = {39 79 5a 58 46 31 5a 58 4e 30 4c 6d 56 34 5a 56 42 4c}
		$sb21 = {66 63 6d 56 78 64 57 56 7a 64 43 35 6c 65 47 56 51 53}
		$sb22 = {58 32 39 79 5a 47 56 79 4c 6d 56 34 5a 56 42 4c}
		$sb23 = {39 76 63 6d 52 6c 63 69 35 6c 65 47 56 51 53}
		$sb24 = {66 62 33 4a 6b 5a 58 49 75 5a 58 68 6c 55 45}
		$sb25 = {4c 58 4a 6c 63 58 56 6c 63 33 51 75 5a 58 68 6c 55 45}
		$sb26 = {31 79 5a 58 46 31 5a 58 4e 30 4c 6d 56 34 5a 56 42 4c}
		$sb27 = {74 63 6d 56 78 64 57 56 7a 64 43 35 6c 65 47 56 51 53}
		$sb28 = {4c 57 39 79 5a 47 56 79 4c 6d 56 34 5a 56 42 4c}
		$sb29 = {31 76 63 6d 52 6c 63 69 35 6c 65 47 56 51 53}
		$sb30 = {74 62 33 4a 6b 5a 58 49 75 5a 58 68 6c 55 45}
		$sb31 = {49 48 4a 6c 63 58 56 6c 63 33 51 75 5a 58 68 6c 55 45}
		$sb32 = {42 79 5a 58 46 31 5a 58 4e 30 4c 6d 56 34 5a 56 42 4c}
		$sb33 = {67 63 6d 56 78 64 57 56 7a 64 43 35 6c 65 47 56 51 53}
		$sb34 = {49 47 39 79 5a 47 56 79 4c 6d 56 34 5a 56 42 4c}
		$sb35 = {42 76 63 6d 52 6c 63 69 35 6c 65 47 56 51 53}
		$sb36 = {67 62 33 4a 6b 5a 58 49 75 5a 58 68 6c 55 45}
		$sb37 = {4c 6d 52 76 59 79 35 6c 65 47 56 51 53}
		$sb38 = {35 6b 62 32 4d 75 5a 58 68 6c 55 45}
		$sb39 = {75 5a 47 39 6a 4c 6d 56 34 5a 56 42 4c}
		$sb40 = {4c 6d 52 76 59 33 67 75 5a 58 68 6c 55 45}
		$sb41 = {35 6b 62 32 4e 34 4c 6d 56 34 5a 56 42 4c}
		$sb42 = {75 5a 47 39 6a 65 43 35 6c 65 47 56 51 53}
		$sb43 = {4c 6e 68 73 63 79 35 6c 65 47 56 51 53}
		$sb44 = {35 34 62 48 4d 75 5a 58 68 6c 55 45}
		$sb45 = {75 65 47 78 7a 4c 6d 56 34 5a 56 42 4c}
		$sb46 = {4c 6e 68 73 63 33 67 75 5a 58 68 6c 55 45}
		$sb47 = {35 34 62 48 4e 34 4c 6d 56 34 5a 56 42 4c}
		$sb48 = {75 65 47 78 7a 65 43 35 6c 65 47 56 51 53}
		$sb49 = {4c 6e 42 6b 5a 69 35 6c 65 47 56 51 53}
		$sb50 = {35 77 5a 47 59 75 5a 58 68 6c 55 45}
		$sb51 = {75 63 47 52 6d 4c 6d 56 34 5a 56 42 4c}
		$sb52 = {4c 6e 42 77 64 43 35 6c 65 47 56 51 53}
		$sb53 = {35 77 63 48 51 75 5a 58 68 6c 55 45}
		$sb54 = {75 63 48 42 30 4c 6d 56 34 5a 56 42 4c}
		$sb55 = {4c 6e 42 77 64 48 67 75 5a 58 68 6c 55 45}
		$sb56 = {35 77 63 48 52 34 4c 6d 56 34 5a 56 42 4c}
		$sb57 = {75 63 48 42 30 65 43 35 6c 65 47 56 51 53}
		$sb58 = {4c 6e 4a 30 5a 69 35 6c 65 47 56 51 53}
		$sb59 = {35 79 64 47 59 75 5a 58 68 6c 55 45}
		$sb60 = {75 63 6e 52 6d 4c 6d 56 34 5a 56 42 4c}
		$sb61 = {4c 6e 52 34 64 43 35 6c 65 47 56 51 53}
		$sb62 = {35 30 65 48 51 75 5a 58 68 6c 55 45}
		$sb63 = {75 64 48 68 30 4c 6d 56 34 5a 56 42 4c}

	condition:
		uint16( 0 ) == 0x4b50 and 1 of ( $sa* ) or 1 of ( $sb* )
}

