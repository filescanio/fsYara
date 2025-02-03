rule Nanocore_RAT_Gen_1 : hardened
{
	meta:
		description = "Detetcs the Nanocore RAT and similar malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.sentinelone.com/blogs/teaching-an-old-rat-new-tricks/"
		date = "2016-04-22"
		score = 70
		hash1 = "e707a7745e346c5df59b5aa4df084574ae7c204f4fb7f924c0586ae03b79bf06"
		id = "b007e0ce-e64f-5027-95ff-d178383e3b59"

	strings:
		$x1 = {43 3a 5c 55 73 65 72 73 5c 4c 6f 67 69 6e 74 65 63 68 5c 44 72 6f 70 62 6f 78 5c 50 72 6f 6a 65 63 74 73 5c 4e 65 77 20 66 6f 6c 64 65 72 5c 4c 61 74 65 73 74 5c 42 65 6e 63 68 6d 61 72 6b 5c 42 65 6e 63 68 6d 61 72 6b 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 42 65 6e 63 68 6d 61 72 6b 2e 70 64 62}
		$x2 = {52 75 6e 50 45 31}
		$x3 = {30 38 32 42 38 43 37 44 33 46 39 31 30 35 44 43 36 36 41 37 45 33 32 36 37 43 39 37 35 30 43 46 34 33 45 39 44 33 32 35}
		$x4 = {24 33 37 34 65 30 37 37 35 2d 65 38 39 33 2d 34 65 37 32 2d 38 30 36 63 2d 61 38 64 38 38 30 61 34 39 61 65 37}
		$x5 = {4d 6f 6e 69 74 6f 72 69 6e 6a 65 63 74 69 6f 6e}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 100KB and ( 1 of them ) ) or ( 3 of them )
}

rule Nanocore_RAT_Gen_2 : hardened
{
	meta:
		description = "Detetcs the Nanocore RAT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 100
		reference = "https://www.sentinelone.com/blogs/teaching-an-old-rat-new-tricks/"
		date = "2016-04-22"
		hash1 = "755f49a4ffef5b1b62f4b5a5de279868c0c1766b528648febf76628f1fe39050"
		id = "74124961-3b0e-5808-b495-90437d3a5999"

	strings:
		$x1 = {4e 61 6e 6f 43 6f 72 65 2e 43 6c 69 65 6e 74 50 6c 75 67 69 6e 48 6f 73 74}
		$x2 = {49 43 6c 69 65 6e 74 4e 65 74 77 6f 72 6b 48 6f 73 74}
		$x3 = {23 3d 71 6a 67 7a 37 6c 6a 6d 70 70 30 4a 37 46 76 4c 39 64 6d 69 38 63 74 4a 49 4c 64 67 74 63 62 77 38 4a 59 55 63 36 47 43 38 4d 65 4a 39 42 31 31 43 72 66 67 32 44 6a 78 63 66 30 70 38 50 5a 47 65}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 1000KB and 1 of them ) or ( all of them )
}

rule Nanocore_RAT_Sample_1 : hardened
{
	meta:
		description = "Detetcs a certain Nanocore RAT sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 75
		reference = "https://www.sentinelone.com/blogs/teaching-an-old-rat-new-tricks/"
		date = "2016-04-22"
		hash2 = "b7cfc7e9551b15319c068aae966f8a9ff563b522ed9b1b42d19c122778e018c8"
		id = "381d3caf-77de-544c-869c-4d9f0cae148f"

	strings:
		$x1 = {54 00 62 00 53 00 69 00 61 00 45 00 64 00 4a 00 54 00 66 00 39 00 6d 00 31 00 75 00 54 00 6e 00 70 00 6a 00 53 00 2e 00 6e 00 39 00 6e 00 39 00 4d 00 37 00 64 00 5a 00 37 00 46 00 48 00 39 00 4a 00 73 00 42 00 41 00 52 00 67 00 4b 00}
		$x2 = {31 45 46 30 44 35 35 38 36 31 36 38 31 44 34 44 32 30 38 45 43 33 30 37 30 42 37 32 30 43 32 31 44 38 38 35 43 42 33 35}
		$x3 = {70 6f 70 74 68 61 74 6b 69 74 74 79 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 900KB and ( 1 of ( $x* ) ) ) or ( all of them )
}

rule Nanocore_RAT_Sample_2 : hardened
{
	meta:
		description = "Detetcs a certain Nanocore RAT sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 75
		reference = "https://www.sentinelone.com/blogs/teaching-an-old-rat-new-tricks/"
		date = "2016-04-22"
		hash1 = "51142d1fb6c080b3b754a92e8f5826295f5da316ec72b480967cbd68432cede1"
		id = "81f6771a-29a3-5fa0-8d24-ea717d3c5251"

	strings:
		$s1 = {55 34 74 53 4f 74 6d 70 4d}
		$s2 = {29 00 55 00 37 00 31 00 55 00 44 00 41 00 55 00 5f 00 51 00 55 00 5f 00 59 00 55 00 5f 00 61 00 55 00 5f 00 69 00 55 00 5f 00 71 00 55 00 5f 00 79 00 55 00 5f 00}
		$s3 = {43 79 34 74 4f 74 54 6d 70 4d 74 54 48 56 46 4f 72 52}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 40KB and all of ( $s* )
}

rule Nanocore_RAT_Feb18_1 : hardened
{
	meta:
		description = "Detects Nanocore RAT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research - T2T"
		date = "2018-02-19"
		hash1 = "aa486173e9d594729dbb5626748ce10a75ee966481b68c1b4f6323c827d9658c"
		id = "6db0c8a7-8c31-58a6-8732-de6663fec16b"

	strings:
		$x1 = {4e 61 6e 6f 43 6f 72 65 20 43 6c 69 65 6e 74 2e 65 78 65}
		$x2 = {4e 61 6e 6f 43 6f 72 65 2e 43 6c 69 65 6e 74 50 6c 75 67 69 6e 48 6f 73 74}
		$s1 = {50 6c 75 67 69 6e 43 6f 6d 6d 61 6e 64}
		$s2 = {46 69 6c 65 43 6f 6d 6d 61 6e 64}
		$s3 = {50 69 70 65 45 78 69 73 74 73}
		$s4 = {50 69 70 65 43 72 65 61 74 65 64}
		$s5 = {49 43 6c 69 65 6e 74 4c 6f 67 67 69 6e 67 48 6f 73 74}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 600KB and ( 1 of ( $x* ) or 5 of them )
}

rule Nanocore_RAT_Feb18_2 : hardened
{
	meta:
		description = "Detects Nanocore RAT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research - T2T"
		date = "2018-02-19"
		hash1 = "377ef8febfd8df1a57a7966043ff0c7b8f3973c2cf666136e6c04080bbf9881a"
		id = "83a8ad4d-0bef-5ba2-aa10-eac5601f2c7b"

	strings:
		$s1 = {52 65 73 4d 61 6e 61 67 65 72 52 75 6e 6e 61 62 6c 65}
		$s2 = {54 72 61 6e 73 66 6f 72 6d 52 75 6e 6e 61 62 6c 65}
		$s3 = {4d 65 74 68 6f 64 49 6e 66 6f 52 75 6e 6e 61 62 6c 65}
		$s4 = {52 65 73 52 75 6e 6e 61 62 6c 65}
		$s5 = {52 75 6e 52 75 6e 6e 61 62 6c 65}
		$s6 = {41 73 6d 52 75 6e 6e 61 62 6c 65}
		$s7 = {52 65 61 64 52 75 6e 6e 61 62 6c 65}
		$s8 = {45 78 69 74 52 75 6e 6e 61 62 6c 65}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1000KB and all of them
}

