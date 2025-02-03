rule CrowdStrike_Shamoon_DroppedFile : hardened
{
	meta:
		description = "Rule to detect Shamoon malware http://goo.gl/QTxohN"
		reference = "http://www.rsaconference.com/writable/presentations/file_upload/exp-w01-hacking-exposed-day-of-destruction.pdf"

	strings:
		$testn123 = {74 00 65 00 73 00 74 00 31 00 32 00 33 00}
		$testn456 = {74 00 65 00 73 00 74 00 34 00 35 00 36 00}
		$testn789 = {74 00 65 00 73 00 74 00 37 00 38 00 39 00}
		$testdomain = {74 00 65 00 73 00 74 00 64 00 6f 00 6d 00 61 00 69 00 6e 00 2e 00 63 00 6f 00 6d 00}
		$pingcmd = {70 00 69 00 6e 00 67 00 20 00 2d 00 6e 00 20 00 33 00 30 00 20 00 31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 20 00 3e 00 6e 00 75 00 6c 00}

	condition:
		( any of ( $testn* ) or $pingcmd ) and $testdomain
}

rule Shamoon2_Wiper : hardened
{
	meta:
		description = "Detects Shamoon 2.0 Wiper Component"
		author = "Florian Roth"
		reference = "https://goo.gl/jKIfGB"
		date = "2016-12-01"
		score = 70
		hash1 = "c7fc1f9c2bed748b50a599ee2fa609eb7c9ddaeb9cd16633ba0d10cf66891d8a"
		hash2 = "128fa5815c6fee68463b18051c1a1ccdf28c599ce321691686b1efa4838a2acd"

	strings:
		$a1 = {5c 00 3f 00 3f 00 5c 00 25 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 25 00 73 00 2e 00 65 00 78 00 65 00}
		$x1 = {49 00 57 00 48 00 42 00 57 00 57 00 48 00 56 00 43 00 49 00 44 00 42 00 52 00 41 00 46 00 55 00 41 00 53 00 49 00 49 00 57 00 55 00 52 00 52 00 54 00 57 00 52 00 54 00 49 00 42 00 49 00 56 00 4a 00 44 00 47 00 57 00 54 00 52 00 52 00 52 00 45 00 46 00 44 00 45 00 41 00 45 00 42 00 49 00 41 00 45 00 42 00 4a 00 47 00 47 00 43 00 53 00 56 00 55 00 48 00 47 00 56 00 4a 00 55 00 48 00 41 00 44 00 49 00 45 00 57 00 41 00 46 00 47 00 57 00 41 00 44 00 52 00 55 00 57 00 44 00 54 00 4a 00 42 00 48 00 54 00 53 00 49 00 54 00 44 00 56 00 56 00 42 00 43 00 49 00 44 00 43 00 57 00 48 00 52 00 48 00 56 00 54 00 44 00 56 00 43 00 44 00 45 00 53 00 54 00 48 00 57 00 53 00 55 00 41 00 45 00 48 00 47 00 54 00 57 00 54 00 4a 00 57 00 46 00 49 00 52 00 54 00 42 00 52 00 42 00}
		$s1 = {55 00 46 00 57 00 59 00 4e 00 59 00 4e 00 54 00 53 00}
		$s2 = {5c 00 5c 00 3f 00 5c 00 45 00 6c 00 52 00 61 00 77 00 44 00 69 00 73 00 6b 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 1000KB and 2 of them ) or ( 3 of them )
}

rule Shamoon2_ComComp : hardened
{
	meta:
		description = "Detects Shamoon 2.0 Communication Components"
		author = "Florian Roth (with Binar.ly)"
		reference = "https://goo.gl/jKIfGB"
		date = "2016-12-01"
		score = 70
		hash1 = "61c1c8fc8b268127751ac565ed4abd6bdab8d2d0f2ff6074291b2d54b0228842"

	strings:
		$s1 = {6d 6b 64 69 72 20 25 73 25 73 20 3e 20 6e 75 6c 20 32 3e 26 31}
		$s2 = {70 5b 25 73 25 73 25 64 2e 25 73}
		$op1 = { 04 32 cb 88 04 37 88 4c 37 01 88 54 37 02 83 c6 }
		$op2 = { c8 02 d2 c0 e9 06 02 d2 24 3f 02 d1 88 45 fb 8d }
		$op3 = { 0c 3b 40 8d 4e 01 47 3b c1 7c d8 83 fe 03 7d 1c }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 500KB and ( all of ( $s* ) or all of ( $op* ) )
}

rule EldoS_RawDisk : hardened
{
	meta:
		description = "EldoS Rawdisk Device Driver (Commercial raw disk access driver - used in Operation Shamoon 2.0)"
		author = "Florian Roth (with Binar.ly)"
		reference = "https://goo.gl/jKIfGB"
		date = "2016-12-01"
		score = 50
		hash1 = "47bb36cd2832a18b5ae951cf5a7d44fba6d8f5dca0a372392d40f51d1fe1ac34"
		hash2 = "394a7ebad5dfc13d6c75945a61063470dc3b68f7a207613b79ef000e1990909b"

	strings:
		$s1 = {67 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00}
		$s2 = {7a 00 74 00 76 00 74 00 74 00 77 00}
		$s3 = {6c 77 69 7a 76 6d}
		$s4 = {46 45 4a 49 4b 43}
		$s5 = {49 4e 5a 51 4e 44}
		$s6 = {49 00 55 00 54 00 4c 00 4f 00 4d 00}
		$s7 = {44 4b 46 4b 43 4b}
		$op1 = { 94 35 77 73 03 40 eb e9 }
		$op2 = { 80 7c 41 01 00 74 0a 3d }
		$op3 = { 74 0a 3d 00 94 35 77 }

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 2000KB and 4 of them )
}

rule Shamoon_Disttrack_Dropper : hardened
{
	meta:
		description = "Detects Shamoon 2.0 Disttrack Dropper"
		author = "Florian Roth"
		reference = "https://goo.gl/jKIfGB"
		date = "2016-12-01"
		score = 70
		hash1 = "4744df6ac02ff0a3f9ad0bf47b15854bbebb73c936dd02f7c79293a2828406f6"
		hash2 = "5a826b4fa10891cf63aae832fc645ce680a483b915c608ca26cedbb173b1b80a"

	strings:
		$a1 = {5c 00 23 00 7b 00 39 00 41 00 36 00 44 00 42 00 37 00 44 00 32 00 2d 00 46 00 45 00 43 00 46 00 2d 00 34 00 31 00 66 00 66 00 2d 00 39 00 41 00 39 00 32 00 2d 00 36 00 45 00 44 00 41 00 36 00 39 00 36 00 36 00 31 00 33 00 44 00 46 00 7d 00 23 00}
		$a2 = {5c 00 23 00 7b 00 38 00 41 00 36 00 44 00 42 00 37 00 44 00 32 00 2d 00 46 00 45 00 43 00 46 00 2d 00 34 00 31 00 66 00 66 00 2d 00 39 00 41 00 39 00 32 00 2d 00 36 00 45 00 44 00 41 00 36 00 39 00 36 00 36 00 31 00 33 00 44 00 45 00 7d 00 23 00}
		$s1 = {5c 61 6d 64 36 34 5c 65 6c 72 61 77 64 73 6b 2e 70 64 62}
		$s2 = {52 00 61 00 77 00 44 00 69 00 73 00 6b 00 53 00 61 00 6d 00 70 00 6c 00 65 00 2e 00 65 00 78 00 65 00}
		$s3 = {52 00 61 00 77 00 44 00 69 00 73 00 6b 00 20 00 44 00 72 00 69 00 76 00 65 00 72 00 2e 00 20 00 41 00 6c 00 6c 00 6f 00 77 00 73 00 20 00 77 00 72 00 69 00 74 00 65 00 20 00 61 00 63 00 63 00 65 00 73 00 73 00 20 00 74 00 6f 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 61 00 6e 00 64 00 20 00 72 00 61 00 77 00 20 00 64 00 69 00 73 00 6b 00 20 00 73 00 65 00 63 00 74 00 6f 00 72 00 73 00 20 00 66 00 6f 00 72 00 20 00 75 00 73 00 65 00 72 00 20 00 6d 00 6f 00 64 00 65 00 20 00 61 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 73 00 20 00 69 00 6e 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 32 00 30 00 30 00 30 00 20 00 61 00 6e 00 64 00 20 00 6c 00 61 00 74 00 65 00 72 00 2e 00}
		$s4 = {65 00 6c 00 72 00 61 00 77 00 64 00 73 00 6b 00 2e 00 73 00 79 00 73 00}
		$s5 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 45 00 6c 00 52 00 61 00 77 00 44 00 69 00 73 00 6b 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 90KB and 1 of ( $a* ) and 1 of ( $s* ) )
}

