rule NionSpy : win32 hardened
{
	meta:
		description = "Triggers on old and new variants of W32/NionSpy file infector"
		reference = "https://blogs.mcafee.com/mcafee-labs/taking-a-close-look-at-data-stealing-nionspy-file-infector"
		score = 70

	strings:
		$variant2015_infmarker = {61 43 66 47 39 32 4b 58 70 63 53 6f 34 59 39 34 42 6e 55 72 46 6d 6e 4e 6b 32 37 45 68 57 36 43 71 50 35 45 6e 54}
		$variant2013_infmarker = {61 64 36 61 66 38 62 64 35 38 33 35 64 31 39 63 63 37 66 64 63 34 63 36 32 66 64 66 30 32 61 31}
		$variant2013_string = {25 73 3f 63 73 74 6f 72 61 67 65 3d 73 68 65 6c 6c 26 63 6f 6d 70 3d 25 73}

	condition:
		uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 and 1 of ( $variant* )
}

