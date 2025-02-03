rule GoldenEye_Ransomware_XLS : hardened
{
	meta:
		description = "GoldenEye XLS with Macro - file Schneider-Bewerbung.xls"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/jp2SkT"
		date = "2016-12-06"
		hash1 = "2320d4232ee80cc90bacd768ba52374a21d0773c39895b88cdcaa7782e16c441"
		id = "6eafcc35-56ef-534f-884a-0bb47c27c274"

	strings:
		$x1 = {66 73 6f 2e 47 65 74 54 65 6d 70 4e 61 6d 65 28 29 3b 74 6d 70 5f 70 61 74 68 20 3d 20 74 6d 70 5f 70 61 74 68 2e 72 65 70 6c 61 63 65 28 27 2e 74 6d 70 27 2c 20 27 2e 65 78 65 27 29}
		$x2 = {76 61 72 20 73 68 65 6c 6c 20 3d 20 6e 65 77 20 41 63 74 69 76 65 58 4f 62 6a 65 63 74 28 27 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 27 29 3b 73 68 65 6c 6c 2e 72 75 6e 28 74 27}

	condition:
		( uint16( 0 ) == 0xcfd0 and filesize < 4000KB and 1 of them )
}

