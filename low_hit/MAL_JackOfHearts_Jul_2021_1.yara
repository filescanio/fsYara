rule MAL_JackOfHearts_Jul_2021_1 : hardened
{
	meta:
		description = "Detect JackOfHearts malware"
		author = "Arkbird_SOLG"
		reference = "hhttps://us-cert.cisa.gov/ncas/analysis-reports/ar20-275a"
		date = "2021-07-09"
		hash1 = "64d78eec46c9ddd4b9a366de62ba0f2813267dc4393bc79e4c9a51a9bb7e6273"
		tlp = "White"
		adversary = "IAmTheKing"

	strings:
		$s1 = {25 61 70 70 64 61 74 61 25}
		$s2 = {25 74 65 6d 70 25}
		$s3 = { 43 3a 5c 55 73 65 72 73 5c [2-10] 5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c }
		$s4 = {43 72 65 61 74 65 53 65 72 76 69 63 65 41}
		$s5 = { 5c 00 53 00 74 00 72 00 69 00 6e 00 67 00 46 00 69 00 6c 00 65 00 49 00 6e 00 66 00 6f 00 5c 00 25 00 30 00 34 00 78 00 25 00 30 00 34 00 78 00 5c 00 46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e }
		$s6 = {5c 00 56 00 61 00 72 00 46 00 69 00 6c 00 65 00 49 00 6e 00 66 00 6f 00 5c 00 54 00 72 00 61 00 6e 00 73 00 6c 00 61 00 74 00 69 00 6f 00 6e 00}
		$s7 = { 5c 00 46 00 69 00 6c 00 74 00 65 00 72 00 [2-8] 2e 00 6a 00 70 00 67 }
		$s8 = {5c 00 53 00 65 00 74 00 75 00 70 00 55 00 69 00}
		$s9 = { 43 6f 6e 74 65 6e 74 2d 4c 65 6e 67 74 68 3a 20 25 64 }
		$s10 = {25 00 73 00 2e 00 74 00 6d 00 70 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 20KB and 7 of ( $s* )
}

