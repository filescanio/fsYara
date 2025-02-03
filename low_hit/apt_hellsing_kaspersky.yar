rule apt_hellsing_implantstrings : hardened limited
{
	meta:
		version = "1.0"
		filetype = "PE"
		author = "Costin Raiu, Kaspersky Lab"
		copyright = "Kaspersky Lab"
		date = "2015-04-07"
		description = "detection for Hellsing implants"
		id = "00aa5885-ae79-5d68-8587-13d3e8965630"

	strings:
		$a1 = {74 68 65 20 66 69 6c 65 20 75 70 6c 6f 61 64 65 64 20 66 61 69 6c 65 64 20 21}
		$a2 = {70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31}
		$b1 = {74 68 65 20 66 69 6c 65 20 64 6f 77 6e 6c 6f 61 64 65 64 20 66 61 69 6c 65 64 20 21}
		$b2 = {63 6f 6d 6d 6f 6e 2e 61 73 70}
		$c = {78 77 65 62 65 72 5f 73 65 72 76 65 72 2e 65 78 65}
		$d = {61 63 74 69 6f 6e 3d}
		$debugpath1 = {64 3a 5c 48 65 6c 6c 73 69 6e 67 5c 72 65 6c 65 61 73 65 5c 6d 73 67 65 72 5c}
		$debugpath2 = {64 3a 5c 68 65 6c 6c 73 69 6e 67 5c 73 79 73 5c 78 72 61 74 5c}
		$debugpath3 = {44 3a 5c 48 65 6c 6c 73 69 6e 67 5c 72 65 6c 65 61 73 65 5c 65 78 65 5c}
		$debugpath4 = {64 3a 5c 68 65 6c 6c 73 69 6e 67 5c 73 79 73 5c 78 6b 61 74 5c}
		$debugpath5 = {65 3a 5c 48 65 6c 6c 73 69 6e 67 5c 72 65 6c 65 61 73 65 5c 63 6c 61 72 65}
		$debugpath6 = {65 3a 5c 48 65 6c 6c 73 69 6e 67 5c 72 65 6c 65 61 73 65 5c 69 72 65 6e 65 5c}
		$debugpath7 = {64 3a 5c 68 65 6c 6c 73 69 6e 67 5c 73 79 73 5c 69 72 65 6e 65 5c}
		$e = {6d 73 67 65 72 5f 73 65 72 76 65 72 2e 64 6c 6c}
		$f = {53 65 72 76 69 63 65 4d 61 69 6e}

	condition:
		uint16( 0 ) == 0x5a4d and ( all of ( $a* ) ) or ( all of ( $b* ) ) or ( $c and $d ) or ( any of ( $debugpath* ) ) or ( $e and $f ) and filesize < 500000
}

rule apt_hellsing_installer : hardened
{
	meta:
		version = "1.0"
		filetype = "PE"
		author = "Costin Raiu, Kaspersky Lab"
		copyright = "Kaspersky Lab"
		date = "2015-04-07"
		description = "detection for Hellsing xweber/msger installers"
		id = "0aca838e-813a-59ee-8a04-7d2f4e854075"

	strings:
		$cmd = {63 6d 64 2e 65 78 65 20 2f 63 20 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 2d 6e 20 35 26 63 6d 64 2e 65 78 65 20 2f 63 20 64 65 6c 20 2f 61 20 2f 66 20 22 25 73 22}
		$a1 = {78 77 65 62 65 72 5f 69 6e 73 74 61 6c 6c 5f 75 61 63 2e 65 78 65}
		$a2 = {73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00}
		$a4 = {53 31 31 53 57 46 4f 72 56 77 52 39 55 6c 70 57 52 56 5a 5a 57 41 52 30 55 31 61 6f 42 48 46 54 55 6c 32 6f 55 31 59 3d}
		$a5 = {53 31 31 53 57 46 4f 72 56 77 52 39 64 6e 46 54 55 67 52 55 56 6c 4e 48 57 56 64 58 42 46 70 54 56 67 52 64 55 6c 70 57 52 56 5a 5a 57 41 52 64 55 71 68 5a 56 6c 70 46 52 31 6b 45 55 56 4e 53 58 61 68 54 56 67 52 61 55 31 59 45 55 56 4e 53 58 61 68 54 56 6c 31 53 57 77 52 5a 56 61 6c 64 56 46 46 5a 55 71 67 51 42 46 31 53 57 6c 5a 46 56 6c 6c 59 42 46 52 54 56 71 67 3d}
		$a6 = {37 64 71 6d 32 4f 44 66 35 4e 2f 59 32 4e 2f 6d 36 2b 62 72 33 64 6e 5a 70 75 6e 6c 34 34 67 3d}
		$a7 = {76 64 2f 6d 37 4f 58 64 32 61 69 2f 35 75 37 61 35 39 72 72 37 4b 69 34 35 64 72 63 71 4d 50 6c 35 74 2f 63 35 64 71 49 5a 77 3d 3d}
		$a8 = {76 64 2f 6d 37 4f 58 64 32 61 69 2f 75 73 50 6c 35 71 6a 59 32 75 58 70 36 39 6e 5a 71 4f 37 6c 32 71 6a 66 35 75 37 61 35 39 72 72 37 4b 6a 66 35 74 7a 72 32 75 37 6e 36 65 75 6f 34 2b 58 6d 33 39 7a 6c 32 71 6a 75 35 64 71 6f 34 2b 58 6d 33 39 7a 6c 32 74 2f 6d 37 61 6a 72 31 39 76 66 32 4f 50 72 33 39 72 6a 35 65 61 5a 6d 71 62 73 35 4f 53 49 4e 6a 6c 32 74 79 49}
		$a9 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 73 00 79 00 73 00 70 00 72 00 65 00 70 00 5c 00 73 00 79 00 73 00 70 00 72 00 65 00 70 00 2e 00 65 00 78 00 65 00}
		$a10 = {25 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 25 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00}
		$a11 = {6d 73 67 65 72 5f 69 6e 73 74 61 6c 6c 2e 64 6c 6c}
		$a12 = {00 65 78 2E 64 6C 6C 00}

	condition:
		uint16( 0 ) == 0x5a4d and ( $cmd and ( 2 of ( $a* ) ) ) and filesize < 500000
}

rule apt_hellsing_proxytool : hardened limited
{
	meta:
		version = "1.0"
		filetype = "PE"
		author = "Costin Raiu, Kaspersky Lab"
		copyright = "Kaspersky Lab"
		date = "2015-04-07"
		description = "detection for Hellsing proxy testing tool"
		id = "54454f07-11a9-5456-b489-9a9610e53123"

	strings:
		$a1 = {50 52 4f 58 59 5f 49 4e 46 4f 3a 20 61 75 74 6f 6d 61 74 69 63 20 70 72 6f 78 79 20 75 72 6c 20 3d 3e 20 25 73}
		$a2 = {50 52 4f 58 59 5f 49 4e 46 4f 3a 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 74 79 70 65 20 3d 3e 20 25 64}
		$a3 = {50 52 4f 58 59 5f 49 4e 46 4f 3a 20 70 72 6f 78 79 20 73 65 72 76 65 72 20 3d 3e 20 25 73}
		$a4 = {50 52 4f 58 59 5f 49 4e 46 4f 3a 20 62 79 70 61 73 73 20 6c 69 73 74 20 3d 3e 20 25 73}
		$a5 = {49 6e 74 65 72 6e 65 74 51 75 65 72 79 4f 70 74 69 6f 6e 20 66 61 69 6c 65 64 20 77 69 74 68 20 47 65 74 4c 61 73 74 45 72 72 6f 72 28 29 20 25 64}
		$a6 = {44 3a 5c 48 65 6c 6c 73 69 6e 67 5c 72 65 6c 65 61 73 65 5c 65 78 65 5c 65 78 65 5c}

	condition:
		uint16( 0 ) == 0x5a4d and ( 2 of ( $a* ) ) and filesize < 300000
}

rule apt_hellsing_xkat : hardened
{
	meta:
		version = "1.0"
		filetype = "PE"
		author = "Costin Raiu, Kaspersky Lab"
		copyright = "Kaspersky Lab"
		date = "2015-04-07"
		description = "detection for Hellsing xKat tool"
		id = "c831ce04-8fb2-5790-8aaf-c88b370835ac"

	strings:
		$a1 = {5c 44 62 67 76 2e 73 79 73}
		$a2 = {58 4b 41 54 5f 42 49 4e}
		$a3 = {72 65 6c 65 61 73 65 20 73 79 73 20 66 69 6c 65 20 65 72 72 6f 72 2e}
		$a4 = {64 72 69 76 65 72 5f 6c 6f 61 64 20 65 72 72 6f 72 2e 20}
		$a5 = {64 72 69 76 65 72 5f 63 72 65 61 74 65 20 65 72 72 6f 72 2e}
		$a6 = {64 65 6c 65 74 65 20 66 69 6c 65 3a 25 73 20 65 72 72 6f 72 2e}
		$a7 = {64 65 6c 65 74 65 20 66 69 6c 65 3a 25 73 20 6f 6b 2e}
		$a8 = {6b 69 6c 6c 20 70 69 64 3a 25 64 20 65 72 72 6f 72 2e}
		$a9 = {6b 69 6c 6c 20 70 69 64 3a 25 64 20 6f 6b 2e}
		$a10 = {2d 70 69 64 2d 64 65 6c 65 74 65}
		$a11 = {6b 69 6c 6c 20 61 6e 64 20 64 65 6c 65 74 65 20 70 69 64 3a 25 64 20 65 72 72 6f 72 2e}
		$a12 = {6b 69 6c 6c 20 61 6e 64 20 64 65 6c 65 74 65 20 70 69 64 3a 25 64 20 6f 6b 2e}

	condition:
		uint16( 0 ) == 0x5a4d and ( 6 of ( $a* ) ) and filesize < 300000
}

rule apt_hellsing_msgertype2 : hardened
{
	meta:
		version = "1.0"
		filetype = "PE"
		author = "Costin Raiu, Kaspersky Lab"
		copyright = "Kaspersky Lab"
		date = "2015-04-07"
		description = "detection for Hellsing msger type 2 implants"
		id = "98f151de-c1c2-56c1-8c64-5d1f437e0742"

	strings:
		$a1 = {25 73 5c 73 79 73 74 65 6d 5c 25 64 2e 74 78 74}
		$a2 = {5f 6d 73 67 65 72}
		$a3 = {68 74 74 70 3a 2f 2f 25 73 2f 6c 69 62 2f 63 6f 6d 6d 6f 6e 2e 61 73 70 3f 61 63 74 69 6f 6e 3d 75 73 65 72 5f 6c 6f 67 69 6e 26 75 69 64 3d 25 73 26 6c 61 6e 3d 25 73 26 68 6f 73 74 3d 25 73 26 6f 73 3d 25 73 26 70 72 6f 78 79 3d 25 73}
		$a4 = {68 74 74 70 3a 2f 2f 25 73 2f 64 61 74 61 2f 25 73 2e 31 30 30 30 30 30 31 30 30 30}
		$a5 = {2f 6c 69 62 2f 63 6f 6d 6d 6f 6e 2e 61 73 70 3f 61 63 74 69 6f 6e 3d 75 73 65 72 5f 75 70 6c 6f 61 64 26 66 69 6c 65 3d}
		$a6 = {25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58}

	condition:
		uint16( 0 ) == 0x5a4d and ( 4 of ( $a* ) ) and filesize < 500000
}

rule apt_hellsing_irene : hardened
{
	meta:
		version = "1.0"
		filetype = "PE"
		author = "Costin Raiu, Kaspersky Lab"
		copyright = "Kaspersky Lab"
		date = "2015-04-07"
		description = "detection for Hellsing msger irene installer"
		id = "b57d1a10-4e5c-511f-b98c-8ce7d766c227"

	strings:
		$a1 = {5c 00 44 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 75 00 73 00 62 00 6d 00 67 00 72 00 2e 00 74 00 6d 00 70 00}
		$a2 = {5c 00 44 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 75 00 73 00 62 00 6d 00 67 00 72 00 2e 00 73 00 79 00 73 00}
		$a3 = {63 6f 6d 6d 6f 6e 5f 6c 6f 61 64 44 72 69 76 65 72 20 43 72 65 61 74 65 46 69 6c 65 20 65 72 72 6f 72 21}
		$a4 = {63 6f 6d 6d 6f 6e 5f 6c 6f 61 64 44 72 69 76 65 72 20 53 74 61 72 74 53 65 72 76 69 63 65 20 65 72 72 6f 72 20 26 26 20 47 65 74 4c 61 73 74 45 72 72 6f 72 28 29 3a 25 64 21}
		$a5 = {69 00 72 00 65 00 6e 00 65 00}
		$a6 = {61 50 4c 69 62 20 76 30 2e 34 33 20 2d 20 74 68 65 20 73 6d 61 6c 6c 65 72 20 74 68 65 20 62 65 74 74 65 72}

	condition:
		uint16( 0 ) == 0x5a4d and ( 4 of ( $a* ) ) and filesize < 500000
}

