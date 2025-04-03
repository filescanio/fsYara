rule apt_sofacy_xtunnel : hardened
{
	meta:
		author = "Claudio Guarnieri"
		description = "Sofacy Malware - German Bundestag"
		score = 75
		id = "aef091b5-cedf-5443-ab61-8b2dbc7e77fd"

	strings:
		$xaps = {3a 5c 50 52 4f 4a 45 43 54 5c 58 41 50 53 5f}
		$variant11 = {58 41 50 53 5f 4f 42 4a 45 43 54 49 56 45 2e 64 6c 6c}
		$variant12 = {73 74 61 72 74}
		$variant21 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 6f 77 73 20 4e 54 20 36 2e 33 3b 20 57 4f 57 36 34 3b 20 72 76 3a 32 38 2e 30 29 20 47 65 63 6b 6f 2f 32 30 31 30 30 31 30 31 20 46 69 72 65 66 6f 78 2f 32 38 2e 30}
		$variant22 = {69 73 20 79 6f 75 20 6c 69 76 65 3f}
		$mix1 = {31 37 36 2e 33 31 2e 31 31 32 2e 31 30}
		$mix2 = {65 72 72 6f 72 20 69 6e 20 73 65 6c 65 63 74 2c 20 65 72 72 6e 6f 20 25 64}
		$mix3 = {6e 6f 20 6d 73 67}
		$mix4 = {69 73 20 79 6f 75 20 6c 69 76 65 3f}
		$mix5 = {31 32 37 2e 30 2e 30 2e 31}
		$mix6 = {65 72 72 20 25 64}
		$mix7 = {69 60 6d 20 77 61 69 74}
		$mix8 = {68 65 6c 6c 6f}
		$mix9 = {4f 70 65 6e 53 53 4c 20 31 2e 30 2e 31 65 20 31 31 20 46 65 62 20 32 30 31 33}
		$mix10 = {58 74 75 6e 6e 65 6c 2e 65 78 65}

	condition:
		(( uint16( 0 ) == 0x5A4D ) or ( uint16( 0 ) == 0xCFD0 ) ) and ( ( $xaps ) or ( all of ( $variant1* ) ) or ( all of ( $variant2* ) ) or ( 6 of ( $mix* ) ) )
}

import "pe"

rule Winexe_RemoteExec : hardened limited
{
	meta:
		description = "Winexe tool for remote execution (also used by Sofacy group)"
		author = "Florian Roth (Nextron Systems), Robert Simmons"
		reference = "http://dokumente.linksfraktion.de/inhalt/report-orig.pdf"
		date = "2015-06-19"
		modified = "2021-02-11"
		hash1 = "5130f600cd9a9cdc82d4bad938b20cbd2f699aadb76e7f3f1a93602330d9997d"
		hash2 = "d19dfdbe747e090c5aa2a70cc10d081ac1aa88f360c3f378288a3651632c4429"
		score = 70
		id = "5079557a-0461-5b04-b0f2-4265bf7ec041"

	strings:
		$s1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 65 72 72 6f 72 20 43 61 6e 6e 6f 74 20 4c 6f 67 6f 6e 55 73 65 72 28 25 73 2c 25 73 2c 25 73 29 20 25 64 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 65 72 72 6f 72 20 43 61 6e 6e 6f 74 20 49 6d 70 65 72 73 6f 6e 61 74 65 4e 61 6d 65 64 50 69 70 65 43 6c 69 65 6e 74 20 25 64 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 5c 5c 2e 5c 70 69 70 65 5c 61 68 65 78 65 63 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s4 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 5c 5c 2e 5c 70 69 70 65 5c 77 6d 63 65 78 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s5 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 69 6d 70 6c 65 76 65 6c (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 115KB and ( 3 of them or pe.imphash ( ) == "2f8a475933ac82b8e09eaf26b396b54d" )
}

rule Sofacy_Mal2 : hardened limited
{
	meta:
		description = "Sofacy Group Malware Sample 2"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://dokumente.linksfraktion.de/inhalt/report-orig.pdf"
		date = "2015-06-19"
		hash = "566ab945f61be016bfd9e83cc1b64f783b9b8deb891e6d504d3442bc8281b092"
		score = 70
		id = "1547cc67-7d7c-5ec9-816c-15b7d523376a"

	strings:
		$x1 = {50 52 4f 4a 45 43 54 5c 58 41 50 53 5f 4f 42 4a 45 43 54 49 56 45 5f 44 4c 4c 5c}
		$x2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 58 41 50 53 5f 4f 42 4a 45 43 54 49 56 45 2e 64 6c 6c (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 69 60 6d 20 77 61 69 74 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		uint16( 0 ) == 0x5a4d and ( 1 of ( $x* ) ) and $s1
}

rule Sofacy_Mal3 : hardened limited
{
	meta:
		description = "Sofacy Group Malware Sample 3"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://dokumente.linksfraktion.de/inhalt/report-orig.pdf"
		date = "2015-06-19"
		modified = "2023-01-06"
		hash = "5f6b2a0d1d966fc4f1ed292b46240767f4acb06c13512b0061b434ae2a692fa1"
		score = 70
		id = "67d002ef-4ed9-54ce-a6ef-49b7f3b951e2"

	strings:
		$s1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 3d 22 53 79 73 74 65 6d 20 56 6f 6c 75 6d 65 20 49 6e 66 6f 72 6d 61 74 69 6f 6e 5c 55 53 42 47 75 61 72 64 2e 65 78 65 22 20 69 6e 73 74 61 6c 6c (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 2e 3f 41 56 41 67 65 6e 74 4d 6f 64 75 6c 65 52 65 6d 6f 74 65 4b 65 79 4c 6f 67 67 65 72 40 40 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 3c 66 6f 6e 74 20 73 69 7a 65 3d 34 20 63 6f 6c 6f 72 3d 72 65 64 3e 70 72 6f 63 65 73 73 20 69 73 6e 27 74 20 65 78 69 73 74 3c 2f 66 6f 6e 74 3e (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s4 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 3c 66 6f 6e 74 20 73 69 7a 65 3d 34 20 63 6f 6c 6f 72 3d 72 65 64 3e 70 72 6f 63 65 73 73 20 69 73 20 65 78 69 73 74 3c 2f 66 6f 6e 74 3e (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s5 = {2e 77 69 6e 6e 74 2e 63 68 65 63 6b 2d 66 69 78 2e 63 6f 6d}
		$s6 = {2e 75 70 64 61 74 65 2e 61 64 6f 62 65 69 6e 63 6f 72 70 2e 63 6f 6d}
		$s7 = {2e 6d 69 63 72 6f 73 6f 66 74 2e 63 68 65 63 6b 77 69 6e 66 72 61 6d 65 2e 63 6f 6d}
		$s8 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 61 00 64 00 6f 00 62 00 65 00 69 00 6e 00 63 00 6f 00 72 00 70 00 2e 00 63 00 6f 00 6d 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s9 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 23 20 45 58 43 3a 20 48 74 74 70 53 65 6e 64 65 72 20 2d 20 43 61 6e 6e 6f 74 20 63 72 65 61 74 65 20 47 65 74 20 43 68 61 6e 6e 65 6c 21 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$x1 = {55 00 73 00 65 00 72 00 2d 00 41 00 67 00 65 00 6e 00 74 00 3a 00 20 00 4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 2f 00 35 00 2e 00 30 00 20 00 28 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 20 00 36 00 2e 00 32 00 3b 00 20 00 57 00 4f 00 57 00 36 00 34 00 3b 00 20 00 72 00 76 00 3a 00 32 00 30 00 2e 00 30 00 29 00 20 00 47 00 65 00 63 00 6b 00 6f 00 2f 00 32 00 30 00 31 00 30 00 30 00 31 00 30 00 31 00 20 00 46 00 69 00 72 00 65 00 66 00 6f 00 78 00 2f 00}
		$x2 = {55 00 73 00 65 00 72 00 2d 00 41 00 67 00 65 00 6e 00 74 00 3a 00 20 00 4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 2f 00 35 00 2e 00 30 00 20 00 28 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 20 00 36 00 2e 00 3b 00 20 00 57 00 4f 00 57 00 36 00 34 00 3b 00 20 00 72 00 76 00 3a 00 32 00 30 00 2e 00 30 00 29 00 20 00 47 00 65 00 63 00 6b 00 6f 00 2f 00 32 00 30 00 31 00 30 00 30 00 31 00 30 00 31 00 20 00 46 00 69 00 72 00 65 00 66 00 6f 00 78 00 2f 00 32 00}
		$x3 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 300KB and ( 2 of ( $s* ) or ( 1 of ( $s* ) and all of ( $x* ) ) )
}

rule Sofacy_Bundestag_Batch : hardened
{
	meta:
		description = "Sofacy Bundestags APT Batch Script"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://dokumente.linksfraktion.de/inhalt/report-orig.pdf"
		date = "2015-06-19"
		score = 70
		id = "869dafec-1387-5640-b608-b84cf0d43342"

	strings:
		$s1 = {66 6f 72 20 25 25 47 20 69 6e 20 28 2e 70 64 66 2c 20 2e 78 6c 73 2c 20 2e 78 6c 73 78 2c 20 2e 64 6f 63 2c 20 2e 64 6f 63 78 29}
		$s2 = {63 6d 64 20 2f 63 20 63 6f 70 79}
		$s3 = {66 6f 72 66 69 6c 65 73}

	condition:
		filesize < 10KB and 2 of them
}

