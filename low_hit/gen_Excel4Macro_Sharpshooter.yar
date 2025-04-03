rule MAL_Sharpshooter_Excel4 : hardened limited
{
	meta:
		description = "Detects Excel documents weaponized with Sharpshooter"
		author = "John Lambert, Florian Roth"
		reference = "https://github.com/mdsecactivebreach/SharpShooter"
		reference2 = "https://outflank.nl/blog/2018/10/06/old-school-evil-excel-4-0-macros-xlm/"
		reference3 = "https://gist.github.com/JohnLaTwC/efab89650d6fcbb37a4221e4c282614c"
		reference4 = "https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/00b5dd7d-51ca-4938-b7b7-483fe0e5933b"
		date = "2020-03-27"
		score = 70
		hash = "ccef64586d25ffcb2b28affc1f64319b936175c4911e7841a0e28ee6d6d4a02d"
		id = "a79e3afe-e8f9-5e56-a131-bb1b346df471"

	strings:
		$header_docf = { D0 CF 11 E0 }
		$s1 = {45 78 63 65 6c 20 34 2e 30 20 4d 61 63 72 6f 73}
		$f1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 43 72 65 61 74 65 54 68 72 65 61 64 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$f2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$f3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 4b 65 72 6e 65 6c 33 32 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$concat = { 00 41 6f 00 08 1e ?? 00 41 6f 00 08 1e ?? 00 41 6f 00 08}

	condition:
		filesize < 1000KB and $header_docf at 0 and #concat > 10 and $s1 and 2 of ( $f* )
}

rule SUSP_Excel4Macro_AutoOpen : hardened limited
{
	meta:
		description = "Detects Excel4 macro use with auto open / close"
		author = "John Lambert @JohnLaTwC"
		date = "2020-03-26"
		score = 50
		hash = "2fb198f6ad33d0f26fb94a1aa159fef7296e0421da68887b8f2548bbd227e58f"
		id = "cfed97fe-b330-5528-8402-08c6ba6af04a"

	strings:
		$header_docf = { D0 CF 11 E0 }
		$s1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 45 78 63 65 6c (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$Auto_Open = {18 00 17 00 20 00 00 01 07 00 00 00 00 00 00 00 00 00 00 01 3a }
		$Auto_Close = {18 00 17 00 20 00 00 01 07 00 00 00 00 00 00 00 00 00 00 02 3a }
		$Auto_Open1 = {18 00 17 00 aa 03 00 01 07 00 00 00 00 00 00 00 00 00 00 01 3a }
		$Auto_Close1 = {18 00 17 00 aa 03 00 01 07 00 00 00 00 00 00 00 00 00 00 02 3a }

	condition:
		filesize < 3000KB and $header_docf at 0 and $s1 and any of ( $Auto_* )
}

