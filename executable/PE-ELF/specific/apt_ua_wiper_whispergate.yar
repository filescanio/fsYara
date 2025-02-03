rule APT_HKTL_Wiper_WhisperGate_Jan22_1 : hardened
{
	meta:
		description = "Detects unknown wiper malware"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/"
		date = "2022-01-16"
		score = 85
		hash1 = "a196c6b8ffcb97ffb276d04f354696e2391311db3841ae16c8c9f56f36a38e92"
		id = "f04b619e-1df2-5c51-9cab-4a0fffd1c042"

	strings:
		$xc1 = { 41 41 41 41 41 00 59 6F 75 72 20 68 61 72 64 20
               64 72 69 76 65 20 68 61 73 20 62 65 65 6E 20 63
               6F 72 72 75 70 74 65 64 }
		$op1 = { 89 34 24 e8 3f ff ff ff 50 8d 65 f4 31 c0 59 5e 5f }
		$op2 = { 8d bd e8 df ff ff e8 04 de ff ff b9 00 08 00 00 f3 a5 c7 44 24 18 00 00 00 00 c7 44 24 14 00 00 00 00 c7 44 24 10 03 00 00 00 c7 44 24 0c 00 00 00 00 }
		$op3 = { c7 44 24 0c 00 00 00 00 c7 44 24 08 00 02 00 00 89 44 24 04 e8 aa fe ff ff 83 ec 14 89 34 24 e8 3f ff ff ff 50 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 100KB and ( 1 of ( $x* ) or 2 of them ) or all of them
}

rule APT_HKTL_Wiper_WhisperGate_Jan22_2 : hardened
{
	meta:
		description = "Detects unknown wiper malware"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/"
		date = "2022-01-16"
		score = 90
		hash1 = "dcbbae5a1c61dbbbb7dcd6dc5dd1eb1169f5329958d38b58c3fd9384081c9b78"
		id = "822e5af5-9c51-5be3-94f1-7e0a714743e6"

	strings:
		$sc1 = { 70 00 6F 00 77 00 65 00 72 00 73 00 68 00 65 00
               6C 00 6C 00 00 27 2D 00 65 00 6E 00 63 00 20 00
               55 00 77 00 42 00 30 00 41 00 47 00 45 00 41 00
               63 00 67 00 42 00 30 00 41 00 43 }
		$sc2 = { 59 00 6C 00 66 00 77 00 64 00 77 00 67 00 6D 00
               70 00 69 00 6C 00 7A 00 79 00 61 00 70 00 68 }
		$s1 = {78 00 6f 00 77 00 6e 00 78 00 6c 00 6f 00 78 00 61 00 64 00 44 00 78 00 61 00 74 00 78 00 78 00 61 00 78 00}
		$s2 = {30 00 41 00 55 00 77 00 42 00 73 00 41 00 47 00 55 00 41 00 5a 00 51 00 42 00 77 00 41 00 43 00 41 00 41 00 4c 00 51 00 42 00 7a 00 41 00 43 00 41 00 41 00 4d 00 51 00 41 00 77 00 41 00 41 00 3d 00 3d 00}
		$s3 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 2f 00}
		$s4 = {66 66 66 78 66 66 66 2e 66 66 66}
		$op1 = { 20 6b 85 b9 03 20 14 19 91 52 61 65 20 e1 ae f1 }
		$op2 = { aa ae 74 20 d9 7c 71 04 59 20 71 cc 13 91 61 20 97 3c 2a c0 }
		$op3 = { 38 9c f3 ff ff 20 f2 96 4d e9 20 5d ae d9 ce 58 20 4f 45 27 }
		$op4 = { d4 67 d4 61 80 1c 00 00 04 38 35 02 00 00 20 27 c0 db 56 65 20 3d eb 24 de 61 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1000KB and 5 of them or 7 of them
}

rule APT_HKTL_Wiper_WhisperGate_Stage3_Jan22 : hardened
{
	meta:
		description = "Detects reversed stage3 related to Ukrainian wiper malware"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/juanandres_gs/status/1482827018404257792"
		date = "2022-01-16"
		hash1 = "9ef7dbd3da51332a78eff19146d21c82957821e464e8133e9594a07d716d892d"
		id = "d5d562cd-03ef-5450-8044-3f538cea32d0"

	strings:
		$xc1 = { 65 31 63 70 00 31 79 72 61 72 62 69 4c 73 73 61 6c 43 00 6e 69 61 4d }
		$s1 = {6c 00 6c 00 64 00 2e 00}

	condition:
		uint16( filesize - 2 ) == 0x4d5a and filesize < 5000KB and all of them
}

rule MAL_OBFUSC_Unknown_Jan22_1 : hardened
{
	meta:
		description = "Detects samples similar to reversed stage3 found in Ukrainian wiper incident named WhisperGate"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/juanandres_gs/status/1482827018404257792"
		date = "2022-01-16"
		hash1 = "9ef7dbd3da51332a78eff19146d21c82957821e464e8133e9594a07d716d892d"
		id = "647c0092-b03d-5627-8568-ddaa982c73a1"

	strings:
		$xc1 = { 37 00 63 00 38 00 63 00 62 00 35 00 35 00 39 00
               38 00 65 00 37 00 32 00 34 00 64 00 33 00 34 00
               33 00 38 00 34 00 63 00 63 00 65 00 37 00 34 00
               30 00 32 00 62 00 31 00 31 00 66 00 30 00 65 }
		$xc2 = { 4D 61 69 6E 00 43 6C 61 73 73 4C 69 62 72 61 72
               79 31 00 70 63 31 65 }
		$s1 = {2e 00 64 00 6c 00 6c 00}
		$s2 = {25 26 25 2c 25 73 25}
		$op1 = { a2 87 fa b1 44 a5 f5 12 da a7 49 11 5c 8c 26 d4 75 }
		$op2 = { d7 af 52 38 c7 47 95 c8 0e 88 f3 d5 0b }
		$op3 = { 6c 05 df d6 b8 ac 11 f2 67 16 cb b7 34 4d b6 91 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1000KB and ( 1 of ( $x* ) or 3 of them )
}

rule MAL_Unknown_Discord_Characteristics_Jan22_1 : hardened
{
	meta:
		description = "Detects unknown malware with a few indicators also found in Wiper malware"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/"
		date = "2022-01-16"
		score = 75
		hash1 = "dcbbae5a1c61dbbbb7dcd6dc5dd1eb1169f5329958d38b58c3fd9384081c9b78"
		id = "23ee5319-6a72-517b-8ea0-55063b6b862c"

	strings:
		$x1 = {78 00 6f 00 77 00 6e 00 78 00 6c 00 6f 00 78 00 61 00 64 00 44 00 78 00 61 00 74 00 78 00 78 00 61 00 78 00}
		$s2 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 2f 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1000KB and all of them
}

