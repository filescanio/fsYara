rule Bytes_used_in_AES_key_generation : hardened
{
	meta:
		author = "NCSC"
		description = "Detects Backdoor.goodor"
		reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
		date = "2018/04/06"
		hash = "b5278301da06450fe4442a25dda2d83d21485be63598642573f59c59e980ad46"
		id = "26a549dd-cbd2-5abc-8d9d-5ea354d0ece8"

	strings:
		$a1 = {35 34 36 35 4B 4A 55 54 5E 49 55 5F 29 7B 68 36 35 67 34 36 64 66 35 68}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 5000KB and all of ( $a* )
}

rule Partial_Implant_ID : hardened
{
	meta:
		author = "NCSC"
		description = "Detects implant from NCSC report"
		reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
		date = "2018/04/06"
		hash = "b5278301da06450fe4442a25dda2d83d21485be63598642573f59c59e980ad46"
		id = "15144f4a-2c96-57f0-b7e9-adbac477c38a"

	strings:
		$a1 = {38 38 31 34 35 36 46 43}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1000KB and all of ( $a* )
}

rule Sleep_Timer_Choice : hardened
{
	meta:
		author = "NCSC"
		description = "Detects malware from NCSC report"
		reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
		date = "2018/04/06"
		hash = "b5278301da06450fe4442a25dda2d83d21485be63598642573f59c59e980ad46"
		id = "c64db0dd-2858-5508-ac51-d3318113a060"

	strings:
		$a1 = {8b0424b90f00000083f9ff743499f7f98d420f}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1000KB and all of ( $a* )
}

rule User_Function_String : hardened
{
	meta:
		author = "NCSC"
		description = "Detects user function string from NCSC report"
		reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
		date = "2018/04/06"
		hash = "b5278301da06450fe4442a25dda2d83d21485be63598642573f59c59e980ad46"
		id = "563ac6af-6b37-53c6-ae13-d97e31edb088"

	strings:
		$a2 = {65 2e 52 61 6e 64 6f 6d 48 61 73 68 53 74 72 69 6e 67}
		$a3 = {65 2e 44 65 63 6f 64 65}
		$a4 = {65 2e 44 65 63 72 79 70 74}
		$a5 = {65 2e 48 61 73 68 53 74 72}
		$a6 = {65 2e 46 72 6f 6d 42 36 34}

	condition:
		4 of ( $a* )
}

rule generic_shellcode_downloader_specific : hardened
{
	meta:
		author = "NCSC"
		description = "Detects Doorshell from NCSC report"
		reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
		date = "2018/04/06"
		hash = "b8bc0611a7fd321d2483a0a9a505251e15c22402e0cfdc62c0258af53ed3658a"
		id = "ddd25add-ff84-5106-ac3c-5d5b4c1ef2a9"

	strings:
		$push1 = {68 6C 6C 6F 63}
		$push2 = {68 75 61 6C 41}
		$push3 = {68 56 69 72 74}
		$a = {BA 90 02 00 00 46 C1 C6 19 03 DD 2B F4 33 DE}
		$b = {87 C0 81 F2 D1 19 89 14 C1 C8 1F FF E0}

	condition:
		( uint16( 0 ) == 0x5A4D and uint16( uint32( 0x3C ) ) == 0x4550 ) and ( $a or $b ) and @push1 < @push2 and @push2 < @push3
}

rule Batch_Script_To_Run_PsExec : hardened
{
	meta:
		author = "NCSC"
		description = "Detects malicious batch file from NCSC report"
		reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
		date = "2018/04/06"
		hash = "b7d7c4bc8f9fd0e461425747122a431f93062358ed36ce281147998575ee1a18"
		id = "1fbeeec8-a5bd-569e-b435-c7d82d32e47b"

	strings:
		$ = {54 6f 6b 65 6e 73 3d 31 20 64 65 6c 69 6d 73 3d}
		$ = {53 45 54 20 77 73 3d 25 31}
		$ = {43 68 65 63 6b 69 6e 67 20 25 77 73 25}
		$ = {25 54 45 4d 50 25 5c 25 77 73 25 6e 73 2e 74 78 74}
		$ = {70 73 2e 65 78 65 20 2d 61 63 63 65 70 74 65 75 6c 61}

	condition:
		3 of them
}

rule Batch_Powershell_Invoke_Inveigh : hardened
{
	meta:
		author = "NCSC"
		description = "Detects malicious batch file from NCSC report"
		reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
		date = "2018/04/06"
		hash = "0a6b1b29496d4514f6485e78680ec4cd0296ef4d21862d8bf363900a4f8e3fd2"
		id = "c5dab029-6515-5d58-9ccd-bf438ba692d5"

	strings:
		$ = {49 6e 76 65 69 67 68 2e 70 73 31}
		$ = {49 6e 76 6f 6b 65 2d 49 6e 76 65 69 67 68}
		$ = {2d 4c 4c 4d 4e 52 20 4e 20 2d 48 54 54 50 20 4e 20 2d 46 69 6c 65 4f 75 74 70 75 74 20 59}
		$ = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65}

	condition:
		all of them
}

rule lnk_detect : hardened
{
	meta:
		author = "NCSC"
		description = "Detects malicious LNK file from NCSC report"
		reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
		date = "2018/04/06"
		id = "76d382f3-b2f2-5ede-94b2-5ae8b766c194"

	strings:
		$lnk_magic = {4C 00 00 00 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46}
		$lnk_target = {41 00 55 00 54 00 4F 00 45 00 58 00 45 00 43 00 2E 00 42 00 41 00 54}
		$s1 = {5C 00 5C 00 31 00}
		$s2 = {5C 00 5C 00 32 00}
		$s3 = {5C 00 5C 00 33 00}
		$s4 = {5C 00 5C 00 34 00}
		$s5 = {5C 00 5C 00 35 00}
		$s6 = {5C 00 5C 00 36 00}
		$s7 = {5C 00 5C 00 37 00}
		$s8 = {5C 00 5C 00 38 00}
		$s9 = {5C 00 5C 00 39 00}

	condition:
		uint32be( 0 ) == 0x4c000000 and uint32be( 4 ) == 0x01140200 and ( ( $lnk_magic at 0 ) and $lnk_target ) and 1 of ( $s* )
}

rule RDP_Brute_Strings : hardened
{
	meta:
		author = "NCSC"
		description = "Detects RDP brute forcer from NCSC report"
		reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
		date = "2018/04/06"
		hash = "8234bf8a1b53efd2a452780a69666d1aedcec9eb1bb714769283ccc2c2bdcc65"
		id = "d6f0cdbc-a910-5826-b25a-61c2924f8e2a"

	strings:
		$ = {((52 44 50 20 42 72 75 74 65) | (52 00 44 00 50 00 20 00 42 00 72 00 75 00 74 00 65 00))}
		$ = {52 64 70 43 68 65 63 6b 65 72}
		$ = {52 64 70 42 72 75 74 65}
		$ = {42 72 75 74 65 5f 43 6f 75 6e 74 5f 50 61 73 73 77 6f 72 64}
		$ = {42 72 75 74 65 49 50 4c 69 73 74}
		$ = {43 68 69 6c 6b 61 74 5f 53 6f 63 6b 65 74 5f 4b 65 79}
		$ = {42 72 75 74 65 5f 53 79 6e 63 5f 53 74 61 74}
		$ = {28 00 45 00 72 00 72 00 6f 00 72 00 21 00 20 00 48 00 79 00 70 00 65 00 72 00 6c 00 69 00 6e 00 6b 00 20 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 20 00 6e 00 6f 00 74 00 20 00 76 00 61 00 6c 00 69 00 64 00 2e 00 29 00}
		$ = {42 00 61 00 64 00 52 00 44 00 50 00}
		$ = {47 00 6f 00 6f 00 64 00 52 00 44 00 50 00}
		$ = {40 00 65 00 63 00 68 00 6f 00 20 00 6f 00 66 00 66 00 7b 00 30 00 7d 00 3a 00 6c 00 6f 00 6f 00 70 00 7b 00 30 00 7d 00 64 00 65 00 6c 00 20 00 7b 00 31 00 7d 00 7b 00 30 00 7d 00 69 00 66 00 20 00 65 00 78 00 69 00 73 00 74 00 20 00 7b 00 31 00 7d 00 20 00 67 00 6f 00 74 00 6f 00 20 00 6c 00 6f 00 6f 00 70 00 7b 00 30 00 7d 00 64 00 65 00 6c 00 20 00 7b 00 32 00 7d 00 7b 00 30 00 7d 00 64 00 65 00 6c 00 20 00 22 00 7b 00 32 00 7d 00 22 00}
		$ = {43 00 6f 00 64 00 65 00 64 00 20 00 62 00 79 00 20 00 7a 00 36 00 36 00 38 00}

	condition:
		4 of them
}

