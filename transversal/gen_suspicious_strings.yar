rule Ping_Command_in_EXE : hardened
{
	meta:
		description = "Detects an suspicious ping command execution in an executable"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2016-11-03"
		score = 40
		id = "937ab622-fbcf-5a31-a3ff-af2584484140"

	strings:
		$x1 = {63 6d 64 20 2f 63 20 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 2d 6e 20}

	condition:
		uint16( 0 ) == 0x5a4d and all of them
}

rule GoogleBot_UserAgent : hardened limited
{
	meta:
		description = "Detects the GoogleBot UserAgent String in an Executable"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-01-27"
		score = 65
		id = "621532ac-fc0b-5118-84b0-eac110693320"

	strings:
		$x1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 47 6f 6f 67 6c 65 62 6f 74 2f 32 2e 31 3b 20 2b 68 74 74 70 3a 2f 2f 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 62 6f 74 2e 68 74 6d 6c 29 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$fp1 = {4d 00 63 00 41 00 66 00 65 00 65 00 2c 00 20 00 49 00 6e 00 63 00 2e 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 500KB and $x1 and not 1 of ( $fp* ) )
}

rule Gen_Net_LocalGroup_Administrators_Add_Command : hardened
{
	meta:
		description = "Detects an executable that contains a command to add a user account to the local administrators group"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-07-08"
		id = "9f6095fc-6d9f-5814-b407-f320191fd912"
		score = 70

	strings:
		$x1 = /net localgroup administrators [a-zA-Z0-9]{1,16} \/add/ nocase ascii

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 400KB and 1 of them )
}

rule Suspicious_Script_Running_from_HTTP : hardened limited
{
	meta:
		description = "Detects a suspicious "
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.hybrid-analysis.com/sample/a112274e109c5819d54aa8de89b0e707b243f4929a83e77439e3ff01ed218a35?environmentId=100"
		score = 50
		date = "2017-08-20"
		id = "9ba84e9c-a32b-5f66-8d50-75344599cafc"

	strings:
		$s1 = {63 6d 64 20 2f 43 20 73 63 72 69 70 74 3a 68 74 74 70 3a 2f 2f}
		$s2 = {63 6d 64 20 2f 43 20 73 63 72 69 70 74 3a 68 74 74 70 73 3a 2f 2f}
		$s3 = {63 6d 64 2e 65 78 65 20 2f 43 20 73 63 72 69 70 74 3a 68 74 74 70 3a 2f 2f}
		$s4 = {63 6d 64 2e 65 78 65 20 2f 43 20 73 63 72 69 70 74 3a 68 74 74 70 73 3a 2f 2f}

	condition:
		1 of them
}

rule ReconCommands_in_File : FILE hardened
{
	meta:
		description = "Detects various recon commands in a single file"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/haroonmeer/status/939099379834658817"
		date = "2017-12-11"
		score = 40
		id = "62d59913-5dbd-512c-98ea-044bbb9ac2da"

	strings:
		$ = {74 61 73 6b 6c 69 73 74}
		$ = {6e 65 74 20 74 69 6d 65}
		$ = {73 79 73 74 65 6d 69 6e 66 6f}
		$ = {77 68 6f 61 6d 69}
		$ = {6e 62 74 73 74 61 74}
		$ = {6e 65 74 20 73 74 61 72 74}
		$ = {71 70 72 6f 63 65 73 73}
		$ = {6e 73 6c 6f 6f 6b 75 70}

	condition:
		filesize < 5KB and 4 of them
}

rule VBS_dropper_script_Dec17_1 : hardened limited
{
	meta:
		description = "Detects a VBS script that drops an executable"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2018-01-01"
		score = 80
		id = "60f23d32-0737-501f-bf1c-1ca32af62efc"

	strings:
		$s1 = {54 56 70 54 41 51 45 41 41 41 41 45 41 41}
		$s2 = {54 56 6f 41 41 41 41 41 41 41 41 41 41 41}
		$s3 = {54 56 71 41 41 41 45 41 41 41 41 45 41 42}
		$s4 = {54 56 70 51 41 41 49 41 41 41 41 45 41 41}
		$s5 = {54 56 71 51 41 41 4d 41 41 41 41 45 41 41}
		$a1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 73 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		filesize < 600KB and $a1 and 1 of ( $s* )
}

rule SUSP_PDB_Strings_Keylogger_Backdoor : HIGHVOL hardened
{
	meta:
		description = "Detects PDB strings used in backdoors or keyloggers"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2018-03-23"
		score = 65
		id = "190daadb-0de6-5665-a241-95c374dbda47"

	strings:
		$ = {5c 52 65 6c 65 61 73 65 5c 50 72 69 76 69 6c 65 67 65 45 73 63 61 6c 61 74 69 6f 6e}
		$ = {5c 52 65 6c 65 61 73 65 5c 4b 65 79 4c 6f 67 67 65 72}
		$ = {5c 44 65 62 75 67 5c 50 72 69 76 69 6c 65 67 65 45 73 63 61 6c 61 74 69 6f 6e}
		$ = {5c 44 65 62 75 67 5c 4b 65 79 4c 6f 67 67 65 72}
		$ = {42 61 63 6b 64 6f 6f 72 5c 4b 65 79 4c 6f 67 67 65 72 5f}
		$ = {5c 53 68 65 6c 6c 43 6f 64 65 5c 44 65 62 75 67 5c}
		$ = {5c 53 68 65 6c 6c 43 6f 64 65 5c 52 65 6c 65 61 73 65 5c}
		$ = {5c 4e 65 77 20 42 61 63 6b 64 6f 6f 72}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1000KB and 1 of them
}

rule SUSP_Microsoft_Copyright_String_Anomaly_2 : hardened limited
{
	meta:
		description = "Detects Floxif Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2018-05-11"
		score = 60
		hash1 = "de055a89de246e629a8694bde18af2b1605e4b9b493c7e4aef669dd67acf5085"
		id = "3257aff0-b923-5e56-b67c-fa676341a102"

	strings:
		$s1 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 28 00 43 00 29 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 28 00 43 00 29 00 20 00 4f 00 70 00 65 00 72 00 61 00 74 00 69 00 6e 00 67 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 200KB and 1 of them
}

rule SUSP_LNK_File_AppData_Roaming : hardened limited
{
	meta:
		description = "Detects a suspicious link file that references to AppData Roaming"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2018/05/deep-dive-into-rig-exploit-kit-delivering-grobios-trojan.html"
		date = "2018-05-16"
		score = 50
		id = "d905e58f-ae2e-5dc2-b206-d0435b023df0"

	strings:
		$s2 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 41 00 70 00 70 00 44 00 61 00 74 00 61 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s3 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 52 00 6f 00 61 00 6d 00 69 00 6e 00 67 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s4 = { 00 2E 00 65 00 78 00 65 00 2E 00 43 00 3A 00 5C
              00 55 00 73 00 65 00 72 00 73 00 5C }

	condition:
		uint16( 0 ) == 0x004c and uint32( 4 ) == 0x00021401 and ( filesize < 1KB and all of them )
}

rule SUSP_LNK_File_PathTraversal : hardened
{
	meta:
		description = "Detects a suspicious link file that references a file multiple folders lower than the link itself"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2018/05/deep-dive-into-rig-exploit-kit-delivering-grobios-trojan.html"
		date = "2018-05-16"
		score = 40
		id = "f4f6709f-9c4d-5f0c-9826-97444d282adc"

	strings:
		$s1 = {2e 2e 5c 2e 2e 5c 2e 2e 5c 2e 2e 5c 2e 2e 5c}

	condition:
		uint16( 0 ) == 0x004c and uint32( 4 ) == 0x00021401 and ( filesize < 1KB and all of them )
}

rule SUSP_Script_Obfuscation_Char_Concat : hardened
{
	meta:
		description = "Detects strings found in sample from CN group repo leak in October 2018"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/JaromirHorejsi/status/1047084277920411648"
		date = "2018-10-04"
		hash1 = "b30cc10e915a23c7273f0838297e0d2c9f4fc0ac1f56100eef6479c9d036c12b"
		id = "6d3bfdfd-ef8f-5740-ac1f-5835c7ce0f43"

	strings:
		$s1 = {22 63 22 20 26 20 22 72 22 20 26 20 22 69 22 20 26 20 22 70 22 20 26 20 22 74 22}

	condition:
		1 of them
}

rule SUSP_Win32dll_String : hardened limited
{
	meta:
		description = "Detects suspicious string in executables"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://medium.com/@Sebdraven/apt-sidewinder-changes-theirs-ttps-to-install-their-backdoor-f92604a2739"
		date = "2018-10-24"
		hash1 = "7bd7cec82ee98feed5872325c2f8fd9f0ea3a2f6cd0cd32bcbe27dbbfd0d7da1"
		id = "b1c78386-c23d-5138-942a-3da90e5802cc"

	strings:
		$s1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 77 69 6e 33 32 64 6c 6c 2e 64 6c 6c (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		filesize < 60KB and all of them
}

rule SUSP_Modified_SystemExeFileName_in_File : hardened limited
{
	meta:
		description = "Detecst a variant of a system file name often used by attackers to cloak their activity"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.symantec.com/blogs/threat-intelligence/seedworm-espionage-group"
		date = "2018-12-11"
		score = 65
		hash1 = "5723f425e0c55c22c6b8bb74afb6b506943012c33b9ec1c928a71307a8c5889a"
		hash2 = "f1f11830b60e6530b680291509ddd9b5a1e5f425550444ec964a08f5f0c1a44e"
		id = "97d91e1b-49b8-504e-9e9c-6cfb7c2afe41"

	strings:
		$s1 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 73 00 2e 00 65 00 78 00 65 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 200KB and 1 of them
}

rule SUSP_JAVA_Class_with_VBS_Content : hardened limited
{
	meta:
		description = "Detects a JAVA class file with strings known from VBS files"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.menlosecurity.com/blog/a-jar-full-of-problems-for-financial-services-companies"
		date = "2019-01-03"
		score = 60
		hash1 = "e0112efb63f2b2ac3706109a233963c19750b4df0058cc5b9d3fa1f1280071eb"
		id = "5c1433e2-e2af-52aa-8a8c-691aaf15760d"

	strings:
		$a1 = {6a 61 76 61 2f 6c 61 6e 67 2f 53 74 72 69 6e 67}
		$s1 = {2e 76 62 73}
		$s2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 63 72 65 61 74 65 4e 65 77 46 69 6c 65 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 77 73 63 72 69 70 74 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		( uint16( 0 ) == 0xfeca or uint16( 0 ) == 0xfacf or uint32( 0 ) == 0xbebafeca ) and filesize < 100KB and $a1 and 3 of ( $s* )
}

rule SUSP_RAR_with_PDF_Script_Obfuscation : hardened
{
	meta:
		description = "Detects RAR file with suspicious .pdf extension prefix to trick users"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2019-04-06"
		hash1 = "b629b46b009a1c2306178e289ad0a3d9689d4b45c3d16804599f23c90c6bca5b"
		id = "a3d2f5e9-3052-551b-8b2c-abcdd1ac2e48"

	strings:
		$s1 = {2e 70 64 66 2e 76 62 65}
		$s2 = {2e 70 64 66 2e 76 62 73}
		$s3 = {2e 70 64 66 2e 70 73 31}
		$s4 = {2e 70 64 66 2e 62 61 74}
		$s5 = {2e 70 64 66 2e 65 78 65}

	condition:
		uint32( 0 ) == 0x21726152 and 1 of them
}

rule SUSP_Netsh_PortProxy_Command : hardened
{
	meta:
		description = "Detects a suspicious command line with netsh and the portproxy command"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://docs.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-interface-portproxy"
		date = "2019-04-20"
		score = 65
		hash1 = "9b33a03e336d0d02750a75efa1b9b6b2ab78b00174582a9b2cb09cd828baea09"
		id = "cbbd2042-572c-5283-bd45-e745b36733ad"

	strings:
		$x1 = {6e 65 74 73 68 20 69 6e 74 65 72 66 61 63 65 20 70 6f 72 74 70 72 6f 78 79 20 61 64 64 20 76 34 74 6f 76 34 20 6c 69 73 74 65 6e 70 6f 72 74 3d}

	condition:
		1 of them
}

rule SUSP_DropperBackdoor_Keywords : hardened loosened limited
{
	meta:
		description = "Detects suspicious keywords that indicate a backdoor"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blog.talosintelligence.com/2019/04/dnspionage-brings-out-karkoff.html"
		date = "2019-04-24"
		hash1 = "cd4b9d0f2d1c0468750855f0ed352c1ed6d4f512d66e0e44ce308688235295b5"
		id = "2942ba6d-a533-5954-bfcf-417262e2fac2"

	strings:
		$x4 = {((44 72 6f 70 70 65 72 42 61 63 6b 64 6f 6f 72) | (44 00 72 00 6f 00 70 00 70 00 65 00 72 00 42 00 61 00 63 00 6b 00 64 00 6f 00 6f 00 72 00))}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1000KB and 1 of them
}

rule SUSP_SFX_cmd : hardened
{
	meta:
		description = "Detects suspicious SFX as used by Gamaredon group"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2018-09-27"
		hash1 = "965129e5d0c439df97624347534bc24168935e7a71b9ff950c86faae3baec403"
		id = "87e75fe6-c2d7-5cb4-9432-7c37dbfe94b8"

	strings:
		$s1 = /RunProgram=\"hidcon:[a-zA-Z0-9]{1,16}.cmd/ fullword ascii

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 2000KB and 1 of them
}

rule SUSP_XMRIG_Reference : hardened
{
	meta:
		description = "Detects an executable with a suspicious XMRIG crypto miner reference"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/itaitevet/status/1141677424045953024"
		date = "2019-06-20"
		score = 70
		id = "0a7324ce-90dc-5e6a-b22a-c29eccf324e9"

	strings:
		$x1 = {5c 78 6d 72 69 67 5c}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 2000KB and 1 of them
}

rule SUSP_Just_EICAR : hardened limited
{
	meta:
		description = "Just an EICAR test file - this is boring but users asked for it"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://2016.eicar.org/85-0-Download.html"
		date = "2019-03-24"
		score = 40
		hash1 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
		id = "e5eedd77-36e2-56a0-be0c-2553043c225a"

	strings:
		$s1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 58 35 4f 21 50 25 40 41 50 5b 34 5c 50 5a 58 35 34 28 50 5e 29 37 43 43 29 37 7d 24 45 49 43 41 52 2d 53 54 41 4e 44 41 52 44 2d 41 4e 54 49 56 49 52 55 53 2d 54 45 53 54 2d 46 49 4c 45 21 24 48 2b 48 2a (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		uint16( 0 ) == 0x3558 and filesize < 70 and $s1 at 0
}

rule SUSP_PDB_Path_Keywords : hardened limited
{
	meta:
		description = "Detects suspicious PDB paths"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/stvemillertime/status/1179832666285326337?s=20"
		date = "2019-10-04"
		id = "cbd9b331-58bb-5b29-88a2-5c19f12893a9"

	strings:
		$ = {44 65 62 75 67 5c 53 68 65 6c 6c 63 6f 64 65}
		$ = {52 65 6c 65 61 73 65 5c 53 68 65 6c 6c 63 6f 64 65}
		$ = {44 65 62 75 67 5c 53 68 65 6c 6c 43 6f 64 65}
		$ = {52 65 6c 65 61 73 65 5c 53 68 65 6c 6c 43 6f 64 65}
		$ = {44 65 62 75 67 5c 73 68 65 6c 6c 63 6f 64 65}
		$ = {52 65 6c 65 61 73 65 5c 73 68 65 6c 6c 63 6f 64 65}
		$ = {73 68 65 6c 6c 63 6f 64 65 2e 70 64 62}
		$ = {5c 53 68 65 6c 6c 63 6f 64 65 4c 61 75 6e 63 68 65 72}
		$ = {5c 53 68 65 6c 6c 43 6f 64 65 4c 61 75 6e 63 68 65 72}
		$ = {46 75 63 6b 65 72 2e 70 64 62}
		$ = {5c 41 56 46 75 63 6b 65 72 5c}
		$ = {72 61 74 54 65 73 74 2e 70 64 62}
		$ = {44 65 62 75 67 5c 43 56 45 5f}
		$ = {52 65 6c 65 61 73 65 5c 43 56 45 5f}
		$ = {44 65 62 75 67 5c 63 76 65 5f}
		$ = {52 65 6c 65 61 73 65 5c 63 76 65 5f}

	condition:
		uint16( 0 ) == 0x5a4d and 1 of them
}

rule SUSP_Disable_ETW_Jun20_1 : hardened loosened limited
{
	meta:
		description = "Detects method to disable ETW in ENV vars before executing a program"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://gist.github.com/Cyb3rWard0g/a4a115fd3ab518a0e593525a379adee3"
		date = "2020-06-06"
		id = "ea5dee09-959e-5ef2-8f84-5497bdef0a05"

	strings:
		$x1 = {((73 65 74 20 43 4f 4d 50 6c 75 73 5f 45 54 57 45 6e 61 62 6c 65 64 3d 30) | (73 00 65 00 74 00 20 00 43 00 4f 00 4d 00 50 00 6c 00 75 00 73 00 5f 00 45 00 54 00 57 00 45 00 6e 00 61 00 62 00 6c 00 65 00 64 00 3d 00 30 00))}
		$x2 = {((24 65 6e 76 3a 43 4f 4d 50 6c 75 73 5f 45 54 57 45 6e 61 62 6c 65 64 3d 30) | (24 00 65 00 6e 00 76 00 3a 00 43 00 4f 00 4d 00 50 00 6c 00 75 00 73 00 5f 00 45 00 54 00 57 00 45 00 6e 00 61 00 62 00 6c 00 65 00 64 00 3d 00 30 00))}
		$s1 = {((53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 2e 4e 45 54 46 72 61 6d 65 77 6f 72 6b) | (53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00))}
		$sa1 = {((2f 76 20 45 54 57 45 6e 61 62 6c 65 64) | (2f 00 76 00 20 00 45 00 54 00 57 00 45 00 6e 00 61 00 62 00 6c 00 65 00 64 00))}
		$sa2 = {((20 2f 64 20 30) | (20 00 2f 00 64 00 20 00 30 00))}
		$sb4 = {2d 4e 61 6d 65 20 45 54 57 45 6e 61 62 6c 65 64}
		$sb5 = {20 2d 56 61 6c 75 65 20 30 20}

	condition:
		1 of ( $x* ) or 3 of them
}

rule SUSP_PE_Discord_Attachment_Oct21_1 : hardened
{
	meta:
		description = "Detects suspicious executable with reference to a Discord attachment (often used for malware hosting on a legitimate FQDN)"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2021-10-12"
		score = 70
		id = "7c217350-4a35-505d-950d-1bc989c14bc2"

	strings:
		$x1 = {((68 74 74 70 73 3a 2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f) | (68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 2f 00))}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 5000KB and 1 of them
}

rule SUSP_Encoded_Discord_Attachment_Oct21_1 : hardened
{
	meta:
		description = "Detects suspicious encoded URL to a Discord attachment (often used for malware hosting on a legitimate FQDN)"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2021-10-12"
		score = 70
		id = "06c086f4-8b79-5506-9e3f-b5d099106157"

	strings:
		$enc_b01 = {((59 32 52 75 4c 6d 52 70 63 32 4e 76 63 6d 52 68 63 48 41 75 59 32 39 74 4c 32 46 30 64 47 46 6a 61 47 31 6c 62 6e 52 7a) | (59 00 32 00 52 00 75 00 4c 00 6d 00 52 00 70 00 63 00 32 00 4e 00 76 00 63 00 6d 00 52 00 68 00 63 00 48 00 41 00 75 00 59 00 32 00 39 00 74 00 4c 00 32 00 46 00 30 00 64 00 47 00 46 00 6a 00 61 00 47 00 31 00 6c 00 62 00 6e 00 52 00 7a 00))}
		$enc_b02 = {((4e 6b 62 69 35 6b 61 58 4e 6a 62 33 4a 6b 59 58 42 77 4c 6d 4e 76 62 53 39 68 64 48 52 68 59 32 68 74 5a 57 35 30 63) | (4e 00 6b 00 62 00 69 00 35 00 6b 00 61 00 58 00 4e 00 6a 00 62 00 33 00 4a 00 6b 00 59 00 58 00 42 00 77 00 4c 00 6d 00 4e 00 76 00 62 00 53 00 39 00 68 00 64 00 48 00 52 00 68 00 59 00 32 00 68 00 74 00 5a 00 57 00 35 00 30 00 63 00))}
		$enc_b03 = {((6a 5a 47 34 75 5a 47 6c 7a 59 32 39 79 5a 47 46 77 63 43 35 6a 62 32 30 76 59 58 52 30 59 57 4e 6f 62 57 56 75 64 48) | (6a 00 5a 00 47 00 34 00 75 00 5a 00 47 00 6c 00 7a 00 59 00 32 00 39 00 79 00 5a 00 47 00 46 00 77 00 63 00 43 00 35 00 6a 00 62 00 32 00 30 00 76 00 59 00 58 00 52 00 30 00 59 00 57 00 4e 00 6f 00 62 00 57 00 56 00 75 00 64 00 48 00))}
		$enc_b04 = {((41 47 4d 41 5a 41 42 75 41 43 34 41 5a 41 42 70 41 48 4d 41 59 77 42 76 41 48 49 41 5a 41 42 68 41 48 41 41 63 41 41 75 41 47 4d 41 62 77 42 74 41 43 38 41 59 51 42 30 41 48 51 41 59 51 42 6a 41 47 67 41 62 51 42 6c 41 47 34 41 64 41 42 7a) | (41 00 47 00 4d 00 41 00 5a 00 41 00 42 00 75 00 41 00 43 00 34 00 41 00 5a 00 41 00 42 00 70 00 41 00 48 00 4d 00 41 00 59 00 77 00 42 00 76 00 41 00 48 00 49 00 41 00 5a 00 41 00 42 00 68 00 41 00 48 00 41 00 41 00 63 00 41 00 41 00 75 00 41 00 47 00 4d 00 41 00 62 00 77 00 42 00 74 00 41 00 43 00 38 00 41 00 59 00 51 00 42 00 30 00 41 00 48 00 51 00 41 00 59 00 51 00 42 00 6a 00 41 00 47 00 67 00 41 00 62 00 51 00 42 00 6c 00 41 00 47 00 34 00 41 00 64 00 41 00 42 00 7a 00))}
		$enc_b05 = {((42 6a 41 47 51 41 62 67 41 75 41 47 51 41 61 51 42 7a 41 47 4d 41 62 77 42 79 41 47 51 41 59 51 42 77 41 48 41 41 4c 67 42 6a 41 47 38 41 62 51 41 76 41 47 45 41 64 41 42 30 41 47 45 41 59 77 42 6f 41 47 30 41 5a 51 42 75 41 48 51 41 63) | (42 00 6a 00 41 00 47 00 51 00 41 00 62 00 67 00 41 00 75 00 41 00 47 00 51 00 41 00 61 00 51 00 42 00 7a 00 41 00 47 00 4d 00 41 00 62 00 77 00 42 00 79 00 41 00 47 00 51 00 41 00 59 00 51 00 42 00 77 00 41 00 48 00 41 00 41 00 4c 00 67 00 42 00 6a 00 41 00 47 00 38 00 41 00 62 00 51 00 41 00 76 00 41 00 47 00 45 00 41 00 64 00 41 00 42 00 30 00 41 00 47 00 45 00 41 00 59 00 77 00 42 00 6f 00 41 00 47 00 30 00 41 00 5a 00 51 00 42 00 75 00 41 00 48 00 51 00 41 00 63 00))}
		$enc_b06 = {((41 59 77 42 6b 41 47 34 41 4c 67 42 6b 41 47 6b 41 63 77 42 6a 41 47 38 41 63 67 42 6b 41 47 45 41 63 41 42 77 41 43 34 41 59 77 42 76 41 47 30 41 4c 77 42 68 41 48 51 41 64 41 42 68 41 47 4d 41 61 41 42 74 41 47 55 41 62 67 42 30 41 48) | (41 00 59 00 77 00 42 00 6b 00 41 00 47 00 34 00 41 00 4c 00 67 00 42 00 6b 00 41 00 47 00 6b 00 41 00 63 00 77 00 42 00 6a 00 41 00 47 00 38 00 41 00 63 00 67 00 42 00 6b 00 41 00 47 00 45 00 41 00 63 00 41 00 42 00 77 00 41 00 43 00 34 00 41 00 59 00 77 00 42 00 76 00 41 00 47 00 30 00 41 00 4c 00 77 00 42 00 68 00 41 00 48 00 51 00 41 00 64 00 41 00 42 00 68 00 41 00 47 00 4d 00 41 00 61 00 41 00 42 00 74 00 41 00 47 00 55 00 41 00 62 00 67 00 42 00 30 00 41 00 48 00))}
		$enc_h01 = {((36 33 36 34 36 45 32 45 36 34 36 39 37 33 36 33 36 46 37 32 36 34 36 31 37 30 37 30 32 45 36 33 36 46 36 44 32 46 36 31 37 34 37 34 36 31 36 33 36 38 36 44 36 35 36 45 37 34 37 33) | (36 00 33 00 36 00 34 00 36 00 45 00 32 00 45 00 36 00 34 00 36 00 39 00 37 00 33 00 36 00 33 00 36 00 46 00 37 00 32 00 36 00 34 00 36 00 31 00 37 00 30 00 37 00 30 00 32 00 45 00 36 00 33 00 36 00 46 00 36 00 44 00 32 00 46 00 36 00 31 00 37 00 34 00 37 00 34 00 36 00 31 00 36 00 33 00 36 00 38 00 36 00 44 00 36 00 35 00 36 00 45 00 37 00 34 00 37 00 33 00))}
		$enc_h02 = {((36 33 36 34 36 65 32 65 36 34 36 39 37 33 36 33 36 66 37 32 36 34 36 31 37 30 37 30 32 65 36 33 36 66 36 64 32 66 36 31 37 34 37 34 36 31 36 33 36 38 36 64 36 35 36 65 37 34 37 33) | (36 00 33 00 36 00 34 00 36 00 65 00 32 00 65 00 36 00 34 00 36 00 39 00 37 00 33 00 36 00 33 00 36 00 66 00 37 00 32 00 36 00 34 00 36 00 31 00 37 00 30 00 37 00 30 00 32 00 65 00 36 00 33 00 36 00 66 00 36 00 64 00 32 00 66 00 36 00 31 00 37 00 34 00 37 00 34 00 36 00 31 00 36 00 33 00 36 00 38 00 36 00 64 00 36 00 35 00 36 00 65 00 37 00 34 00 37 00 33 00))}
		$enc_r01 = {((73 74 6e 65 6d 68 63 61 74 74 61 2f 6d 6f 63 2e 70 70 61 64 72 6f 63 73 69 64 2e 6e 64 63) | (73 00 74 00 6e 00 65 00 6d 00 68 00 63 00 61 00 74 00 74 00 61 00 2f 00 6d 00 6f 00 63 00 2e 00 70 00 70 00 61 00 64 00 72 00 6f 00 63 00 73 00 69 00 64 00 2e 00 6e 00 64 00 63 00))}

	condition:
		filesize < 5000KB and 1 of them
}

