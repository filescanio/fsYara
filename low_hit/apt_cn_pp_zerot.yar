rule PP_CN_APT_ZeroT_1 : hardened
{
	meta:
		description = "Detects malware from the Proofpoint CN APT ZeroT incident"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
		date = "2017-02-03"
		hash1 = "09061c603a32ac99b664f7434febfc8c1f9fd7b6469be289bb130a635a6c47c0"
		id = "c16f3abb-ac7e-5d5f-b8d7-b105cff3886e"

	strings:
		$s1 = {73 75 70 72 69 73 65 2e 65 78 65}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 2000KB and all of them )
}

rule PP_CN_APT_ZeroT_2 : hardened
{
	meta:
		description = "Detects malware from the Proofpoint CN APT ZeroT incident"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
		date = "2017-02-03"
		hash1 = "74eb592ef7f5967b14794acdc916686e061a43169f06e5be4dca70811b9815df"
		id = "8433216e-1189-568c-bd18-051fb1fec215"

	strings:
		$s1 = {4e 4f 32 2d 32 30 31 36 31 30 31 39 30 32 2e 65 78 65}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 2000KB and all of them )
}

rule PP_CN_APT_ZeroT_3 : hardened
{
	meta:
		description = "Detects malware from the Proofpoint CN APT ZeroT incident"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
		date = "2017-02-03"
		hash1 = "ee2e2937128dac91a11e9bf55babc1a8387eb16cebe676142c885b2fc18669b2"
		id = "99aa29cf-d962-5a3d-bd28-6486c40822bb"

	strings:
		$s1 = {2f 73 76 63 68 6f 73 74 2e 65 78 65}
		$s2 = {52 61 73 54 6c 73 2e 64 6c 6c}
		$s3 = {32 30 31 36 30 36 32 30 2e 68 74 6d}
		$s4 = {2a 20 24 6c 26 24}
		$s5 = {64 66 6a 68 6d 68}
		$s6 = {2f 32 30 31 36 30 36 32 30 2e 68 74 6d}

	condition:
		( uint16( 0 ) == 0x5449 and filesize < 1000KB and 3 of them ) or ( all of them )
}

rule PP_CN_APT_ZeroT_4 : hardened
{
	meta:
		description = "Detects malware from the Proofpoint CN APT ZeroT incident"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
		date = "2017-02-03"
		hash1 = "a9519d2624a842d2c9060b64bb78ee1c400fea9e43d4436371a67cbf90e611b8"
		id = "b21961ee-d346-51d3-bacd-02554240162d"

	strings:
		$s1 = {4d 63 75 74 69 6c 2e 64 6c 6c}
		$s2 = {6d 63 75 74 2e 65 78 65}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 1000KB and all of them )
}

rule PP_CN_APT_ZeroT_5 : hardened
{
	meta:
		description = "Detects malware from the Proofpoint CN APT ZeroT incident"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
		date = "2017-02-03"
		hash1 = "74dd52aeac83cc01c348528a9bcb20bbc34622b156f40654153e41817083ba1d"
		id = "2a7c6a36-aace-562e-bbc4-425c1d93fab1"

	strings:
		$x1 = {64 62 6f 7a 63 62}
		$s1 = {6e 66 6c 6f 67 67 65 72 2e 64 6c 6c}
		$s2 = {2f 73 76 63 68 6f 73 74 2e 65 78 65}
		$s3 = {31 32 30 37 2e 68 74 6d}
		$s4 = {2f 31 32 30 37 2e 68 74 6d}

	condition:
		( uint16( 0 ) == 0x5449 and filesize < 1000KB and 1 of ( $x* ) and 1 of ( $s* ) ) or ( all of them )
}

rule PP_CN_APT_ZeroT_6 : hardened
{
	meta:
		description = "Detects malware from the Proofpoint CN APT ZeroT incident"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
		date = "2017-02-03"
		hash1 = "a16078c6d09fcfc9d6ff7a91e39e6d72e2d6d6ab6080930e1e2169ec002b37d3"
		id = "2e3bb4bd-5e20-56e7-a82b-d717d83eaeeb"

	strings:
		$s1 = {6a 47 65 74 67 51 7c 30 68 39 3d}
		$s2 = {5c 73 66 78 72 61 72 33 32 5c 52 65 6c 65 61 73 65 5c 73 66 78 72 61 72 2e 70 64 62}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1000KB and all of them
}

rule PP_CN_APT_ZeroT_7 : hardened
{
	meta:
		description = "Detects malware from the Proofpoint CN APT ZeroT incident"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
		date = "2017-02-03"
		hash1 = "fc2d47d91ad8517a4a974c4570b346b41646fac333d219d2f1282c96b4571478"
		id = "e9cdca86-84a8-5673-935c-c319b523674b"

	strings:
		$s1 = {52 61 73 54 6c 73 2e 64 6c 6c}
		$s2 = {52 61 73 54 6c 73 2e 65 78 65}
		$s4 = {4c 4f 41 44 45 52 20 45 52 52 4f 52}
		$s5 = {54 68 65 20 70 72 6f 63 65 64 75 72 65 20 65 6e 74 72 79 20 70 6f 69 6e 74 20 25 73 20 63 6f 75 6c 64 20 6e 6f 74 20 62 65 20 6c 6f 63 61 74 65 64 20 69 6e 20 74 68 65 20 64 79 6e 61 6d 69 63 20 6c 69 6e 6b 20 6c 69 62 72 61 72 79 20 25 73}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 1000KB and all of them )
}

rule PP_CN_APT_ZeroT_8 : hardened
{
	meta:
		description = "Detects malware from the Proofpoint CN APT ZeroT incident"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
		date = "2017-02-03"
		hash1 = "4ef91c17b1415609a2394d2c6c353318a2503900e400aab25ab96c9fe7dc92ff"
		id = "f9a4f092-c699-5e91-9667-64ffe1b02bc1"

	strings:
		$s1 = {2f 73 76 63 68 6f 73 74 2e 65 78 65}
		$s2 = {52 61 73 54 6c 73 2e 64 6c 6c}
		$s3 = {32 30 31 36 30 36 32 30 2e 68 74 6d}
		$s4 = {2f 32 30 31 36 30 36 32 30 2e 68 74 6d}

	condition:
		( uint16( 0 ) == 0x5449 and filesize < 1000KB and 3 of them )
}

rule PP_CN_APT_ZeroT_9 : hardened
{
	meta:
		description = "Detects malware from the Proofpoint CN APT ZeroT incident"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
		date = "2017-02-03"
		hash1 = "a685cf4dca6a58213e67d041bba637dca9cb3ea6bb9ad3eae3ba85229118bce0"
		id = "e1c32993-409c-5a62-8239-cff99fb83a7f"

	strings:
		$x1 = {6e 66 6c 6f 67 67 65 72 2e 64 6c 6c}
		$s7 = {5a 6c 68 2e 65 78 65}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 1000KB and all of them )
}

rule CN_APT_ZeroT_nflogger : hardened
{
	meta:
		description = "Chinese APT by Proofpoint ZeroT RAT  - file nflogger.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
		date = "2017-02-04"
		hash1 = "946adbeb017616d56193a6d43fe9c583be6ad1c7f6a22bab7df9db42e6e8ab10"
		id = "0d23f312-e3b6-5c23-855b-25ae54265512"

	strings:
		$x1 = {5c 4c 6f 61 64 65 72 44 6c 6c 2e 56 53 32 30 31 30 5c 52 65 6c 65 61 73 65 5c}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 200KB and all of them )
}

rule CN_APT_ZeroT_extracted_Go : hardened
{
	meta:
		description = "Chinese APT by Proofpoint ZeroT RAT  - file Go.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
		date = "2017-02-04"
		modified = "2023-01-06"
		hash1 = "83ddc69fe0d3f3d2f46df7e72995d59511c1bfcca1a4e14c330cb71860b4806b"
		id = "ba929e6d-4162-58e7-b8a8-bcb066b64522"

	strings:
		$x1 = {25 73 5c 63 6d 64 2e 65 78 65 20 2f 63 20 25 73 5c 5a 6c 68 2e 65 78 65}
		$x2 = {5c 42 79 70 61 73 73 55 41 43 2e 56 53 32 30 31 30 5c 52 65 6c 65 61 73 65 5c}
		$s1 = {5a 6a 64 73 66 2e 65 78 65}
		$s2 = {53 53 33 32 70 72 65 70 2e 65 78 65}
		$s3 = {77 69 6e 64 6f 77 73 67 72 65 70 2e 65 78 65}
		$s4 = {53 79 73 64 75 67 2e 65 78 65}
		$s5 = {50 72 6f 65 73 73 7a 2e 65 78 65}
		$s6 = {25 73 5c 5a 6c 68 2e 65 78 65}
		$s7 = {2f 43 20 25 73 5c 25 73}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 100KB and ( 1 of ( $x* ) or 3 of ( $s* ) ) ) or ( 7 of them )
}

rule CN_APT_ZeroT_extracted_Mcutil : hardened
{
	meta:
		description = "Chinese APT by Proofpoint ZeroT RAT  - file Mcutil.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
		date = "2017-02-04"
		hash1 = "266c06b06abbed846ebabfc0e683f5d20dadab52241bc166b9d60e9b8493b500"
		id = "c887d36b-8aeb-54f1-a683-727561723238"

	strings:
		$s1 = {4c 6f 61 64 65 72 44 6c 6c 2e 64 6c 6c}
		$s2 = {51 61 67 65 42 6f 78 31 55 53 45 52}
		$s3 = {78 68 6d 6f 77 6c}
		$s4 = {3f 4b 45 59 4b 59}
		$s5 = {48 48 3a 6d 6d 3a 5f 73}
		$s6 = {3d 6c 69 63 6e 69 5d 20 68 61 73 20 6d 61 58 30 74}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 90KB and 3 of them ) or ( all of them )
}

rule CN_APT_ZeroT_extracted_Zlh : hardened
{
	meta:
		description = "Chinese APT by Proofpoint ZeroT RAT - file Zlh.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
		date = "2017-02-04"
		hash1 = "711f0a635bbd6bf1a2890855d0bd51dff79021db45673541972fe6e1288f5705"
		id = "4c8b9a90-6cb3-5aba-a993-f73207341d0e"

	strings:
		$s1 = {6e 00 66 00 6c 00 6f 00 67 00 67 00 65 00 72 00 2e 00 64 00 6c 00 6c 00}
		$s2 = {25 73 20 25 64 3a 20 43 72 65 61 74 65 50 72 6f 63 65 73 73 28 27 25 73 27 2c 20 27 25 73 27 29 20 66 61 69 6c 65 64 2e 20 57 69 6e 64 6f 77 73 20 65 72 72 6f 72 20 63 6f 64 65 20 69 73 20 30 78 25 30 38 78}
		$s3 = {5f 53 74 61 72 74 5a 6c 68 68 28 29 3a 20 45 78 65 63 75 74 65 64 20 22 25 73 22}
		$s4 = {45 78 65 63 75 74 61 62 6c 65 3a 20 27 25 73 27 20 28 25 73 29 20 25 69}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 300KB and 3 of them )
}

