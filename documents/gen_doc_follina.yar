rule SUSP_PS1_Msdt_Execution_May22 : hardened
{
	meta:
		description = "Detects suspicious calls of msdt.exe as seen in CVE-2022-30190 / Follina exploitation"
		author = "Nasreddine Bencherchali, Christian Burkard"
		date = "2022-05-31"
		modified = "2022-07-08"
		reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
		score = 75
		id = "caa8a042-ffd4-52b2-a9f0-86e6c83a0aa3"

	strings:
		$a = {((50 43 57 44 69 61 67 6e 6f 73 74 69 63) | (50 00 43 00 57 00 44 00 69 00 61 00 67 00 6e 00 6f 00 73 00 74 00 69 00 63 00))}
		$sa1 = {((6d 73 64 74 2e 65 78 65) | (6d 00 73 00 64 00 74 00 2e 00 65 00 78 00 65 00))}
		$sa2 = {((6d 73 64 74 20) | (6d 00 73 00 64 00 74 00 20 00))}
		$sa3 = {((6d 73 2d 6d 73 64 74) | (6d 00 73 00 2d 00 6d 00 73 00 64 00 74 00))}
		$sb1 = {((2f 61 66 20) | (2f 00 61 00 66 00 20 00))}
		$sb2 = {((2d 61 66 20) | (2d 00 61 00 66 00 20 00))}
		$sb3 = {((49 54 5f 42 72 6f 77 73 65 46 6f 72 46 69 6c 65 3d) | (49 00 54 00 5f 00 42 00 72 00 6f 00 77 00 73 00 65 00 46 00 6f 00 72 00 46 00 69 00 6c 00 65 00 3d 00))}
		$fp1 = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00
               46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00
               00 00 70 00 63 00 77 00 72 00 75 00 6E 00 2E 00
               65 00 78 00 65 00 }
		$fp2 = {46 00 69 00 6c 00 65 00 73 00 46 00 75 00 6c 00 6c 00 54 00 72 00 75 00 73 00 74 00}

	condition:
		filesize < 10MB and $a and 1 of ( $sa* ) and 1 of ( $sb* ) and not 1 of ( $fp* )
}

rule SUSP_Doc_WordXMLRels_May22 : hardened
{
	meta:
		description = "Detects a suspicious pattern in docx document.xml.rels file as seen in CVE-2022-30190 / Follina exploitation"
		author = "Tobias Michalski, Christian Burkard, Wojciech Cieslak"
		date = "2022-05-30"
		modified = "2022-06-20"
		reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
		hash = "62f262d180a5a48f89be19369a8425bec596bc6a02ed23100424930791ae3df0"
		score = 70
		id = "304c4816-b2f6-5319-9fe9-8f74bdb82ad0"

	strings:
		$a1 = {3c 52 65 6c 61 74 69 6f 6e 73 68 69 70 73}
		$a2 = {54 61 72 67 65 74 4d 6f 64 65 3d 22 45 78 74 65 72 6e 61 6c 22}
		$x1 = {2e 68 74 6d 6c 21}
		$x2 = {2e 68 74 6d 21}
		$x3 = {25 32 45 25 36 38 25 37 34 25 36 44 25 36 43 25 32 31}
		$x4 = {25 32 45 25 36 38 25 37 34 25 36 44 25 32 31}

	condition:
		filesize < 50KB and all of ( $a* ) and 1 of ( $x* )
}

rule SUSP_Doc_RTF_ExternalResource_May22 : hardened
{
	meta:
		description = "Detects a suspicious pattern in RTF files which downloads external resources as seen in CVE-2022-30190 / Follina exploitation"
		author = "Tobias Michalski, Christian Burkard"
		date = "2022-05-30"
		modified = "2022-05-31"
		reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
		score = 70
		id = "71bb97e0-ec12-504c-a1f6-25039ac91c86"

	strings:
		$s1 = {20 4c 49 4e 4b 20 68 74 6d 6c 66 69 6c 65 20 22 68 74 74 70}
		$s2 = {2e 68 74 6d 6c 21 22 20}

	condition:
		uint32be( 0 ) == 0x7B5C7274 and filesize < 300KB and all of them
}

rule EXPL_Follina_CVE_2022_30190_Msdt_MSProtocolURI_May22 : hardened
{
	meta:
		description = "Detects the malicious usage of the ms-msdt URI as seen in CVE-2022-30190 / Follina exploitation"
		author = "Tobias Michalski, Christian Burkard"
		date = "2022-05-30"
		modified = "2022-07-18"
		reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
		hash1 = "4a24048f81afbe9fb62e7a6a49adbd1faf41f266b5f9feecdceb567aec096784"
		hash2 = "778cbb0ee4afffca6a0b788a97bc2f4855ceb69ddc5eaa230acfa2834e1aeb07"
		score = 80
		id = "62e67c25-a420-5dac-9d1c-b0648ea6b574"

	strings:
		$re1 = /location\.href\s{0,20}=\s{0,20}"ms-msdt:/
		$a1 = {25 36 44 25 37 33 25 32 44 25 36 44 25 37 33 25 36 34 25 37 34 25 33 41 25 32 46}

	condition:
		filesize > 3KB and filesize < 100KB and 1 of them
}

rule SUSP_Doc_RTF_OLE2Link_Jun22 : hardened limited
{
	meta:
		description = "Detects a suspicious pattern in RTF files which downloads external resources"
		author = "Christian Burkard"
		date = "2022-06-01"
		reference = "Internal Research"
		hash = "4abc20e5130b59639e20bd6b8ad759af18eb284f46e99a5cc6b4f16f09456a68"
		score = 60
		id = "e9c83d58-6214-51d5-882a-4bd2ed6acc9a"

	strings:
		$sa = {5c 6f 62 6a 64 61 74 61}
		$sb1 = {34 66 34 63 34 35 33 32 34 63 36 39 36 65 36 62}
		$sb2 = {34 46 34 43 34 35 33 32 34 43 36 39 36 45 36 42}
		$sc1 = {64 30 63 66 31 31 65 30 61 31 62 31 31 61 65 31}
		$sc2 = {44 30 43 46 31 31 45 30 41 31 42 31 31 41 45 31}
		$x1 = {36 38 30 30 37 34 30 30 37 34 30 30 37 30 30 30 33 61 30 30 32 66 30 30 32 66 30 30}
		$x2 = {36 38 30 30 37 34 30 30 37 34 30 30 37 30 30 30 33 41 30 30 32 46 30 30 32 46 30 30}
		$x3 = {36 38 30 30 37 34 30 30 37 34 30 30 37 30 30 30 37 33 30 30 33 61 30 30 32 66 30 30 32 66 30 30}
		$x4 = {36 38 30 30 37 34 30 30 37 34 30 30 37 30 30 30 37 33 30 30 33 41 30 30 32 46 30 30 32 46 30 30}
		$x5 = {36 36 30 30 37 34 30 30 37 30 30 30 33 61 30 30 32 66 30 30 32 66 30 30}
		$x6 = {36 36 30 30 37 34 30 30 37 30 30 30 33 41 30 30 32 46 30 30 32 46 30 30}

	condition:
		( uint32be( 0 ) == 0x7B5C7274 or uint32be( 0 ) == 0x7B5C2A5C ) and $sa and 1 of ( $sb* ) and 1 of ( $sc* ) and 1 of ( $x* )
}

rule SUSP_Doc_RTF_OLE2Link_EMAIL_Jun22 : hardened
{
	meta:
		description = "Detects a suspicious pattern in RTF files which downloads external resources inside e-mail attachments"
		author = "Christian Burkard"
		date = "2022-06-01"
		reference = "Internal Research"
		hash = "4abc20e5130b59639e20bd6b8ad759af18eb284f46e99a5cc6b4f16f09456a68"
		score = 75
		id = "48cde505-3ce4-52ef-b338-0c08ac4f63de"

	strings:
		$sa1 = {58 47 39 69 61 6d 52 68 64 47}
		$sa2 = {78 76 59 6d 70 6b 59 58 52 68}
		$sa3 = {63 62 32 4a 71 5a 47 46 30 59}
		$sb1 = {4e 47 59 30 59 7a 51 31 4d 7a 49 30 59 7a 59 35 4e 6d 55 32 59}
		$sb2 = {52 6d 4e 47 4d 30 4e 54 4d 79 4e 47 4d 32 4f 54 5a 6c 4e 6d}
		$sb3 = {30 5a 6a 52 6a 4e 44 55 7a 4d 6a 52 6a 4e 6a 6b 32 5a 54 5a 69}
		$sb4 = {4e 45 59 30 51 7a 51 31 4d 7a 49 30 51 7a 59 35 4e 6b 55 32 51}
		$sb5 = {52 47 4e 45 4d 30 4e 54 4d 79 4e 45 4d 32 4f 54 5a 46 4e 6b}
		$sb6 = {30 52 6a 52 44 4e 44 55 7a 4d 6a 52 44 4e 6a 6b 32 52 54 5a 43}
		$sc1 = {5a 44 42 6a 5a 6a 45 78 5a 54 42 68 4d 57 49 78 4d 57 46 6c 4d}
		$sc2 = {51 77 59 32 59 78 4d 57 55 77 59 54 46 69 4d 54 46 68 5a 54}
		$sc3 = {6b 4d 47 4e 6d 4d 54 46 6c 4d 47 45 78 59 6a 45 78 59 57 55 78}
		$sc4 = {52 44 42 44 52 6a 45 78 52 54 42 42 4d 55 49 78 4d 55 46 46 4d}
		$sc5 = {51 77 51 30 59 78 4d 55 55 77 51 54 46 43 4d 54 46 42 52 54}
		$sc6 = {45 4d 45 4e 47 4d 54 46 46 4d 45 45 78 51 6a 45 78 51 55 55 78}
		$x1 = {4e 6a 67 77 4d 44 63 30 4d 44 41 33 4e 44 41 77 4e 7a 41 77 4d 44 4e 68 4d 44 41 79 5a 6a 41 77 4d 6d 59 77 4d}
		$x2 = {59 34 4d 44 41 33 4e 44 41 77 4e 7a 51 77 4d 44 63 77 4d 44 41 7a 59 54 41 77 4d 6d 59 77 4d 44 4a 6d 4d 44}
		$x3 = {32 4f 44 41 77 4e 7a 51 77 4d 44 63 30 4d 44 41 33 4d 44 41 77 4d 32 45 77 4d 44 4a 6d 4d 44 41 79 5a 6a 41 77}
		$x4 = {4e 6a 67 77 4d 44 63 30 4d 44 41 33 4e 44 41 77 4e 7a 41 77 4d 44 4e 42 4d 44 41 79 52 6a 41 77 4d 6b 59 77 4d}
		$x5 = {59 34 4d 44 41 33 4e 44 41 77 4e 7a 51 77 4d 44 63 77 4d 44 41 7a 51 54 41 77 4d 6b 59 77 4d 44 4a 47 4d 44}
		$x6 = {32 4f 44 41 77 4e 7a 51 77 4d 44 63 30 4d 44 41 33 4d 44 41 77 4d 30 45 77 4d 44 4a 47 4d 44 41 79 52 6a 41 77}
		$x7 = {4e 6a 67 77 4d 44 63 30 4d 44 41 33 4e 44 41 77 4e 7a 41 77 4d 44 63 7a 4d 44 41 7a 59 54 41 77 4d 6d 59 77 4d 44 4a 6d 4d 44}
		$x8 = {59 34 4d 44 41 33 4e 44 41 77 4e 7a 51 77 4d 44 63 77 4d 44 41 33 4d 7a 41 77 4d 32 45 77 4d 44 4a 6d 4d 44 41 79 5a 6a 41 77}
		$x9 = {32 4f 44 41 77 4e 7a 51 77 4d 44 63 30 4d 44 41 33 4d 44 41 77 4e 7a 4d 77 4d 44 4e 68 4d 44 41 79 5a 6a 41 77 4d 6d 59 77 4d}
		$x10 = {4e 6a 67 77 4d 44 63 30 4d 44 41 33 4e 44 41 77 4e 7a 41 77 4d 44 63 7a 4d 44 41 7a 51 54 41 77 4d 6b 59 77 4d 44 4a 47 4d 44}
		$x11 = {59 34 4d 44 41 33 4e 44 41 77 4e 7a 51 77 4d 44 63 77 4d 44 41 33 4d 7a 41 77 4d 30 45 77 4d 44 4a 47 4d 44 41 79 52 6a 41 77}
		$x12 = {32 4f 44 41 77 4e 7a 51 77 4d 44 63 30 4d 44 41 33 4d 44 41 77 4e 7a 4d 77 4d 44 4e 42 4d 44 41 79 52 6a 41 77 4d 6b 59 77 4d}
		$x13 = {4e 6a 59 77 4d 44 63 30 4d 44 41 33 4d 44 41 77 4d 32 45 77 4d 44 4a 6d 4d 44 41 79 5a 6a 41 77}
		$x14 = {59 32 4d 44 41 33 4e 44 41 77 4e 7a 41 77 4d 44 4e 68 4d 44 41 79 5a 6a 41 77 4d 6d 59 77 4d}
		$x15 = {32 4e 6a 41 77 4e 7a 51 77 4d 44 63 77 4d 44 41 7a 59 54 41 77 4d 6d 59 77 4d 44 4a 6d 4d 44}
		$x16 = {4e 6a 59 77 4d 44 63 30 4d 44 41 33 4d 44 41 77 4d 30 45 77 4d 44 4a 47 4d 44 41 79 52 6a 41 77}
		$x17 = {59 32 4d 44 41 33 4e 44 41 77 4e 7a 41 77 4d 44 4e 42 4d 44 41 79 52 6a 41 77 4d 6b 59 77 4d}
		$x18 = {32 4e 6a 41 77 4e 7a 51 77 4d 44 63 77 4d 44 41 7a 51 54 41 77 4d 6b 59 77 4d 44 4a 47 4d 44}

	condition:
		filesize < 10MB and 1 of ( $sa* ) and 1 of ( $sb* ) and 1 of ( $sc* ) and 1 of ( $x* )
}

rule SUSP_DOC_RTF_ExternalResource_EMAIL_Jun22 : hardened
{
	meta:
		description = "Detects a suspicious pattern in RTF files which downloads external resources as seen in CVE-2022-30190 / Follina exploitation inside e-mail attachment"
		author = "Christian Burkard"
		date = "2022-06-01"
		reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
		score = 70
		id = "3ddc838c-8520-5572-9652-8cb823f83e27"

	strings:
		$sa1 = {50 46 4a 6c 62 47 46 30 61 57 39 75 63 32 68 70 63 48}
		$sa2 = {78 53 5a 57 78 68 64 47 6c 76 62 6e 4e 6f 61 58 42 7a}
		$sa3 = {38 55 6d 56 73 59 58 52 70 62 32 35 7a 61 47 6c 77 63}
		$sb1 = {56 47 46 79 5a 32 56 30 54 57 39 6b 5a 54 30 69 52 58 68 30 5a 58 4a 75 59 57 77 69}
		$sb2 = {52 68 63 6d 64 6c 64 45 31 76 5a 47 55 39 49 6b 56 34 64 47 56 79 62 6d 46 73 49}
		$sb3 = {55 59 58 4a 6e 5a 58 52 4e 62 32 52 6c 50 53 4a 46 65 48 52 6c 63 6d 35 68 62 43}
		$sc1 = {4c 6d 68 30 62 57 77 68 49}
		$sc2 = {35 6f 64 47 31 73 49 53}
		$sc3 = {75 61 48 52 74 62 43 45 69}

	condition:
		filesize < 400KB and 1 of ( $sa* ) and 1 of ( $sb* ) and 1 of ( $sc* )
}

rule SUSP_Msdt_Artefact_Jun22_2 : hardened limited
{
	meta:
		description = "Detects suspicious pattern in msdt diagnostics log (e.g. CVE-2022-30190 / Follina exploitation)"
		author = "Christian Burkard"
		date = "2022-06-01"
		modified = "2022-07-29"
		reference = "https://twitter.com/nas_bench/status/1531718490494844928"
		score = 75
		id = "aa2a4bd7-2094-5652-a088-f58d0c7d3f62"

	strings:
		$a1 = {3c 53 63 72 69 70 74 45 72 72 6f 72 3e 3c 44 61 74 61 20 69 64 3d 22 53 63 72 69 70 74 4e 61 6d 65 22 20 6e 61 6d 65 3d 22 53 63 72 69 70 74 22 3e 54 53 5f 50 72 6f 67 72 61 6d 43 6f 6d 70 61 74 69 62 69 6c 69 74 79 57 69 7a 61 72 64 2e 70 73 31}
		$x1 = {2f 2e 2e 2f 2e 2e 2f}
		$x2 = {24 28 49 6e 76 6f 6b 65 2d 45 78 70 72 65 73 73 69 6f 6e}
		$x3 = {24 28 49 45 58 28}

	condition:
		uint32( 0 ) == 0x6D783F3C and $a1 and 1 of ( $x* )
}

