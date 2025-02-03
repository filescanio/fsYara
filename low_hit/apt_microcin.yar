import "pe"

rule Microcin_Sample_1 : hardened
{
	meta:
		description = "Malware sample mentioned in Microcin technical report by Kaspersky"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/files/2017/09/Microcin_Technical-PDF_eng_final.pdf"
		date = "2017-09-26"
		hash1 = "49816eefcd341d7a9c1715e1f89143862d4775ba4f9730397a1e8529f5f5e200"
		hash2 = "a73f8f76a30ad5ab03dd503cc63de3a150e6ab75440c1060d75addceb4270f46"
		hash3 = "9dd9bb13c2698159eb78a0ecb4e8692fd96ca4ecb50eef194fa7479cb65efb7c"
		id = "96e9ac3b-a837-5909-b17b-259d54e0e7fd"

	strings:
		$s1 = {65 20 43 6c 61 73 73 20 44 65 73 63 72 69 70 74 6f 72 20 61 74 20 28}
		$s2 = {2e 3f 41 56 43 41 6e 74 69 41 6e 74 69 41 70 70 6c 65 46 72 61 6d 65 52 65 61 6c 43 6c 61 73 73 40 40}
		$s3 = {2e 3f 41 56 43 41 6e 74 69 41 6e 74 69 41 70 70 6c 65 46 72 61 6d 65 42 61 73 65 43 6c 61 73 73 40 40}
		$s4 = {2e 3f 41 56 43 41 70 70 6c 65 42 69 6e 52 65 61 6c 43 6c 61 73 73 40 40}
		$s5 = {2e 3f 41 56 43 41 70 70 6c 65 42 69 6e 42 61 73 65 43 6c 61 73 73 40 40}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 300KB and ( 4 of them or pe.imphash ( ) == "897077ca318eaf629cfe74569f10e023" ) )
}

rule Microcin_Sample_2 : hardened
{
	meta:
		description = "Malware sample mentioned in Microcin technical report by Kaspersky"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/files/2017/09/Microcin_Technical-PDF_eng_final.pdf"
		date = "2017-09-26"
		hash1 = "8a7d04229722539f2480270851184d75b26c375a77b468d8cbad6dbdb0c99271"
		id = "8718ef84-be2b-55a6-a4bb-41161548a2b4"

	strings:
		$s2 = {5b 50 61 75 73 65 5d}
		$s7 = {49 63 6f 6e 43 61 63 68 65 5f 25 30 32 64 25 30 32 64 25 30 32 64 25 30 32 64 25 30 32 64}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 200KB and all of them )
}

rule Microcin_Sample_3 : hardened
{
	meta:
		description = "Malware sample mentioned in Microcin technical report by Kaspersky"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/files/2017/09/Microcin_Technical-PDF_eng_final.pdf"
		date = "2017-09-26"
		hash1 = "4f74a3b67c5ed6f38f08786f1601214412249fe128f12c51525135710d681e1d"
		id = "daecdfe3-e78c-55ee-83a3-3cee8cb9bb5f"

	strings:
		$x1 = {43 3a 5c 55 73 65 72 73 5c 4c 65 6e 6f 76 6f 5c 44 65 73 6b 74 6f 70 5c 74 65 73 74 5c 52 65 6c 65 61 73 65 5c 74 65 73 74 2e 70 64 62}
		$s2 = {74 00 65 00 73 00 74 00 2c 00 20 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 20 00 31 00 2e 00 30 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 200KB and all of them )
}

rule Microcin_Sample_4 : hardened
{
	meta:
		description = "Malware sample mentioned in Microcin technical report by Kaspersky"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/files/2017/09/Microcin_Technical-PDF_eng_final.pdf"
		date = "2017-09-26"
		hash1 = "92c01d5af922bdaacb6b0b2dfbe29e5cc58c45cbee5133932a499561dab616b8"
		id = "8a6a0735-422a-5e91-9274-ce55f7bee5d3"

	strings:
		$s1 = {63 00 6d 00 64 00 20 00 2f 00 63 00 20 00 64 00 69 00 72 00 20 00 2f 00 61 00 20 00 2f 00 73 00 20 00 22 00 25 00 73 00 22 00 20 00 3e 00 20 00 22 00 25 00 73 00 22 00}
		$s2 = {69 00 6e 00 69 00 2e 00 64 00 61 00 74 00}
		$s3 = {77 00 69 00 6e 00 75 00 70 00 64 00 61 00 74 00 61 00}
		$f1 = {25 00 73 00 5c 00 28 00 25 00 30 00 38 00 78 00 25 00 30 00 38 00 78 00 29 00 25 00 73 00}
		$f2 = {25 00 73 00 5c 00 64 00 25 00 30 00 38 00 78 00 5c 00 64 00 25 00 30 00 38 00 78 00 2e 00 64 00 62 00}
		$f3 = {25 00 73 00 5c 00 75 00 25 00 30 00 38 00 78 00 5c 00 75 00 25 00 30 00 38 00 78 00 2e 00 64 00 62 00}
		$f4 = {25 00 73 00 5c 00 68 00 25 00 30 00 38 00 78 00 5c 00 68 00 25 00 30 00 38 00 78 00 2e 00 64 00 62 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 200KB and all of ( $s* ) or 5 of them )
}

rule Microcin_Sample_5 : hardened
{
	meta:
		description = "Malware sample mentioned in Microcin technical report by Kaspersky"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/files/2017/09/Microcin_Technical-PDF_eng_final.pdf"
		date = "2017-09-26"
		hash1 = "b9c51397e79d5a5fd37647bc4e4ee63018ac3ab9d050b02190403eb717b1366e"
		id = "cd06f9f7-0ba3-52c9-a814-be1cd53e2e42"

	strings:
		$x1 = {53 6f 72 72 79 2c 20 79 6f 75 20 61 72 65 20 6e 6f 74 20 66 6f 72 74 75 61 6e 74 65 20 5e 5f 5e 2c 20 50 6c 65 61 73 65 20 74 72 79 20 6f 74 68 65 72 20 70 61 73 73 77 6f 72 64 20 64 69 63 74 69 6f 6e 61 72 79 20}
		$x2 = {44 6f 6d 43 72 61 63 6b 20 3c 49 50 3e 20 3c 55 73 65 72 4e 61 6d 65 3e 20 3c 50 61 73 73 77 6f 72 64 5f 44 69 63 20 66 69 6c 65 20 70 61 74 68 3e 20 3c 6f 70 74 69 6f 6e 3e}
		$x3 = {54 68 65 20 70 61 73 73 77 6f 72 64 20 69 73 20 22 25 73 22 20 20 20 20 20 20 20 20 20 54 69 6d 65 3a 20 25 64 28 73 29}
		$x4 = {54 68 65 20 70 61 73 73 77 6f 72 64 20 69 73 20 22 20 25 73 20 22 20 20 20 20 20 20 20 20 20 54 69 6d 65 3a 20 25 64 28 73 29}
		$x5 = {4e 6f 20 70 61 73 73 77 6f 72 64 20 66 6f 75 6e 64 21}
		$x7 = {43 61 6e 20 6e 6f 74 20 66 6f 75 6e 64 20 74 68 65 20 50 61 73 73 77 6f 72 64 20 44 69 63 74 6f 6f 6e 61 72 79 20 66 69 6c 65 21 20}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 100KB and 1 of them ) or 2 of them
}

rule Microcin_Sample_6 : hardened
{
	meta:
		description = "Malware sample mentioned in Microcin technical report by Kaspersky"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/files/2017/09/Microcin_Technical-PDF_eng_final.pdf"
		date = "2017-09-26"
		hash1 = "cbd43e70dc55e94140099722d7b91b07a3997722d4a539ecc4015f37ea14a26e"
		hash2 = "871ab24fd6ae15783dd9df5010d794b6121c4316b11f30a55f23ba37eef4b87a"
		id = "9988723f-a7ca-598f-9a6c-9f3915732117"

	strings:
		$s1 = {2a 2a 20 45 52 52 4f 52 20 2a 2a 20 25 73 3a 20 25 73}
		$s2 = {54 00 45 00 4d 00 50 00 44 00 41 00 54 00 41 00}
		$s3 = {42 00 72 00 75 00 6e 00 74 00 69 00 6d 00 65 00 20 00 65 00 72 00 72 00 6f 00 72 00 20 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 600KB and all of them )
}

