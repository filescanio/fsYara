rule Codoso_PlugX_3 : hardened
{
	meta:
		description = "Detects Codoso APT PlugX Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		date = "2016-01-30"
		hash = "74e1e83ac69e45a3bee78ac2fac00f9e897f281ea75ed179737e9b6fe39971e3"
		id = "55066812-3a8e-5099-afb4-ff7a59f1ccb2"

	strings:
		$s1 = {43 00 61 00 6e 00 6e 00 6f 00 74 00 20 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 66 00 6f 00 6c 00 64 00 65 00 72 00 20 00 25 00 73 00 44 00 43 00 52 00 43 00 20 00 66 00 61 00 69 00 6c 00 65 00 64 00 20 00 69 00 6e 00 20 00 74 00 68 00 65 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 66 00 69 00 6c 00 65 00 20 00 25 00 73 00 2e 00 20 00 43 00 6f 00 72 00 72 00 75 00 70 00 74 00 20 00 66 00 69 00 6c 00 65 00 20 00 6f 00 72 00 20 00 77 00 72 00 6f 00 6e 00 67 00 20 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 2e 00}
		$s2 = {6d 63 73 2e 65 78 65}
		$s3 = {4d 63 41 6c 74 4c 69 62 2e 64 6c 6c}
		$s4 = {57 00 69 00 6e 00 52 00 41 00 52 00 20 00 73 00 65 00 6c 00 66 00 2d 00 65 00 78 00 74 00 72 00 61 00 63 00 74 00 69 00 6e 00 67 00 20 00 61 00 72 00 63 00 68 00 69 00 76 00 65 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1200KB and all of them
}

rule Codoso_PlugX_2 : hardened
{
	meta:
		description = "Detects Codoso APT PlugX Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		date = "2016-01-30"
		hash = "b9510e4484fa7e3034228337768176fce822162ad819539c6ca3631deac043eb"
		id = "0402a0ff-5664-52db-a739-51c5181853f8"

	strings:
		$s1 = {25 00 54 00 45 00 4d 00 50 00 25 00 5c 00 48 00 49 00 44 00}
		$s2 = {25 00 73 00 5c 00 68 00 69 00 64 00 2e 00 64 00 6c 00 6c 00}
		$s3 = {25 00 73 00 5c 00 53 00 4f 00 55 00 4e 00 44 00 4d 00 41 00 4e 00 2e 00 65 00 78 00 65 00}
		$s4 = {22 00 25 00 73 00 5c 00 53 00 4f 00 55 00 4e 00 44 00 4d 00 41 00 4e 00 2e 00 65 00 78 00 65 00 22 00 20 00 25 00 64 00 20 00 25 00 64 00}
		$s5 = {25 00 73 00 5c 00 48 00 49 00 44 00 2e 00 64 00 6c 00 6c 00 78 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 400KB and 3 of them ) or all of them
}

rule Codoso_CustomTCP_4 : hardened
{
	meta:
		description = "Detects Codoso APT CustomTCP Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		date = "2016-01-30"
		hash1 = "ea67d76e9d2e9ce3a8e5f80ff9be8f17b2cd5b1212153fdf36833497d9c060c0"
		hash2 = "130abb54112dd47284fdb169ff276f61f2b69d80ac0a9eac52200506f147b5f8"
		hash3 = "3ea6b2b51050fe7c07e2cf9fa232de6a602aa5eff66a2e997b25785f7cf50daa"
		hash4 = "02cf5c244aebaca6195f45029c1e37b22495609be7bdfcfcd79b0c91eac44a13"
		id = "b6ed6939-db0c-5a47-8839-3337d1bc1f6c"

	strings:
		$x1 = {76 61 72 75 73 5f 73 65 72 76 69 63 65 5f 78 38 36 2e 64 6c 6c}
		$s1 = {2f 73 20 25 73 20 2f 70 20 25 64 20 2f 73 74 20 25 64 20 2f 72 74 20 25 64}
		$s2 = {6e 65 74 20 73 74 61 72 74 20 25 25 31}
		$s3 = {70 69 6e 67 20 31 32 37 2e 31 20 3e 20 6e 75 6c}
		$s4 = {4d 63 49 6e 69 74 4d 49 53 50 41 6c 65 72 74 45 78}
		$s5 = {73 63 20 73 74 61 72 74 20 25 25 31}
		$s6 = {6e 65 74 20 73 74 6f 70 20 25 25 31}
		$s7 = {57 6f 72 6b 65 72 52 75 6e}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 400KB and 5 of them ) or ( $x1 and 2 of ( $s* ) )
}

rule Codoso_CustomTCP_3 : hardened
{
	meta:
		description = "Detects Codoso APT CustomTCP Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		date = "2016-01-30"
		hash = "d66106ec2e743dae1d71b60a602ca713b93077f56a47045f4fc9143aa3957090"
		id = "b6ed6939-db0c-5a47-8839-3337d1bc1f6c"

	strings:
		$s1 = {44 6e 73 41 70 69 2e 64 6c 6c}
		$s2 = {73 6f 66 74 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 5c 5a 6f 6e 65 4d 61 70 5c 44 6f 6d 61 69 6e 73 5c 25 73}
		$s3 = {43 4f 4e 4e 45 43 54 20 25 73 3a 25 64 20 68 54 54 50 2f 31 2e 31}
		$s4 = {43 4f 4e 4e 45 43 54 20 25 73 3a 25 64 20 48 54 54 70 2f 31 2e 31}
		$s5 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 39 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 36 2e 31 3b 20 54 72 69 64 65 6e 74 2f 34 2e 30 3b 29}
		$s6 = {69 70 68 6c 70 61 70 69 2e 64 6c 6c}
		$s7 = {25 73 79 73 74 65 6d 72 6f 6f 74 25 5c 57 65 62 5c}
		$s8 = {50 72 6f 78 79 2d 41 75 74 68 6f 72 69 7a 61 74 69 6f 6e 3a 20 4e 65 67 6f 74 69 61 74 65 20 25 73}
		$s9 = {43 4c 53 49 44 5c 7b 25 73 7d 5c 49 6e 70 72 6f 63 53 65 72 76 65 72 33 32}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 500KB and 5 of them ) or 7 of them
}

rule Codoso_CustomTCP_2 : hardened
{
	meta:
		description = "Detects Codoso APT CustomTCP Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		date = "2016-01-30"
		hash = "3577845d71ae995762d4a8f43b21ada49d809f95c127b770aff00ae0b64264a3"
		id = "b6ed6939-db0c-5a47-8839-3337d1bc1f6c"

	strings:
		$s1 = {76 61 72 75 73 5f 73 65 72 76 69 63 65 5f 78 38 36 2e 64 6c 6c}
		$s2 = {2f 73 20 25 73 20 2f 70 20 25 64 20 2f 73 74 20 25 64 20 2f 72 74 20 25 64}
		$s3 = {6e 65 74 20 73 74 61 72 74 20 25 25 31}
		$s4 = {70 69 6e 67 20 31 32 37 2e 31 20 3e 20 6e 75 6c}
		$s5 = {4d 63 49 6e 69 74 4d 49 53 50 41 6c 65 72 74 45 78}
		$s6 = {73 63 20 73 74 61 72 74 20 25 25 31}
		$s7 = {42 5f 57 4b 4e 44 4e 53 4b 5e}
		$s8 = {6e 65 74 20 73 74 6f 70 20 25 25 31}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 406KB and all of them
}

rule Codoso_PGV_PVID_6 : hardened
{
	meta:
		description = "Detects Codoso APT PGV_PVID Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		date = "2016-01-30"
		hash = "4b16f6e8414d4192d0286b273b254fa1bd633f5d3d07ceebd03dfdfc32d0f17f"
		id = "6d1d8490-fdcb-5263-ae00-0b436e822fc3"

	strings:
		$s0 = {72 75 6e 64 6c 6c 33 32 20 22 25 73 22 2c 25 73}
		$s1 = {2f 63 20 70 69 6e 67 20 31 32 37 2e 25 64 20 26 20 64 65 6c 20 22 25 73 22}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 6000KB and all of them
}

rule Codoso_Gh0st_3 : hardened
{
	meta:
		description = "Detects Codoso APT Gh0st Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		date = "2016-01-30"
		hash = "bf52ca4d4077ae7e840cf6cd11fdec0bb5be890ddd5687af5cfa581c8c015fcd"
		id = "55fb17c5-ee11-55be-9af3-e9fe8d6160b5"

	strings:
		$x1 = {52 75 6e 4d 65 42 79 44 4c 4c 33 32}
		$s1 = {73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 64 00 6c 00 6c 00}
		$s2 = {73 65 72 76 65 72 2e 64 6c 6c}
		$s3 = {43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 3f 00 20 00 32 00 30 00 30 00 38 00}
		$s4 = {74 65 73 74 73 75 70 64 61 74 65 33 33}
		$s5 = {44 00 65 00 76 00 69 00 63 00 65 00 20 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 20 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00}
		$s6 = {4d 53 56 43 50 36 30 2e 44 4c 4c}
		$s7 = {6d 61 69 6c 2d 6e 65 77 73 2e 65 69 63 70 2e 6e 65 74}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 195KB and $x1 or 4 of them
}

rule Codoso_Gh0st_2 : hardened
{
	meta:
		description = "Detects Codoso APT Gh0st Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		date = "2016-01-30"
		hash = "5402c785037614d09ad41e41e11093635455b53afd55aa054a09a84274725841"
		id = "5643d028-2a76-5bce-bf2f-8be706ab1fd5"

	strings:
		$s0 = {63 6d 64 2e 65 78 65 20 2f 63 20 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 26 26 20 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 26 26 20 73 63 20 73 74 61 72 74 20 25 73 20 26 26 20 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 26 26 20 73 63 20 73 74 61 72 74 20 25 73}
		$s1 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 22 25 73 22 2c 20 52 75 6e 4d 65 42 79 44 4c 4c 33 32}
		$s13 = {45 00 6c 00 65 00 76 00 61 00 74 00 69 00 6f 00 6e 00 3a 00 41 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00 21 00 6e 00 65 00 77 00 3a 00 7b 00 33 00 61 00 64 00 30 00 35 00 35 00 37 00 35 00 2d 00 38 00 38 00 35 00 37 00 2d 00 34 00 38 00 35 00 30 00 2d 00 39 00 32 00 37 00 37 00 2d 00 31 00 31 00 62 00 38 00 35 00 62 00 64 00 62 00 38 00 65 00 30 00 39 00 7d 00}
		$s14 = {25 73 20 2d 72 20 64 65 62 75 67 20 31}
		$s15 = {5c 5c 2e 5c 6b 65 79 6d 6d 64 72 76 31}
		$s17 = {52 75 6e 4d 65 42 79 44 4c 4c 33 32}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 500KB and 1 of them
}

rule Codoso_CustomTCP : hardened
{
	meta:
		description = "Codoso CustomTCP Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		date = "2016-01-30"
		hash = "b95d7f56a686a05398198d317c805924c36f3abacbb1b9e3f590ec0d59f845d8"
		id = "b6ed6939-db0c-5a47-8839-3337d1bc1f6c"

	strings:
		$s4 = {77 6e 79 67 6c 77}
		$s5 = {57 6f 72 6b 65 72 52 75 6e}
		$s7 = {62 6f 61 7a 64 63 64}
		$s8 = {77 61 79 66 6c 77}
		$s9 = {43 4f 44 45 54 41 42 4c}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 405KB and all of them
}

rule Codoso_PGV_PVID_5 : hardened
{
	meta:
		description = "Detects Codoso APT PGV PVID Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		date = "2016-01-30"
		super_rule = 1
		hash1 = "13bce64b3b5bdfd24dc6f786b5bee08082ea736be6536ef54f9c908fd1d00f75"
		hash2 = "bc0b885cddf80755c67072c8b5961f7f0adcaeb67a1a5c6b3475614fd51696fe"
		id = "0202d82c-c1f8-59f7-96b6-b21f21c1dc69"

	strings:
		$s1 = {2f 63 20 64 65 6c 20 25 73 20 3e 3e 20 4e 55 4c}
		$s2 = {25 73 25 73 2e 6d 61 6e 69 66 65 73 74}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 500KB and all of them
}

rule Codoso_Gh0st_1 : hardened
{
	meta:
		description = "Detects Codoso APT Gh0st Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		date = "2016-01-30"
		super_rule = 1
		hash1 = "5402c785037614d09ad41e41e11093635455b53afd55aa054a09a84274725841"
		hash2 = "7dc7cec2c3f7e56499175691f64060ebd955813002d4db780e68a8f6e7d0a8f8"
		hash3 = "d7004910a87c90ade7e5ff6169f2b866ece667d2feebed6f0ec856fb838d2297"
		id = "24d9e64c-4b35-5737-92ae-8ec391d494c7"

	strings:
		$x1 = {63 6d 64 2e 65 78 65 20 2f 63 20 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 26 26 20 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 26 26 20 73 63 20 73 74 61 72 74 20 25 73 20 26 26 20 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 26 26 20 73 63 20 73 74 61 72 74 20 25 73}
		$x2 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 22 25 73 22 2c 20 52 75 6e 4d 65 42 79 44 4c 4c 33 32}
		$x3 = {45 00 6c 00 65 00 76 00 61 00 74 00 69 00 6f 00 6e 00 3a 00 41 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00 21 00 6e 00 65 00 77 00 3a 00 7b 00 33 00 61 00 64 00 30 00 35 00 35 00 37 00 35 00 2d 00 38 00 38 00 35 00 37 00 2d 00 34 00 38 00 35 00 30 00 2d 00 39 00 32 00 37 00 37 00 2d 00 31 00 31 00 62 00 38 00 35 00 62 00 64 00 62 00 38 00 65 00 30 00 39 00 7d 00}
		$x4 = {5c 5c 2e 5c 6b 65 79 6d 6d 64 72 76 31}
		$s1 = {73 70 69 64 65 72 61 67 65 6e 74 2e 65 78 65}
		$s2 = {41 56 47 49 44 53 41 67 65 6e 74 2e 65 78 65}
		$s3 = {6b 61 76 73 76 63 2e 65 78 65}
		$s4 = {6d 73 70 61 69 6e 74 2e 65 78 65}
		$s5 = {6b 61 76 2e 65 78 65}
		$s6 = {61 76 70 2e 65 78 65}
		$s7 = {4e 41 56 2e 65 78 65}
		$c1 = {45 00 6c 00 65 00 76 00 61 00 74 00 69 00 6f 00 6e 00 3a 00 41 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00 21 00 6e 00 65 00 77 00 3a 00}
		$c2 = {47 6c 6f 62 61 6c 5c 52 55 4e 44 4c 4c 33 32 45 58 49 54 45 56 45 4e 54 5f 4e 41 4d 45 7b 31 32 38 34 35 2d 38 36 35 34 2d 35 34 33 7d}
		$c3 = {5c 00 73 00 79 00 73 00 70 00 72 00 65 00 70 00 5c 00 73 00 79 00 73 00 70 00 72 00 65 00 70 00 2e 00 65 00 78 00 65 00}
		$c4 = {5c 00 73 00 79 00 73 00 70 00 72 00 65 00 70 00 5c 00 43 00 52 00 59 00 50 00 54 00 42 00 41 00 53 00 45 00 2e 00 64 00 6c 00 6c 00}
		$c5 = {47 6c 6f 62 61 6c 5c 54 45 52 4d 49 4e 41 54 45 45 56 45 4e 54 5f 4e 41 4d 45 7b 31 32 38 34 35 2d 38 36 35 34 2d 35 34 32 7d}
		$c6 = {43 6f 6e 73 65 6e 74 50 72 6f 6d 70 74 42 65 68 61 76 69 6f 72 41 64 6d 69 6e}
		$c7 = {5c 00 73 00 79 00 73 00 70 00 72 00 65 00 70 00}
		$c8 = {47 6c 6f 62 61 6c 5c 55 4e 7b 35 46 46 43 30 43 38 42 2d 38 42 45 35 2d 34 39 64 35 2d 42 39 46 32 2d 42 43 44 43 38 39 37 36 45 45 31 30 7d}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1000KB and ( 4 of ( $s* ) or 4 of ( $c* ) ) or 1 of ( $x* ) or 6 of ( $c* )
}

rule Codoso_PGV_PVID_4 : hardened
{
	meta:
		description = "Detects Codoso APT PlugX Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		date = "2016-01-30"
		super_rule = 1
		hash1 = "13bce64b3b5bdfd24dc6f786b5bee08082ea736be6536ef54f9c908fd1d00f75"
		hash2 = "8a56b476d792983aea0199ee3226f0d04792b70a1c1f05f399cb6e4ce8a38761"
		hash3 = "b2950f2e09f5356e985c38b284ea52175d21feee12e582d674c0da2233b1feb1"
		hash4 = "b631553421aa17171cc47248adc110ca2e79eff44b5e5b0234d69b30cab104e3"
		hash5 = "bc0b885cddf80755c67072c8b5961f7f0adcaeb67a1a5c6b3475614fd51696fe"
		id = "c1c753a6-77b6-5bfb-89f9-16127c264fd0"

	strings:
		$x1 = {64 00 72 00 6f 00 70 00 70 00 65 00 72 00 2c 00 20 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 20 00 31 00 2e 00 30 00}
		$x2 = {64 00 72 00 6f 00 70 00 70 00 65 00 72 00}
		$x3 = {44 00 52 00 4f 00 50 00 50 00 45 00 52 00}
		$x4 = {41 00 62 00 6f 00 75 00 74 00 20 00 64 00 72 00 6f 00 70 00 70 00 65 00 72 00}
		$s1 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 20 00 55 00 74 00 69 00 6c 00 69 00 74 00 79 00}
		$s2 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c}
		$s3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 5c 4e 6f 74 69 66 79}
		$s4 = {3c 61 73 73 65 6d 62 6c 79 20 78 6d 6c 6e 73 3d 22 75 72 6e 3a 73 63 68 65 6d 61 73 2d 6d 69 63 72 6f 73 6f 66 74 2d 63 6f 6d 3a 61 73 6d 2e 76 31 22 20 6d 61 6e 69 66 65 73 74 56 65 72 73 69 6f 6e 3d 22 31 2e 30 22 3e 3c 74 72 75 73 74 49 6e 66 6f 20 78 6d 6c 6e 73 3d 22 75 72 6e 3a 73 63 68 65 6d 61 73 2d 6d 69 63 72 6f 73 6f 66 74 2d 63 6f 6d 3a 61 73 6d 2e 76 33}
		$s5 = {3c 73 75 70 70 6f 72 74 65 64 4f 53 20 49 64 3d 22 7b 65 32 30 31 31 34 35 37 2d 31 35 34 36 2d 34 33 63 35 2d 61 35 66 65 2d 30 30 38 64 65 65 65 33 64 33 66 30 7d 22 3e 3c 2f 73 75 70 70 6f 72 74 65 64 4f 53 3e}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 900KB and 2 of ( $x* ) and 2 of ( $s* )
}

rule Codoso_PlugX_1 : hardened
{
	meta:
		description = "Detects Codoso APT PlugX Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		date = "2016-01-30"
		super_rule = 1
		hash1 = "0b8cbc9b4761ab35acce2aa12ba2c0a283afd596b565705514fd802c8b1e144b"
		hash2 = "448711bd3f689ceebb736d25253233ac244d48cb766834b8f974c2e9d4b462e8"
		hash3 = "fd22547497ce52049083092429eeff0599d0b11fe61186e91c91e1f76b518fe2"
		id = "af777818-5cff-5571-b5e9-0f5a4c8b08ff"

	strings:
		$s1 = {47 45 54 50 41 53 53 57 4f 52 44 31}
		$s2 = {4e 76 53 6d 61 72 74 4d 61 78 2e 64 6c 6c}
		$s3 = {4c 49 43 45 4e 53 45 44 4c 47}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 800KB and all of them
}

rule Codoso_PGV_PVID_3 : hardened
{
	meta:
		description = "Detects Codoso APT PGV PVID Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		date = "2016-01-30"
		super_rule = 1
		hash1 = "126fbdcfed1dfb31865d4b18db2fb963f49df838bf66922fea0c37e06666aee1"
		hash2 = "13bce64b3b5bdfd24dc6f786b5bee08082ea736be6536ef54f9c908fd1d00f75"
		hash3 = "8a56b476d792983aea0199ee3226f0d04792b70a1c1f05f399cb6e4ce8a38761"
		hash4 = "b2950f2e09f5356e985c38b284ea52175d21feee12e582d674c0da2233b1feb1"
		hash5 = "b631553421aa17171cc47248adc110ca2e79eff44b5e5b0234d69b30cab104e3"
		hash6 = "bc0b885cddf80755c67072c8b5961f7f0adcaeb67a1a5c6b3475614fd51696fe"
		id = "08003dba-1201-5f74-9edd-ea321bb26e99"

	strings:
		$x1 = {43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 28 00 43 00 29 00 20 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 20 00 20 00 41 00 6c 00 6c 00 20 00 72 00 69 00 67 00 68 00 74 00 73 00 20 00 72 00 65 00 73 00 65 00 72 00 76 00 65 00 64 00 2e 00 28 00 43 00 29 00 20 00 32 00 30 00 31 00 32 00}

	condition:
		$x1
}

rule Codoso_PGV_PVID_2 : hardened
{
	meta:
		description = "Detects Codoso APT PGV PVID Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		date = "2016-01-30"
		super_rule = 1
		hash1 = "13bce64b3b5bdfd24dc6f786b5bee08082ea736be6536ef54f9c908fd1d00f75"
		hash2 = "b631553421aa17171cc47248adc110ca2e79eff44b5e5b0234d69b30cab104e3"
		hash3 = "bc0b885cddf80755c67072c8b5961f7f0adcaeb67a1a5c6b3475614fd51696fe"
		id = "e4c00806-3092-5ec2-844f-b638c31fa6a5"

	strings:
		$s0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 76 63 48 6f 73 74}
		$s1 = {72 65 67 73 76 72 33 32 2e 65 78 65 20 2f 73 20 22 25 73 22}
		$s2 = {48 65 6c 70 20 61 6e 64 20 53 75 70 70 6f 72 74}
		$s3 = {6e 65 74 73 76 63 73}
		$s9 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 6e 65 74 73 76 63 73}
		$s10 = {77 69 6e 6c 6f 67 6f 6e}
		$s11 = {53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 907KB and all of them
}

rule Codoso_PGV_PVID_1 : hardened
{
	meta:
		description = "Detects Codoso APT PGV PVID Malware"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		date = "2016-01-30"
		super_rule = 1
		hash1 = "41a936b0d1fd90dffb2f6d0bcaf4ad0536f93ca7591f7b75b0cd1af8804d0824"
		hash2 = "58334eb7fed37e3104d8235d918aa5b7856f33ea52a74cf90a5ef5542a404ac3"
		hash3 = "934b87ddceabb2063b5e5bc4f964628fe0c63b63bb2346b105ece19915384fc7"
		hash4 = "ce91ea20aa2e6af79508dd0a40ab0981f463b4d2714de55e66d228c579578266"
		hash5 = "e770a298ae819bba1c70d0c9a2e02e4680d3cdba22d558d21caaa74e3970adf1"
		id = "9487773a-01d9-558e-8866-b8a8650996ba"
		score = 75

	strings:
		$x1 = {44 00 52 00 49 00 56 00 45 00 52 00 53 00 5c 00 69 00 70 00 69 00 6e 00 69 00 70 00 2e 00 73 00 79 00 73 00}
		$s1 = {54 73 57 6f 72 6b 53 70 61 63 65 73 2e 64 6c 6c}
		$s2 = {25 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 25 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 77 00 69 00 61 00 73 00 65 00 72 00 76 00 63 00 2e 00 64 00 6c 00 6c 00}
		$s3 = {2f 73 65 6c 66 73 65 72 76 69 63 65 2f 6d 69 63 72 6f 73 69 74 65 73 2f 73 65 61 72 63 68 2e 70 68 70 3f 25 30 31 36 49 36 34 64}
		$s4 = {2f 73 6f 6c 75 74 69 6f 6e 73 2f 63 6f 6d 70 61 6e 79 2d 73 69 7a 65 2f 73 6d 62 2f 69 6e 64 65 78 2e 68 74 6d 3f 25 30 31 36 49 36 34 64}
		$s5 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00 68 00 61 00 72 00 74 00 20 00 41 00 63 00 74 00 69 00 76 00 65 00 58 00 20 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00}
		$s6 = {4d 00 53 00 43 00 68 00 61 00 72 00 74 00 43 00 74 00 72 00 6c 00 2e 00 6f 00 63 00 78 00}
		$s7 = {7b 25 30 38 58 2d 25 30 34 58 2d 25 30 34 78 2d 25 30 32 58 25 30 32 58 2d 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 7d}
		$s8 = {57 55 53 65 72 76 69 63 65 4d 61 69 6e}
		$s9 = {43 6f 6f 6b 69 65 3a 20 70 67 76 5f 70 76 69 64 3d}

	condition:
		( uint16( 0 ) == 0x5a4d and ( 1 of ( $x* ) or 3 of them ) ) or 5 of them
}

