rule derusbi_kernel : hardened
{
	meta:
		description = "Derusbi Driver version"
		date = "2015-12-09"
		author = "Airbus Defence and Space Cybersecurity CSIRT - Fabien Perigaud"
		id = "a60ab93a-e2be-53ee-a7da-56c763bc5533"

	strings:
		$token1 = {24 24 24 2d 2d 48 65 6c 6c 6f}
		$token2 = {57 72 6f 64 2d 2d 24 24 24}
		$class = {2e 3f 41 56 50 43 43 5f 42 41 53 45 4d 4f 44 40 40}

	condition:
		uint16( 0 ) == 0x5A4D and $token1 and $token2 and $class
}

rule derusbi_linux : hardened
{
	meta:
		description = "Derusbi Server Linux version"
		date = "2015-12-09"
		author = "Airbus Defence and Space Cybersecurity CSIRT - Fabien Perigaud"
		id = "2b33afb5-be87-5d41-b05e-b99d0c1d8ed9"

	strings:
		$PS1 = {50 53 31 3d 52 4b 23 20 5c 75 40 5c 68 3a 5c 77 20 5c 24}
		$cmd = {75 6e 73 65 74 20 4c 53 5f 4f 50 54 49 4f 4e 53 3b 75 6e 61 6d 65 20 2d 61}
		$pname = {5b 64 69 73 6b 69 6f 5d}
		$rkfile = {2f 74 6d 70 2f 2e 73 65 63 75 72 65}
		$ELF = {7f 45 4c 46}

	condition:
		$ELF at 0 and $PS1 and $cmd and $pname and $rkfile
}

rule Derusbi_Kernel_Driver_WD_UDFS : hardened
{
	meta:
		description = "Detects Derusbi Kernel Driver"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://blog.airbuscybersecurity.com/post/2015/11/Newcomers-in-the-Derusbi-family"
		date = "2015-12-15"
		score = 80
		hash1 = "1b449121300b0188ff9f6a8c399fb818d0cf53fd36cf012e6908a2665a27f016"
		hash2 = "50174311e524b97ea5cb4f3ea571dd477d1f0eee06cd3ed73af39a15f3e6484a"
		hash3 = "6cdb65dbfb2c236b6d149fd9836cb484d0608ea082cf5bd88edde31ad11a0d58"
		hash4 = "e27fb16dce7fff714f4b05f2cef53e1919a34d7ec0e595f2eaa155861a213e59"
		id = "51d80d19-f87f-5b09-ac49-08ebcb464013"

	strings:
		$x1 = {5c 00 5c 00 2e 00 5c 00 70 00 69 00 70 00 65 00 5c 00 75 00 73 00 62 00 70 00 63 00 65 00 78 00 25 00 64 00}
		$x2 = {5c 00 5c 00 2e 00 5c 00 70 00 69 00 70 00 65 00 5c 00 75 00 73 00 62 00 70 00 63 00 67 00 25 00 64 00}
		$x3 = {5c 00 3f 00 3f 00 5c 00 70 00 69 00 70 00 65 00 5c 00 75 00 73 00 62 00 70 00 63 00 65 00 78 00 25 00 64 00}
		$x4 = {5c 00 3f 00 3f 00 5c 00 70 00 69 00 70 00 65 00 5c 00 75 00 73 00 62 00 70 00 63 00 67 00 25 00 64 00}
		$x5 = {24 24 24 2d 2d 48 65 6c 6c 6f}
		$x6 = {57 72 6f 64 2d 2d 24 24 24}
		$s1 = {5c 00 52 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 5c 00 55 00 73 00 65 00 72 00 5c 00 25 00 73 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 53 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00}
		$s2 = {55 70 64 61 74 65 2e 64 6c 6c}
		$s3 = {5c 00 52 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 5c 00 4d 00 61 00 63 00 68 00 69 00 6e 00 65 00 5c 00 53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5c 00 57 00 4d 00 49 00}
		$s4 = {5c 00 44 00 72 00 69 00 76 00 65 00 72 00 5c 00 6e 00 73 00 69 00 70 00 72 00 6f 00 78 00 79 00}
		$s5 = {48 4f 53 54 3a 20 25 73}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 800KB and ( 2 of ( $x* ) or all of ( $s* ) )
}

rule Derusbi_Code_Signing_Cert : hardened
{
	meta:
		description = "Detects an executable signed with a certificate also used for Derusbi Trojan - suspicious"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://blog.airbuscybersecurity.com/post/2015/11/Newcomers-in-the-Derusbi-family"
		date = "2015-12-15"
		score = 60
		id = "d123fde9-0182-5232-a716-b76e8d9830c4"

	strings:
		$s1 = {46 75 71 69 6e 67 20 44 61 77 75 20 54 65 63 68 6e 6f 6c 6f 67 79 20 43 6f 2e 2c 4c 74 64 2e 30}
		$s2 = {58 4c 20 47 61 6d 65 73 20 43 6f 2e 2c 4c 74 64 2e 30}
		$s3 = {57 65 6d 61 64 65 20 45 6e 74 65 72 74 61 69 6e 6d 65 6e 74 20 63 6f 2e 2c 4c 74 64 30}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 800KB and 1 of them
}

rule XOR_4byte_Key : hardened
{
	meta:
		description = "Detects an executable encrypted with a 4 byte XOR (also used for Derusbi Trojan)"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://blog.airbuscybersecurity.com/post/2015/11/Newcomers-in-the-Derusbi-family"
		date = "2015-12-15"
		score = 60
		id = "77850332-87ce-5ed3-bb09-88e91e5bb5f6"

	strings:
		$s1 = { 85 C9 74 0A 31 06 01 1E 83 C6 04 49 EB F2 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 900KB and all of them
}

rule Derusbi_Backdoor_Mar17_1 : hardened
{
	meta:
		description = "Detects a variant of the Derusbi backdoor"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-03-03"
		hash1 = "f87915f21dcc527981ebb6db3d332b5b341129b4af83524f59d7178e9d2a3a32"
		id = "5c8838d6-b9c2-589e-b6a2-a8c7ad6f10cc"

	strings:
		$x1 = {25 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 25 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 77 00 69 00 61 00 73 00 65 00 72 00 76 00 63 00 2e 00 64 00 6c 00 6c 00}
		$x2 = {63 00 25 00 57 00 49 00 4e 00 44 00 49 00 52 00 25 00 5c 00 50 00 43 00 48 00 65 00 61 00 6c 00 74 00 68 00 5c 00 48 00 65 00 6c 00 70 00 43 00 74 00 72 00 5c 00 42 00 69 00 6e 00 61 00 72 00 69 00 65 00 73 00 5c 00 70 00 63 00 68 00 73 00 76 00 63 00 2e 00 64 00 6c 00 6c 00}
		$x3 = {25 00 53 00 79 00 73 00 74 00 65 00 6d 00 72 00 6f 00 6f 00 74 00 25 00 5c 00 48 00 65 00 6c 00 70 00 5c 00 70 00 65 00 72 00 66 00 63 00 30 00 30 00 39 00 2e 00 64 00 61 00 74 00}
		$x4 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 20 00 22 00 25 00 73 00 22 00 2c 00 20 00 52 00 33 00 32 00 20 00 25 00 73 00}
		$x5 = {4f 66 66 69 63 65 55 74 33 32 2e 64 6c 6c}
		$x6 = {5c 00 5c 00 2e 00 5c 00 70 00 69 00 70 00 65 00 5c 00 75 00 73 00 62 00 25 00 73 00 6f 00}
		$x7 = {5c 00 5c 00 2e 00 5c 00 70 00 69 00 70 00 65 00 5c 00 75 00 73 00 62 00 25 00 73 00 69 00}
		$x8 = {5c 00 74 00 6d 00 70 00 31 00 2e 00 64 00 61 00 74 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 400KB and 1 of them )
}

