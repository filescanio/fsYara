rule OpCloudHopper_Malware_1 : hardened
{
	meta:
		description = "Detects malware from Operation Cloud Hopper"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
		date = "2017-04-03"
		hash1 = "27876dc5e6f746ff6003450eeea5e98de5d96cbcba9e4694dad94ca3e9fb1ddc"
		id = "28ca64ac-beee-51d9-96d4-a1f6d52823ec"

	strings:
		$s1 = {7a 6f 6b 5d 5c 5c 5c 5a 5a 59 59 59 36 36 36 35 36 34 34 34 34}
		$s2 = {7a 7b 5b 5a 5a 59 55 4b 4b 4b 49 49 47 47 47 47 47 47 47 47 47 47 47 47 47}
		$s3 = {45 45 45 43 45 45 43}
		$s4 = {49 49 45 46 45 45}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 200KB and all of them )
}

rule OpCloudHopper_Malware_2 : hardened
{
	meta:
		description = "Detects Operation CloudHopper malware samples"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
		date = "2017-04-03"
		modified = "2023-01-06"
		score = 90
		hash1 = "c1dbf481b2c3ba596b3542c7dc4e368f322d5c9950a78197a4ddbbaacbd07064"
		id = "7c0a3d68-5f6b-5491-b0c2-94e8cff478d1"

	strings:
		$x1 = {73 45 52 76 45 72 2e 44 6c 6c}
		$x2 = {54 00 6f 00 6f 00 6c 00 62 00 61 00 72 00 46 00 2e 00 64 00 6c 00 6c 00}
		$x3 = {2e 3f 41 56 43 4b 65 79 4c 6f 67 67 65 72 4d 61 6e 61 67 65 72 40 40}
		$x4 = {47 48 30 53 54 43 5a 48}
		$s1 = {25 00 25 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 25 00 25 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 20 00 2d 00 6b 00 20 00 22 00 25 00 73 00 22 00}
		$s2 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 20 00 22 00 25 00 73 00 22 00 2c 00 20 00 55 00 6e 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 20 00 2f 00 75 00 70 00 64 00 61 00 74 00 65 00 20 00 25 00 73 00}
		$s3 = {5c 52 65 6c 65 61 73 65 5c 4c 6f 61 64 65 72 2e 70 64 62}
		$s4 = {25 00 73 00 5c 00 25 00 78 00 2e 00 64 00 6c 00 6c 00}
		$s5 = {4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 2f 00 34 00 2e 00 30 00 20 00 28 00 63 00 6f 00 6d 00 70 00 61 00 74 00 69 00 62 00 6c 00 65 00 29 00}
		$s6 = {5c 00 73 00 79 00 73 00 6c 00 6f 00 67 00 2e 00 64 00 61 00 74 00}
		$s7 = {4e 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00}
		$op1 = { 8d 34 17 8d 49 00 8a 14 0e 3a 14 29 75 05 41 3b }
		$op2 = { 83 e8 14 78 cf c1 e0 06 8b f8 8b c3 8a 08 84 c9 }
		$op3 = { 3b fb 7d 3f 8a 4d 14 8d 45 14 84 c9 74 1b 8a 14 }

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 900KB and ( 1 of ( $x* ) or 3 of ( $s* ) ) or all of ( $op* ) ) or ( 6 of them )
}

rule OpCloudHopper_Malware_3 : hardened
{
	meta:
		description = "Detects malware from Operation Cloud Hopper"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
		date = "2017-04-03"
		hash1 = "c21eaadf9ffc62ca4673e27e06c16447f103c0cf7acd8db6ac5c8bd17805e39d"
		id = "ad1d3b48-d48c-5011-ac51-c8047e1ee8ed"

	strings:
		$s6 = {6f 70 65 72 61 74 6f 72 20 22 22 20}
		$s7 = {7a 6f 6b 5d 5c 5c 5c 5a 5a 59 59 59 36 36 36 35 36 34 34 34 34}
		$s11 = {49 6e 76 6f 6b 65 4d 61 69 6e 56 69 61 43 52 54}
		$s12 = {2e 3f 41 56 41 45 53 40 40}
		$op1 = { b6 4c 06 f5 32 cf 88 4c 06 05 0f b6 4c 06 f9 32 }
		$op2 = { 06 fc eb 03 8a 5e f0 85 c0 74 05 8a 0c 06 eb 03 }
		$op3 = { 7e f8 85 c0 74 06 8a 74 06 08 eb 03 8a 76 fc 85 }

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 600KB and ( all of ( $s* ) and 1 of ( $op* ) ) or all of ( $op* ) ) or ( 5 of them )
}

rule OpCloudHopper_Dropper_1 : hardened
{
	meta:
		description = "Detects malware from Operation Cloud Hopper"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
		date = "2017-04-03"
		hash1 = "411571368804578826b8f24f323617f51b068809b1c769291b21125860dc3f4e"
		id = "b43ffb7e-1643-5560-8719-9c63582920e7"

	strings:
		$s1 = {7b 5c 76 65 72 73 69 6f 6e 32 7d 7b 5c 65 64 6d 69 6e 73 30 7d 7b 5c 6e 6f 66 70 61 67 65 73 31 7d 7b 5c 6e 6f 66 77 6f 72 64 73 31 31 7d 7b 5c 6e 6f 66 63 68 61 72 73 36 39 7d 7b 5c 2a 5c 63 6f 6d 70 61 6e 79 20 67 6f 6f 67 6c 65 7d 7b 5c 6e 6f 66 63 68 61 72 73 77 73 37 39 7d 7b 5c 76 65 72 6e 32 34 36 31 31 7d 7b 5c 2a 5c 70 61 73 73 77 6f 72 64}

	condition:
		( uint16( 0 ) == 0x5c7b and filesize < 700KB and all of them )
}

rule OpCloudHopper_Malware_5 : hardened
{
	meta:
		description = "Detects malware from Operation Cloud Hopper"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
		date = "2017-04-03"
		score = 70
		hash1 = "beb1bc03bb0fba7b0624f8b2330226f8a7da6344afd68c5bc526f9d43838ef01"
		id = "1ad189f8-a4c2-5f56-beec-a55bd516ad8d"

	strings:
		$x1 = {43 57 49 4e 44 4f 57 53 53 59 53 54 45 4d 52 4f 4f 54}
		$x2 = {59 4a 5f 44 5f 4b 52 4f 50 4f 58 5f 4d 5f 4e 55 4a 49 5f 4f 4c 59 5f 53 5f 4a 55 5f 4d 4f 4f 4b}
		$x3 = {4e 4a 4b 5f 4a 4b 5f 53 45 44 5f 50 4e 4a 48 47 46 55 55 47 49 4f 4f 5f 50 49 59}
		$x4 = {63 5f 56 44 47 51 42 55 6c 7d 59 53 42 5f 43 5f 56 44 6c 71 53 44 59 46 55}
		$s7 = {46 41 4c 4c 49 4e 4c 4f 56 45}
		$op1 = { 83 ec 60 8d 4c 24 00 e8 6f ff ff ff 8d 4c 24 00 }

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 100KB and ( 1 of ( $x* ) or 2 of them ) ) or ( 4 of them )
}

rule OpCloudHopper_Malware_6 : hardened
{
	meta:
		description = "Detects malware from Operation Cloud Hopper"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
		date = "2017-04-03"
		hash1 = "aabebea87f211d47f72d662e2449009f83eac666d81b8629cf57219d0ce31af6"
		id = "b7578cbd-0f41-5dec-86f6-5792c305a182"

	strings:
		$s1 = {59 44 4e 43 43 4f 56 5a 4b 58 47 52 56 51 50 4f 42 52 4e 58 58 51 56 4e 51 59 58 42 42 43 4f 4e 43 4f 51 45 47 59 45 4c 49 52 42 45 59 4f 56 4f 44 47 58 43 4f 58 54 48 58 50 43 58 4e 47 55 43 48 52 56 57 4b 4b 5a 53 59 51 4d 41 4f 57 57 47 48 52 53 50 52 47 53 45 55 57 59 4d 45 46 5a 48 52 54 48 4f}
		$s2 = {70 73 79 63 68 69 61 74 72 79 2e 64 61 74}
		$s3 = {6d 65 65 6b 6e 65 73 73 2e 6c 6e 6b}
		$s4 = {53 4f 46 54 57 41 52 45 5c 45 47 47 4f 52 47}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 300KB and 1 of them )
}

rule OpCloudHopper_Malware_7 : hardened
{
	meta:
		description = "Detects malware from Operation Cloud Hopper"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
		date = "2017-04-03"
		hash1 = "44a7bea8a08f4c2feb74c6a00ff1114ba251f3dc6922ea5ffab9e749c98cbdce"
		id = "8d32e379-c902-5330-84f5-693a7649a2e4"

	strings:
		$x1 = {6a 65 70 73 6a 65 70 73 6a 65 70 73 6a 65 70 73 6a 65 70 73 6a 65 70 73 6a 65 70 73 6a 65 70 73 6a 65 70 73 6a 65 70 73}
		$x2 = {65 78 74 4f 65 78 74 4f 65 78 74 4f 65 78 74 4f}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 200KB and 1 of them )
}

rule OpCloudHopper_Malware_8 : hardened
{
	meta:
		description = "Detects malware from Operation Cloud Hopper"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
		date = "2017-04-03"
		hash1 = "19aa5019f3c00211182b2a80dd9675721dac7cfb31d174436d3b8ec9f97d898b"
		hash2 = "5cebc133ae3b6afee27beb7d3cdb5f3d675c3f12b7204531f453e99acdaa87b1"
		id = "5e0a09e3-732a-5a90-9d4a-11eae2aa4cc4"

	strings:
		$s1 = {57 00 53 00 48 00 45 00 4c 00 4c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00}
		$s2 = {6f 70 65 72 61 74 6f 72 20 22 22 20}
		$s3 = {22 00 20 00 2f 00 74 00 20 00 52 00 45 00 47 00 5f 00 53 00 5a 00 20 00 2f 00 64 00 20 00 22 00}
		$s4 = {20 00 2f 00 66 00 20 00 2f 00 76 00 20 00 22 00}
		$s5 = {7a 6f 6b 5d 5c 5c 5c 5a 5a 59 59 59 36 36 36 35 36 34 34 34 34}
		$s6 = {41 00 46 00 58 00 5f 00 44 00 49 00 41 00 4c 00 4f 00 47 00 5f 00 4c 00 41 00 59 00 4f 00 55 00 54 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 900KB and 4 of them )
}

rule OpCloudHopper_Malware_9 : hardened
{
	meta:
		description = "Detects malware from Operation Cloud Hopper"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
		date = "2017-04-03"
		hash1 = "f0002b912135bcee83f901715002514fdc89b5b8ed7585e07e482331e4a56c06"
		id = "5a02f2ac-905d-550a-bde0-cfde6ed1a4ab"

	strings:
		$s1 = {4d 73 4d 70 45 6e 67 2e 65 78 65}
		$op0 = { 2b c7 50 e8 22 83 ff ff ff b6 c0 }

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 2000KB and all of them )
}

rule OpCloudHopper_Malware_10 : hardened
{
	meta:
		description = "Detects malware from Operation Cloud Hopper"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
		date = "2017-04-03"
		hash1 = "5b4028728d8011a2003b7ce6b9ec663dd6a60b7adcc20e2125da318e2d9e13f4"
		id = "a5d3237e-d6db-54ba-bfa6-f642f8096819"

	strings:
		$x1 = {62 00 61 00 6b 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 45 00 58 00 45 00}
		$s19 = {62 00 61 00 6b 00 73 00 68 00 65 00 6c 00 6c 00 20 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 7a 00 69 00 6f 00 6e 00 65 00 20 00 4d 00 46 00 43 00}
		$op0 = { 83 c4 34 c3 57 8b ce e8 92 18 00 00 68 20 70 40 }

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 200KB and 2 of them )
}

rule OpCloudHopper_Malware_11 : hardened
{
	meta:
		description = "Detects malware from Operation Cloud Hopper"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
		date = "2017-04-03"
		hash1 = "a80f6c57f772f20d63021c8971a280c19e8eafe7cc7088344c598d84026dda15"
		id = "18bd2fa9-7eca-5dbc-8e79-953800d5bb0a"

	strings:
		$x1 = {49 4f 47 56 57 44 57 43 58 5a 56 52 48 54 45}
		$op1 = { c9 c3 56 6a 00 8b f1 6a 64 e8 dd 34 00 00 c7 06 }
		$op2 = { 68 38 00 41 00 68 34 00 41 00 e8 d3 }

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 200KB and 2 of them )
}

rule OpCloudHopper_lockdown : hardened
{
	meta:
		description = "Tools related to Operation Cloud Hopper"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/maaaaz/impacket-examples-windows"
		date = "2017-04-07"
		hash1 = "8ca61cef74573d9c1d19b8191c23cbd2b7a1195a74eaba037377e5ee232b1dc5"
		id = "0500f19c-597b-5904-8401-35236215ff29"

	strings:
		$s1 = {6c 6f 63 6b 64 6f 77 6e 2e 64 6c 6c}
		$s3 = {6d 66 65 61 6e 6e 2e 65 78 65}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 300KB and all of them )
}

rule OpCloudHopper_WindowXarBot : hardened
{
	meta:
		description = "Malware related to Operation Cloud Hopper"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf"
		date = "2017-04-07"
		id = "4434632a-1886-5e8b-a205-12220263980a"

	strings:
		$s1 = {5c 52 65 6c 65 61 73 65 5c 57 69 6e 64 6f 77 58 61 72 62 6f 74 2e 70 64 62}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 2000KB and all of them )
}

rule OpCloudHopper_WmiDLL_inMemory : hardened
{
	meta:
		description = "Malware related to Operation Cloud Hopper - Page 25"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf"
		date = "2017-04-07"
		id = "0afb6e52-bc9a-5a68-890b-79a017e5d554"

	strings:
		$s1 = {77 6d 69 2e 64 6c 6c 20 32 3e 26 31}

	condition:
		all of them
}

rule VBS_WMIExec_Tool_Apr17_1 : hardened
{
	meta:
		description = "Tools related to Operation Cloud Hopper"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/maaaaz/impacket-examples-windows"
		date = "2017-04-07"
		hash1 = "21bc328ed8ae81151e7537c27c0d6df6d47ba8909aebd61333e32155d01f3b11"
		id = "8175eb74-38f1-5d8f-a668-aa8e215b032e"

	strings:
		$x1 = {73 74 72 4e 65 74 55 73 65 20 3d 20 22 63 6d 64 2e 65 78 65 20 2f 63 20 6e 65 74 20 75 73 65 20 5c 5c 5c 22 20 26 20 68 6f 73 74}
		$x2 = {6c 6f 63 61 6c 63 6d 64 20 3d 20 22 63 6d 64 2e 65 78 65 20 2f 63 20 22 20 26 20 63 6f 6d 6d 61 6e 64 20}
		$x3 = {26 20 22 20 3e 20 22 20 26 20 54 65 6d 70 46 69 6c 65 20 26 20 22 20 32 3e 26 31 22 20 20 27 32 3e 26 31 20 65 72 72}
		$x4 = {73 74 72 45 78 65 63 20 3d 20 22 63 6d 64 2e 65 78 65 20 2f 63 20 22 20 26 20 63 6d 64 20 26 20 22 20 3e 3e 20 22 20 26 20 72 65 73 75 6c 74 66 69 6c 65 20 26 20 22 20 32 3e 26 31 22 20 20 27 32 3e 26 31 20 65 72 72}
		$x5 = {54 65 6d 70 46 69 6c 65 20 3d 20 6f 62 6a 53 68 65 6c 6c 2e 45 78 70 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 28 22 25 54 45 4d 50 25 22 29 20 26 20 22 5c 77 6d 69 2e 64 6c 6c 22}
		$a1 = {57 4d 49 45 58 45 43 20 45 52 52 4f 52 3a 20 43 6f 6d 6d 61 6e 64 20 2d 3e 20}
		$a2 = {57 4d 49 45 58 45 43 20 3a 20 43 6f 6d 6d 61 6e 64 20 72 65 73 75 6c 74 20 77 69 6c 6c 20 6f 75 74 70 75 74 20 74 6f}
		$a3 = {57 4d 49 45 58 45 43 20 3a 20 54 61 72 67 65 74 20 2d 3e}
		$a4 = {57 4d 49 45 58 45 43 20 3a 20 4c 6f 67 69 6e 20 2d 3e 20 4f 4b}
		$a5 = {57 4d 49 45 58 45 43 20 3a 20 50 72 6f 63 65 73 73 20 63 72 65 61 74 65 64 2e 20 50 49 44 3a}

	condition:
		( filesize < 40KB and 1 of them ) or 3 of them
}

