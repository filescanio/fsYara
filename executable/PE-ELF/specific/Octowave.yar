rule Octowave_Installer_03_2025 : hardened
{
	meta:
		description = "Detects resources embedded within Octowave Loader MSI installers"
		author = "Jai Minton (@CyberRaiju) - HuntressLabs"
		date = "2025-03-28"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		yt_reference = "https://www.youtube.com/watch?v=NiNIbkiuExU"
		reference = "https://x.com/CyberRaiju/status/1893450184224362946?t=u0X6ST2Qgnrf-ujjphGOSg&s=19"
		hash1 = "05b025b8475c0acbc9a5d2cd13c15088a2fb452aa514d0636f145e1c4c93e6ee"
		hash2 = "500462c4fb6e4d0545f04d63ef981d9611b578948e5cfd61d840ff8e2f206587"
		hash3 = "5ee9e74605b0c26b39b111a89139d95423e54f7a54decf60c7552f45b8b60407"
		hash4 = "76efc8c64654d8f2318cc513c0aaf0da612423b1715e867b4622712ba0b3926f"
		hash5 = "c3e2af892b813f3dcba4d0970489652d6f195b7985dc98f08eaddca7727786f0"
		hash6 = "d7816ba6ddda0c4e833d9bba85864de6b1bd289246fcedae84b8a6581db3f5b6"
		hash7 = "e93969a57ef2a7aee13a159cbf2015e2c8219d9153078e257b743d5cd90f05cb"
		hash8 = "45984ae78d18332ecb33fe3371e5eb556c0db86f1d3ba8a835b72cd61a7eeecf"
		Hash9 = "141a69449a580ac432961df0ca05a277579a97e1a1482b1ffe2485d3c63f9aa7"
		id = "56685a0a-523d-4060-a008-aa28542cb85c"
		score = 65
		tags = "octowave,installer,stego"

	strings:
		$string1 = {4c 61 75 6e 63 68 43 6f 6e 64 69 74 69 6f 6e 73 56 61 6c 69 64 61 74 65 50 72 6f 64 75 63 74 49 44 50 72 6f 63 65 73 73 43 6f 6d 70 6f 6e 65 6e 74 73 55 6e 70 75 62 6c 69 73 68 46 65 61 74 75 72 65 73 52 65 6d 6f 76 65 46 69 6c 65 73 52 65 67 69 73 74 65 72 55 73 65 72 52 65 67 69 73 74 65 72 50 72 6f 64 75 63 74 49 6e 73 74 61 6c 6c 65 64 20 4f 52 20 50 68 79 73 69 63 61 6c 4d 65 6d 6f 72 79 20 3e 3d 20 32 30 34 38}
		$string2 = {2e 63 61 62}
		$string3 = {2e 77 61 76}
		$string4 = {2e 64 6c 6c}
		$supporting1 = {2e 72 61 77}
		$supporting2 = {2e 64 62}
		$supporting3 = {2e 70 61 6b}
		$supporting4 = {2e 62 69 6e}
		$supporting5 = {2e 62 61 6b}
		$supporting6 = {2e 64 61 74}
		$supporting7 = {2e 73 61 76}

	condition:
		( uint32( 0 ) == 0xe011cfd0 ) and filesize < 200000KB and all of ( $string* ) and 1 of ( $supporting* )
}

rule Octowave_Loader_03_2025 : hardened
{
	meta:
		description = "Detects opcodes found in Octowave Loader DLLs and WAV steganography files"
		author = "Jai Minton (@CyberRaiju) - HuntressLabs"
		date = "2025-03-19"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		yt_reference = "https://www.youtube.com/watch?v=NiNIbkiuExU"
		x_reference = "https://x.com/CyberRaiju/status/1893450184224362946?t=u0X6ST2Qgnrf-ujjphGOSg&s=19"
		hash1 = "0504BFBACB6E10B81196F625F2FE37B33500E7BF65FD82D3510A2B178C6CD5BD"
		hash2 = "3A2DB0CB9EE01549A6B660D58115D112D36A744D65705394B54D7D95287C7A74"
		hash3 = "EB50D06057FE123D6E9F7A76D3D1A4BC5307E8F15D017BE8F6031E92136CF36A"
		hash4 = "24715920E749B014BA05F74C96627A27355C5860A14461C106AA48A7ABA371EA"
		shoutout = "https://yaratoolkit.securitybreak.io/"
		id = "84d9f24f-154e-4fef-b6ba-a2e051aa5842"
		score = 75
		tags = "octowave,loader,stego"

	strings:
		$opcode_1 = {
			55
			8B EC
			56
			57
			8B D1
			33 C0
			8B FA
			6A 06
			59
			AB
			AB
			AB
			AB
			8B 45 08
			8B FA
			83 62 10 00
			8B F0
			83 62 14 00
			F3 A5
			83 60 10 00
		}
		$opcode_2 = {
			55
			8B EC
			8B 55 ??
			56
			8B F1
			8B 46 ??
			8B 4E ??
			2B C1
			3B D0
			77 ??
			83 7E ?? 07
			53
			8D 1C 11
			57
			89 5E ??
			8B FE
			76 ??
			8B 3E
			8D 04 12
			50
			FF 75 ??
			8D 0C 4F
			51
			E8 ?? ?? ?? ??
			83 C4 0C
			33 C0
			66 89 04 5F
			8B C6
			5F
			5B
			EB ??
			52
			FF 75 ??
			8B CE
			FF 75 ??
			52
			E8 ?? ?? ?? ??
			5E
			5D
			C2 08 00
		}
		$opcode_3 = {
			55
			8B EC
			8B 4D 08
			83 C9 ??
			56
			3B 4D 10
			77 1C
			8B 75 0C
			8B D6
			8B 45 10
			D1 EA
			2B C2
			3B F0
			77 0C
			8D 04 32
			3B C8
			0F 42 C8
			8B C1
			EB 03
		}
		$opcode_4 = {
			56
			8B F1
			8B 46 14
			83 F8 ??
			76 ??
		}
		$opcode_5 = {
			50
			FF 36
			E8 ?? ?? ?? ??
			59
			59
			83 66 ?? 00
		}
		$opcode_6 = {
			C7 46 14 ?? 00 00 00
			66 89 06
			5E
			C3
		}
		$opcode_7 = {
			55
			8B EC
			51
			51
			A1 ?? ?? ?? ??
			33 C5
			89 45 FC
			8B 4D 0C
			8B 45 08
			89 45 F8
			81 F9 00 10 00 00
			72 ??
			8D 45 0C
			50
			8D 45 F8
			50
			E8 ?? ?? ?? ??
			8B 45 F8
			59
			59
		}

	condition:
		( uint16( 0 ) == ( 0x5a4d ) or uint32( 0 ) == 0x46464952 ) and filesize < 50000KB and all of them
}

rule Octowave_Loader_Supporting_File_03_2025 : hardened
{
	meta:
		description = "Detects supporting file used by Octowave Loader containing hardcoded values"
		author = "Jai Minton (@CyberRaiju) - HuntressLabs"
		date = "2025-03-19"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		yt_reference = "https://www.youtube.com/watch?v=NiNIbkiuExU"
		reference = "https://x.com/CyberRaiju/status/1893450184224362946?t=u0X6ST2Qgnrf-ujjphGOSg&s=19"
		hash1 = "C4CBAA7E4521FA0ED9CC634C5E2BACBF41F46842CA4526B7904D98843A7E9DB9"
		hash2 = "F5CFB2E634539D5DC7FFE202FFDC422EF7457100401BA1FBC21DD05558719865"
		hash3 = "56F1967F7177C166386D864807CDF03D5BBD3F118A285CE67EA226D02E5CF58C"
		hash4 = "11EE5AD8A81AE85E5B7DDF93ADF6EDD20DE8460C755BF0426DFCBC7F658D7E85"
		hash5 = "D218B65493E4D9D85CBC2F7B608F4F7E501708014BC04AF27D33D995AA54A703"
		hash6 = "0C112F9DFE27211B357C74F358D9C144EA10CC0D92D6420B8742B72A65562C5A"
		score = 75
		tags = "octowave,loader,stego"

	strings:
		$unique_key = {1D 1C 1F 1E 01 01 03 02 05 04 07 06 09 D4 0E 0A 0D 0C 0F 0E 31 30 31 32 35 34 36 36 39 38 DC 3F 3D 3C 3E}
		$unique_string = {4d 4c 4f 4e 71 70 73 72 75 74 77 76 79 78}
		$unique_string2 = {41 40 43 42 45 44 47 46 49 48 4b 4a 4d 4c 4f 4e 71 70 73 72 75 74 77 76 79 78}

	condition:
		( uint16( 0 ) != 0x5a4d ) and filesize < 10000KB and all of them
}

