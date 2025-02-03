rule CobaltStrike_Resources_Artifact32_and_Resources_Dropper_v1_49_to_v3_14 : hardened
{
	meta:
		description = "Cobalt Strike's resources/artifact32{.exe,.dll,big.exe,big.dll} and resources/dropper.exe signature for versions 1.49 to 3.14"
		hash = "40fc605a8b95bbd79a3bd7d9af73fbeebe3fada577c99e7a111f6168f6a0d37a"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "243e3761-cbea-561c-97da-f6ba12ebc7ee"
		score = 80
		vetted_family = "cobalt"

	strings:
		$payloadDecoder = { 8B [2] 89 ?? 03 [2] 8B [2] 03 [2] 0F B6 18 8B [2] 89 ?? C1 ?? 1F C1 ?? 1E 01 ?? 83 ?? 03 29 ?? 03 [2] 0F B6 00 31 ?? 88 ?? 8B [2] 89 ?? 03 [2] 8B [2] 03 [2] 0F B6 12 }

	condition:
		any of them
}

rule CobaltStrike_Resources_Artifact32_v3_1_and_v3_2 : hardened
{
	meta:
		description = "Cobalt Strike's resources/artifact32{.dll,.exe,svc.exe,big.exe,big.dll,bigsvc.exe} and resources/artifact32uac(alt).dll signature for versions 3.1 and 3.2"
		hash = "4f14bcd7803a8e22e81e74d6061d0df9e8bac7f96f1213d062a29a8523ae4624"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "4fff7f42-9f50-5945-8ec0-2438ac5c7000"
		score = 80
		vetted_family = "cobalt"

	strings:
		$decoderFunc = { 89 ?? B? 04 00 00 00 99 F7 FF 8B [2] 8A [2] 30 ?? 8A ?? 4? 88 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Artifact32_v3_14_to_v4_x : hardened
{
	meta:
		description = "Cobalt Strike's resources/artifact32{.dll,.exe,big.exe,big.dll,bigsvc.exe} signature for versions 3.14 to 4.x and resources/artifact32svc.exe for 3.14 to 4.x and resources/artifact32uac.dll for v3.14 and v4.0"
		hash = "888bae8d89c03c1d529b04f9e4a051140ce3d7b39bc9ea021ad9fc7c9f467719"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "8a010305-dce5-55f4-b2dd-a736721efe22"
		score = 80
		vetted_family = "cobalt"

	strings:
		$pushFmtStr = {	C7 [3] 5C 00 00 00 C7 [3] 65 00 00 00 C7 [3] 70 00 00 00 C7 [3] 69 00 00 00 C7 [3] 70 00 00 00 F7 F1 C7 [3] 5C 00 00 00  C7 [3] 2E 00 00 00 C7 [3] 5C 00 00 00 }
		$fmtStr = {25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 4d 53 53 45 2d 25 64 2d 73 65 72 76 65 72}

	condition:
		all of them
}

rule CobaltStrike_Resources_Artifact32svc_Exe_v3_1_v3_2_v3_14_and_v4_x : hardened
{
	meta:
		description = "Cobalt Strike's resources/artifact32svc(big).exe signature for versions 3.1 and 3.2 (with overlap with v3.14 through v4.x)"
		hash = "871390255156ce35221478c7837c52d926dfd581173818620b738b4b029e6fd9"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "732169be-e334-5774-b0ac-54b217a8b681"
		score = 80
		vetted_family = "cobalt"

	strings:
		$decoderFunc = { 89 ?? B? 04 00 00 00 99 F7 FF 8B [2] 8A [2] 30 }

	condition:
		$decoderFunc
}

rule CobaltStrike_Resources_Artifact64_v1_49_v2_x_v3_0_v3_3_thru_v3_14 : hardened
{
	meta:
		description = "Cobalt Strike's resources/artifact64{.dll,.exe,big.exe,big.dll,bigsvc.exe,big.x64.dll} and resources/rtifactuac(alt)64.dll signature for versions v1.49, v2.x, v3.0, and v3.3 through v3.14"
		hash = "9ec57d306764517b5956b49d34a3a87d4a6b26a2bb3d0fdb993d055e0cc9920d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "67902782-500e-5a89-8b2a-59ee21bcba3e"
		score = 80
		vetted_family = "cobalt"

	strings:
		$a = { 8B [2] 48 98 48 [2] 48 [3] 8B [2] 48 98 48 [3] 44 [3] 8B [2] 89 ?? C1 ?? 1F C1 ?? 1E 01 ?? 83 ?? 03 29 ?? 48 98 48 [3] 0F B6 00 44 [2] 88 }

	condition:
		$a
}

rule CobaltStrike_Resources_Artifact64_v3_1_v3_2_v3_14_and_v4_0 : hardened
{
	meta:
		description = "Cobalt Strike's resources/artifact64{svcbig.exe,.dll,big.dll,svc.exe} and resources/artifactuac(big)64.dll signature for versions 3.14 to 4.x and resources/artifact32svc.exe for 3.14 to 4.x"
		hash = "2e7a39bd6ac270f8f548855b97c4cef2c2ce7f54c54dd4d1aa0efabeecf3ba90"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "c9e9b8e0-16fe-5abc-b1fe-0e3e586f6db6"
		score = 80
		vetted_family = "cobalt"

	strings:
		$decoderFunction = { 31 ?? EB 0F 41 [2] 03 47 [3] 44 [3] 48 [2] 39 ?? 41 [2] 7C EA 4C [6] E9 }

	condition:
		$decoderFunction
}

rule CobaltStrike_Resources_Artifact64_v3_14_to_v4_x : hardened
{
	meta:
		description = "Cobalt Strike's resources/artifact64{.exe,.dll,svc.exe,svcbig.exe,big.exe,big.dll,.x64.dll,big.x64.dll} and resource/artifactuac(alt)64.exe signature for versions v3.14 through v4.x"
		hash = "decfcca0018f2cec4a200ea057c804bb357300a67c6393b097d52881527b1c44"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "1c7731d3-429b-57aa-9c17-8de7d0841b1e"
		score = 80
		vetted_family = "cobalt"

	strings:
		$fmtBuilder = {
			41 ?? 5C 00 00 00
			C7 [3] 5C 00 00 00
			C7 [3] 65 00 00 00
			C7 [3] 70 00 00 00
			C7 [3] 69 00 00 00
			C7 [3] 70 00 00 00
			C7 [3] 5C 00 00 00
			C7 [3] 2E 00 00 00
			89 [3]
			48 [6]
			E8
		}
		$fmtString = {25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 4d 53 53 45 2d 25 64 2d 73 65 72 76 65 72}

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v1_44 : hardened
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Version 1.44"
		hash = "75102e8041c58768477f5f982500da7e03498643b6ece86194f4b3396215f9c2"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "935ee27f-ce1b-5491-b4a3-cb78f199ab1b"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 0F B7 D2 4A 53 8B D9 83 FA 04 77 36 FF 24 }
		$decode = { B1 ?? 30 88 [4] 40 3D 28 01 00 00 7C F2 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v1_45 : hardened
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Version 1.45"
		hash = "1a92b2024320f581232f2ba1e9a11bef082d5e9723429b3e4febb149458d1bb1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "04d4d0ee-f1ee-5888-8108-ca55243c770a"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 51 0F B7 D2 4A 53 56 83 FA 08 77 6B FF 24 }
		$decode = { B1 ?? 30 88 [4] 40 3D 28 01 00 00 7C F2 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v1_46 : hardened
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Version 1.46"
		hash = "44e34f4024878024d4804246f57a2b819020c88ba7de160415be38cd6b5e2f76"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "79715042-1963-5e48-8b64-7d915da58d84"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 8B F2 83 F9 0C 0F 87 8E 00 00 00 FF 24 }
		$decode = { B1 ?? 30 88 [4] 40 3D A8 01 00 00 7C F2 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v1_47 : hardened
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Version 1.47"
		hash = "8ff6dc80581804391183303bb39fca2a5aba5fe13d81886ab21dbd183d536c8d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "ac2249a9-210c-581f-8dd1-7619356dca7d"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 83 F8 12 77 10 FF 24 }
		$decode = { B1 ?? 30 88 [4] 40 3D A8 01 00 00 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v1_48 : hardened
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Version 1.48"
		hash = "dd4e445572cd5e32d7e9cc121e8de337e6f19ff07547e3f2c6b7fce7eafd15e4"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "dd15099f-ad19-58df-9ed4-ce66d7ee8540"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 48 57 8B F1 8B DA 83 F8 17 77 12 FF 24 }
		$decode = { B1 ?? 30 88 [4] 40 3D A8 01 00 00 7C F2 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v1_49 : hardened
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Version 1.49"
		hash = "52b4bd87e21ee0cbaaa0fc007fd3f894c5fc2c4bae5cbc2a37188de3c2c465fe"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "871e28c9-b580-5a32-8529-2290ded1a1b6"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 48 56 83 F8 1E 0F 87 23 01 00 00 FF 24 }
		$decoder = { B1 ?? 90 30 88 [4] 40 3D A8 01 00 00 7C F2 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v2_0_49 : hardened
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Version 2.0.49"
		hash = "ed08c1a21906e313f619adaa0a6e5eb8120cddd17d0084a30ada306f2aca3a4e"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "087c584a-5ceb-536a-8842-53fbd668df54"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 83 F8 22 0F 87 96 01 00 00 FF 24 }
		$decoder = { B1 ?? EB 03 8D 49 00 30 88 [4] 40 3D 30 05 00 00 72 F2  }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v2_1_and_v2_2 : hardened
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 2.1 and 2.2"
		hash = "ae7a1d12e98b8c9090abe19bcaddbde8db7b119c73f7b40e76cdebb2610afdc2"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "384fb247-aae7-52e1-a45d-6bda0f80a04e"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 49 56 57 83 F9 24 0F 87 8A 01 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v2_3 : hardened
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 2.3"
		hash = "00dd982cb9b37f6effb1a5a057b6571e533aac5e9e9ee39a399bb3637775ff83"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "aed092f1-fbb1-5efe-be8d-fb7c5aba1cde"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 49 56 57 83 F9 26 0F 87 A9 01 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v2_4 : hardened
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 2.4"
		hash = "78c6f3f2b80e6140c4038e9c2bcd523a1b205d27187e37dc039ede4cf560beed"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "347a6b06-84a8-53ff-80a1-05fa1a48a412"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 4A 56 57 83 FA 2F 0F 87 F9 01 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v2_5 : hardened
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 2.5"
		hash = "d99693e3e521f42d19824955bef0cefb79b3a9dbf30f0d832180577674ee2b58"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "a89f9239-099c-5b97-b1df-e8ce2b95ea52"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 48 57 8B F2 83 F8 3A 0F 87 6E 02 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_0 : hardened
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.0"
		hash = "30251f22df7f1be8bc75390a2f208b7514647835f07593f25e470342fd2e3f52"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "132a1be8-f529-5141-ba03-fdf6df3d55d4"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 48 57 8B F2 83 F8 3C 0F 87 89 02 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_1 : hardened
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.1"
		hash = "4de723e784ef4e1633bbbd65e7665adcfb03dd75505b2f17d358d5a40b7f35cf"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "aa511dee-69ea-53bd-be90-d2d03d08c550"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 55 8B EC 83 EC 58 A1 [4] 33 C5 89 45 FC E8 DF F5 FF FF 6A 50 8D 45 A8 50 FF 15 [4] 8D 45 ?? 50 FF 15 [4] 85 C0 74 14 8B 40 0C 83 38 00 74 0C 8B 00 FF 30 FF 15 [4] EB 05 B8 [4] 8B 4D FC 33 CD E8 82 B7 00 00 C9 }
		$decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_2 : hardened
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.2"
		hash = "b490eeb95d150530b8e155da5d7ef778543836a03cb5c27767f1ae4265449a8d"
		rs2 = "a93647c373f16d61c38ba6382901f468247f12ba8cbe56663abb2a11ff2a5144"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "3ccbc0f2-241c-5c10-8930-4a3d264d3b57"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 48 57 8B F2 83 F8 3D 0F 87 83 02 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }
		$version3_1_sig = { 55 8B EC 83 EC 58 A1 [4] 33 C5 89 45 FC E8 DF F5 FF FF 6A 50 8D 45 A8 50 FF 15 [4] 8D 45 ?? 50 FF 15 [4] 85 C0 74 14 8B 40 0C 83 38 00 74 0C 8B 00 FF 30 FF 15 [4] EB 05 B8 [4] 8B 4D FC 33 CD E8 82 B7 00 00 C9 }

	condition:
		$version_sig and $decoder and not $version3_1_sig
}

rule CobaltStrike_Resources_Beacon_Dll_v3_3 : hardened
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.3"
		hash = "158dba14099f847816e2fc22f254c60e09ac999b6c6e2ba6f90c6dd6d937bc42"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "7cce26c9-1403-535f-bd9d-19667c7e313c"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 48 57 8B F1 83 F8 41 0F 87 F0 02 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_4 : hardened
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.4"
		hash = "5c40bfa04a957d68a095dd33431df883e3a075f5b7dea3e0be9834ce6d92daa3"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "58a34ab6-c061-59a2-b929-8519d3d844e7"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 48 57 8B F1 83 F8 42 0F 87 F0 02 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_5_hf1_and_3_5_1 : hardened
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.5-hf1 and 3.5.1 (3.5.x)"
		hash = "c78e70cd74f4acda7d1d0bd85854ccacec79983565425e98c16a9871f1950525"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "1532596e-be0e-58c2-8d3b-5120c793d677"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 48 57 8B F1 83 F8 43 0F 87 07 03 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_6 : hardened
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.6"
		hash = "495a744d0a0b5f08479c53739d08bfbd1f3b9818d8a9cbc75e71fcda6c30207d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "7e7b5c22-82b3-5298-b794-b06d94a668d5"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 48 57 8B F9 83 F8 47 0F 87 2F 03 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_7 : hardened
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.7"
		hash = "f18029e6b12158fb3993f4951dab2dc6e645bb805ae515d205a53a1ef41ca9b2"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "6352a31c-34b8-5886-8e34-ef9221c22e6e"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 48 57 8B F9 83 F8 49 0F 87 47 03 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_8 : hardened limited
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.8"
		hash = "67b6557f614af118a4c409c992c0d9a0cc800025f77861ecf1f3bbc7c293d603"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "6c65cbf8-2c60-5315-b3b2-48dfcee75733"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 48 57 8B F9 83 F8 4B 0F 87 5D 03 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }
		$xmrig_srcpath = {43 3a 2f 55 73 65 72 73 2f 53 4b 4f 4c 2d 4e 4f 54 45 2f 44 65 73 6b 74 6f 70 2f 4c 6f 61 64 65 72 2f 73 63 72 69 70 74 2e 67 6f}
		$c2_1 = {6e 73 37 2e 73 6f 66 74 6c 69 6e 65 2e 74 6f 70}
		$c2_2 = {6e 73 38 2e 73 6f 66 74 6c 69 6e 65 2e 74 6f 70}
		$c2_3 = {6e 73 39 2e 73 6f 66 74 6c 69 6e 65 2e 74 6f 70}

	condition:
		$version_sig and $decoder and ( 2 of ( $c2_* ) or $xmrig_srcpath )
}

rule CobaltStrike_Resources_Beacon_Dll_v3_11 : hardened
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.11"
		hash = "2428b93464585229fd234677627431cae09cfaeb1362fe4f648b8bee59d68f29"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "00e42396-db81-5d43-90ee-5a97b379019e"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 48 57 8B FA 83 F8 50 0F 87 11 03 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_11_bugfix_and_v3_12 : hardened
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.11-bugfix and 3.12"
		hash = "5912c96fffeabb2c5c5cdd4387cfbfafad5f2e995f310ace76ca3643b866e3aa"
		rs2 = "4476a93abe48b7481c7b13dc912090b9476a2cdf46a1c4287b253098e3523192"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "08ff2a2f-97bd-5839-b414-d67fbf2cdb0f"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 48 57 8B FA 83 F8 50 0F 87 0D 03 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_13 : hardened
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.13"
		hash = "362119e3bce42e91cba662ea80f1a7957a5c2b1e92075a28352542f31ac46a0c"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "98dd32e6-9bb5-57b2-a5e5-1c74a0d1e6d3"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 4A 56 57 83 FA 5A 0F 87 2D 03 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_14 : hardened
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Versions 3.14"
		hash = "254c68a92a7108e8c411c7b5b87a2f14654cd9f1324b344f036f6d3b6c7accda"
		rs2 = "87b3eb55a346b52fb42b140c03ac93fc82f5a7f80697801d3f05aea1ad236730"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "00edfc72-c7b8-5100-8275-ae3548b96e49"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 83 FA 5B 77 15 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Sleeve_Beacon_Dll_v4_0_suspected : hardened
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.dll Versions 4.0 (suspected, not confirmed)"
		hash = "e2b2b72454776531bbc6a4a5dd579404250901557f887a6bccaee287ac71b248"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "50ff6e44-ebc0-5000-a816-b385a6675768"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 51 4A 56 57 83 FA 62 0F 87 8F 03 00 00 FF 24 95 56 7B 00 10 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Sleeve_Beacon_Dll_v4_1_and_v4_2 : hardened
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.dll Versions 4.1 and 4.2"
		hash = "daa42f4380cccf8729129768f3588bb98e4833b0c40ad0620bb575b5674d5fc3"
		rs2 = "9de55f27224a4ddb6b2643224a5da9478999c7b2dea3a3d6b3e1808148012bcf"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "793df916-bdf7-5743-b008-0113caf38bae"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 48 57 8B F2 83 F8 63 0F 87 3C 03 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Sleeve_Beacon_Dll_v4_3_v4_4_v4_5_and_v4_6 : hardened
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.dll Versions 4.3 and 4.4"
		hash = "51490c01c72c821f476727c26fbbc85bdbc41464f95b28cdc577e5701790845f"
		rs2 = "78a6fbefa677eeee29d1af4a294ee57319221b329a2fe254442f5708858b37dc"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "976e087c-f371-5fc6-85f8-9c803a91f549"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 48 57 8B F2 83 F8 65 0F 87 47 03 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Sleeve_Beacon_Dll_v4_7_suspected : hardened
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.dll Versions 4.7 (suspected, not confirmed)"
		hash = "da9e91b3d8df3d53425dd298778782be3bdcda40037bd5c92928395153160549"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "4b6f90dd-69f3-5555-9195-6a0aed0fff58"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 53 56 48 57 8B F2 83 F8 67 0F 87 5E 03 00 00  }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_2 : hardened
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.2"
		hash = "5993a027f301f37f3236551e6ded520e96872723a91042bfc54775dcb34c94a1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "61188243-0b90-5bff-bcc8-50f10ed941f6"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 4C 8D 05 9F F8 FF FF 8B D3 48 8B CF E8 05 1A 00 00
                     EB 0A 8B D3 48 8B CF E8 41 21 00 00 48 8B 5C 24 30
                     48 83 C4 20 }
		$decoder = { 80 31 ?? FF C2 48 FF C1 48 63 C2 48 3D 10 06 00 00 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_3 : hardened
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.3"
		hash = "7b00721efeff6ed94ab108477d57b03022692e288cc5814feb5e9d83e3788580"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "fb96ecff-809e-5704-974e-a2d8ef022daa"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 8B D3 48 8B CF E8 89 66 00 00 E9 23 FB FF FF
                     41 B8 01 00 00 00 E9 F3 FD FF FF 48 8D 0D 2A F8 FF FF
                     E8 8D 2B 00 00 48 8B 5C 24 30 48 83 C4 20 }
		$decoder = { 80 31 ?? FF C2 48 FF C1 48 63 C2 48 3D 10 06 00 00 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_4 : hardened
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.4"
		hash = "5a4d48c2eda8cda79dc130f8306699c8203e026533ce5691bf90363473733bf0"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "97ef152c-86c7-513c-a881-e7d594d38dcf"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 8B D3 48 8B CF E8 56 6F 00 00 E9 17 FB FF FF
                     41 B8 01 00 00 00 8B D3 48 8B CF E8 41 4D 00 00
                     48 8B 5C 24 30 48 83 C4 20 }
		$decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_5_hf1_and_v3_5_1 : hardened
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.5-hf1 and 3.5.1"
		hash = "934134ab0ee65ec76ae98a9bb9ad0e9571d80f4bf1eb3491d58bacf06d42dc8d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "0c0e87d3-e0e2-5ddc-9d89-5e56443da4b8"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 8B D3 48 8B CF E8 38 70 00 00 E9 FD FA FF FF
                     41 B8 01 00 00 00 8B D3 48 8B CF E8 3F 4D 00 00
                     48 8B 5C 24 30 48 83 C4 20 5F }
		$decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_6 : hardened
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.6"
		hash = "92b0a4aec6a493bcb1b72ce04dd477fd1af5effa0b88a9d8283f26266bb019a1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "9651a1ca-d8ea-5b0b-bcba-a850c2e07791"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 48 89 5C 24 08 57 48 83 EC 20 41 8B D8 48 8B FA 83 F9 27
                     0F 87 47 03 00 00 0F 84 30 03 00 00 83 F9 14
                     0F 87 A4 01 00 00 0F 84 7A 01 00 00 83 F9 0C
                     0F 87 C8 00 00 00 0F 84 B3 00 00 00 }
		$decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_7 : hardened
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.7"
		hash = "81296a65a24c0f6f22208b0d29e7bb803569746ce562e2fa0d623183a8bcca60"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "27fad98a-2882-5c52-af6e-c7dcf5559624"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 48 89 5C 24 08 57 48 83 EC 20 41 8B D8 48 8B FA 83 F9 28
                     0F 87 7F 03 00 00 0F 84 67 03 00 00 83 F9 15
                     0F 87 DB 01 00 00 0F 84 BF 01 00 00 }
		$decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_8 : hardened
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.8"
		hash = "547d44669dba97a32cb9e95cfb8d3cd278e00599e6a11080df1a9d09226f33ae"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "89809d81-9a8b-5cf3-a251-689bf52e98e0"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 8B D3 48 8B CF E8 7A 52 00 00 EB 0D 45 33 C0 8B D3 48 8B CF
                     E8 8F 55 00 00 }
		$decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_11 : hardened
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.11 (two subversions)"
		hash = "64007e104dddb6b5d5153399d850f1e1f1720d222bed19a26d0b1c500a675b1a"
		rs2 = "815f313e0835e7fdf4a6d93f2774cf642012fd21ce870c48ff489555012e0047"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "bf0c7661-2583-5fca-beb5-abb2b50c860d"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 48 83 EC 20 41 8B D8 48 8B FA 83 F9 2D 0F 87 B2 03 00 00
                     0F 84 90 03 00 00 83 F9 17 0F 87 F8 01 00 00
                     0F 84 DC 01 00 00 83 F9 0E 0F 87 F9 00 00 00
                     0F 84 DD 00 00 00 FF C9 0F 84 C0 00 00 00 83 E9 02
                     0F 84 A6 00 00 00 FF C9 }
		$decoder = {
      80 34 28 ??
      48 FF C0
      48 3D 00 10 00 00
      7C F1
    }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_12 : hardened
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.12"
		hash = "8a28b7a7e32ace2c52c582d0076939d4f10f41f4e5fa82551e7cc8bdbcd77ebc"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "6eeae9f4-96e0-5a98-a8dc-779c916cd968"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 8B D3 48 8B CF E8 F8 2E 00 00 EB 16 8B D3 48 8B CF
                     E8 00 5C 00 00 EB 0A 8B D3 48 8B CF E8 64 4F 00 00 }
		$decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_13 : hardened
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.13"
		hash = "945e10dcd57ba23763481981c6035e0d0427f1d3ba71e75decd94b93f050538e"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "202eb8ea-7afb-515b-9306-67514abf5e55"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 48 8D 0D 01 5B FF FF 48 83 C4 28 E9 A8 54 FF FF 8B D0
                     49 8B CA E8 22 55 FF FF }
		$decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_14 : hardened
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.14"
		hash = "297a8658aaa4a76599a7b79cb0da5b8aa573dd26c9e2c8f071e591200cf30c93"
		rs2 = "39b9040e3dcd1421a36e02df78fe031cbdd2fb1a9083260b8aedea7c2bc406bf"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "d69171e3-86f4-5187-8874-5eee2045f746"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 8B D0 49 8B CA 48 83 C4 28 E9 B1 1F 00 00 8B D0 49 8B CA
                     48 83 C4 28 }
		$decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Sleeve_Beacon_Dll_x86_v4_0_suspected : hardened
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 4.0 (suspected, not confirmed)"
		hash = "55aa2b534fcedc92bb3da54827d0daaa23ece0f02a10eb08f5b5247caaa63a73"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "28a735c4-87d1-5e14-9379-46a6fd0cdd2a"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 41 B8 01 00 00 00 8B D0 49 8B CA 48 83 C4 28 E9 D1 B3 FF FF
                     8B D0 49 8B CA 48 83 C4 28 E9 AF F5 FF FF 45 33 C0
                     4C 8D 0D 8D 70 FF FF 8B D0 49 8B CA E8 9B B0 FF FF }
		$decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Sleeve_Beacon_x64_v4_1_and_v_4_2 : hardened
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 4.1 and 4.2"
		hash = "29ec171300e8d2dad2e1ca2b77912caf0d5f9d1b633a81bb6534acb20a1574b2"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "dc320d17-98fc-5df3-ba05-4d134129317e"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 83 F9 34 0F 87 8E 03 00 00 0F 84 7A 03 00 00 83 F9 1C 0F 87 E6 01 00 00
                     0F 84 D7 01 00 00 83 F9 0E 0F 87 E9 00 00 00 0F 84 CE 00 00 00 FF C9
                     0F 84 B8 00 00 00 83 E9 02 0F 84 9F 00 00 00 FF C9 }
		$decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Sleeve_Beacon_x64_v4_3 : hardened
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Version 4.3"
		hash = "3ac9c3525caa29981775bddec43d686c0e855271f23731c376ba48761c27fa3d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "572616c7-d1ec-5aa1-b142-4f2edf73737f"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 8B D0 49 8B CA 48 83 C4 28 E9 D3 88 FF FF
                     4C 8D 05 84 6E FF FF 8B D0 49 8B CA 48 83 C4 28 }
		$decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Sleeve_Beacon_x64_v4_4_v_4_5_and_v4_6 : hardened
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 4.4 through at least 4.6"
		hash = "3280fec57b7ca94fd2bdb5a4ea1c7e648f565ac077152c5a81469030ccf6ab44"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "79b6bfd4-1e45-5bd9-ac5c-19eb176ce698"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 8B D0 49 8B CA 48 83 C4 28 E9 83 88 FF FF
                     4C 8D 05 A4 6D FF FF 8B D0 49 8B CA 48 83 C4 28 }
		$decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Sleeve_Beacon_x64_v4_5_variant : hardened
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 4.5 (variant)"
		hash = "8f0da7a45945b630cd0dfb5661036e365dcdccd085bc6cff2abeec6f4c9f1035"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "45715da9-8f16-5304-b216-1ca36c508c77"
		score = 80
		vetted_family = "cobalt"

	strings:
		$version_sig = { 41 B8 01 00 00 00 8B D0 49 8B CA 48 83 C4 28 E9 E8 AB FF FF
                     8B D0 49 8B CA E8 1A EB FF FF 48 83 C4 28 }
		$decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}

rule CobaltStrike_Resources_Bind64_Bin_v2_5_through_v4_x : hardened
{
	meta:
		description = "Cobalt Strike's resources/bind64.bin signature for versions v2.5 to v4.x"
		hash = "5dd136f5674f66363ea6463fd315e06690d6cb10e3cc516f2d378df63382955d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "a01e7bc3-40e9-5f87-8fd6-926972be273b"
		score = 80
		vetted_family = "cobalt"

	strings:
		$apiLocator = {
			48 [2]
			AC
			41 [2] 0D
			41 [2]
			38 ??
			75 ??
			4C [4]
			45 [2]
			75 ??
			5?
			44 [2] 24
			49 [2]
			66 [4]
			44 [2] 1C
			49 [2]
			41 [3]
			48
		}
		$calls = {
			41 BA C2 DB 37 67
			FF D5
			48 [2]
			48 [2]
			41 BA B7 E9 38 FF
			FF D5
			4D [2]
			48 [2]
			48 [2]
			41 BA 74 EC 3B E1
			FF D5
			48 [2]
			48 [2]
			41 BA 75 6E 4D 61
		}

	condition:
		$apiLocator and $calls
}

rule CobaltStrike_Resources_Bind_Bin_v2_5_through_v4_x : hardened
{
	meta:
		description = "Cobalt Strike's resources/bind.bin signature for versions 2.5 to 4.x"
		hash = "3727542c0e3c2bf35cacc9e023d1b2d4a1e9e86ee5c62ee5b66184f46ca126d1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "32f129c1-9845-5843-9e16-7d9af217b8e2"
		score = 80
		vetted_family = "cobalt"

	strings:
		$apiLocator = {
			31 ??
			AC
			C1 ?? 0D
			01 ??
			38 ??
			75 ??
			03 [2]
			3B [2]
			75 ??
			5?
			8B ?? 24
			01 ??
			66 8B [2]
			8B ?? 1C
			01 ??
			8B ?? 8B
			01 ??
			89 [3]
			5?
			5?
		}
		$ws2_32 = {
			5D
			68 33 32 00 00
			68 77 73 32 5F
		}
		$listenaccept = {
			5?
			5?
			68 B7 E9 38 FF
			FF ??
			5?
			5?
			5?
			68 74 EC 3B E1
		}

	condition:
		$apiLocator and $ws2_32 and $listenaccept
}

rule CobaltStrike__Resources_Browserpivot_Bin_v1_48_to_v3_14_and_Sleeve_Browserpivot_Dll_v4_0_to_v4_x : hardened
{
	meta:
		description = "Cobalt Strike's resources/browserpivot.bin from v1.48 to v3.14 and sleeve/browserpivot.dll from v4.0 to at least v4.4"
		hash = "12af9f5a7e9bfc49c82a33d38437e2f3f601639afbcdc9be264d3a8d84fd5539"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "55086544-6684-526b-914f-505a562be458"
		score = 80
		vetted_family = "cobalt"

	strings:
		$socket_recv = {
			FF [1-5]
			83 ?? FF
			74 ??
			85 C0
			(74 | 76) ??
			03 ??
			83 ?? 02
			72 ??
			80 ?? 3E FF 0A
			75 ??
			80 ?? 3E FE 0D
		}
		$fmt = {25 31 30 32 34 5b 5e 20 5d 20 25 38 5b 5e 3a 5d 3a 2f 2f 25 31 30 31 36 5b 5e 2f 5d 25 37 31 36 38 5b 5e 20 5d 20 25 31 30 32 34 5b 5e 20 5d}

	condition:
		all of them
}

rule CobaltStrike_Resources_Browserpivot_x64_Bin_v1_48_to_v3_14_and_Sleeve_Browserpivot_x64_Dll_v4_0_to_v4_x : hardened
{
	meta:
		description = "Cobalt Strike's resources/browserpivot.x64.bin from v1.48 to v3.14 and sleeve/browserpivot.x64.dll from v4.0 to at least v4.4"
		hash = "0ad32bc4fbf3189e897805cec0acd68326d9c6f714c543bafb9bc40f7ac63f55"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "a5dfae85-ff9c-5ca5-9ac0-041c6108a6ed"
		score = 80
		vetted_family = "cobalt"

	strings:
		$socket_recv = {
			FF 15 [4]
			83 ?? FF
			74 ??
			85 ??
			74 ??
			03 ??
			83 ?? 02
			72 ??
			8D ?? FF
			80 [2] 0A
			75 ??
			8D ?? FE
			80 [2] 0D
		}
		$fmt = {25 31 30 32 34 5b 5e 20 5d 20 25 38 5b 5e 3a 5d 3a 2f 2f 25 31 30 31 36 5b 5e 2f 5d 25 37 31 36 38 5b 5e 20 5d 20 25 31 30 32 34 5b 5e 20 5d}

	condition:
		all of them
}

rule CobaltStrike_Resources_Bypassuac_Dll_v1_49_to_v3_14_and_Sleeve_Bypassuac_Dll_v4_0_to_v4_x : hardened
{
	meta:
		description = "Cobalt Strike's resources/bypassuac(-x86).dll from v1.49 to v3.14 (32-bit version) and sleeve/bypassuac.dll from v4.0 to at least v4.4"
		hash = "91d12e1d09a642feedee5da966e1c15a2c5aea90c79ac796e267053e466df365"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "614046b5-cf81-56a5-8824-b3a7e14a8ed5"
		score = 80
		vetted_family = "cobalt"

	strings:
		$deleteFileCOM = {
			A1 [4]
			6A 00
			8B ??
			5?
			5?
			FF ?? 48
			85 ??
			75 ??
			A1 [4]
			5?
			8B ??
			FF ?? 54
		}
		$copyFileCOM = {
			A1 [4]
			6A 00
			FF [2]
			8B ??
			FF [5]
			FF [5]
			5?
			FF ?? 40
			85 ??
			[2 - 6]
			A1 [4]
			5?
			8B ??
			FF ?? 54
		}

	condition:
		all of them
}

rule CobaltStrike_Resources_Bypassuac_x64_Dll_v3_3_to_v3_14_and_Sleeve_Bypassuac_x64_Dll_v4_0_and_v4_x : hardened
{
	meta:
		description = "Cobalt Strike's resources/bypassuac-x64.dll from v3.3 to v3.14 (64-bit version) and sleeve/bypassuac.x64.dll from v4.0 to at least v4.4"
		hash = "9ecf56e9099811c461d592c325c65c4f9f27d947cbdf3b8ef8a98a43e583aecb"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "eef83901-63d9-55a3-b115-03f420416177"
		score = 80
		vetted_family = "cobalt"

	strings:
		$deleteFileCOM = {
			48 8B [5]
			45 33 ??
			48 8B ??
			FF 90 90 00 00 00
			85 C0
			75 ??
			48 8B [5]
			48 8B ??
			FF 92 A8 00 00 00
			85 C0
		}
		$copyFileCOM = {
			48 8B [5]
			4C 8B [5]
			48 8B [5]
			48 8B ??
			4C 8B ??
			48 89 [3]
			FF 90 80 00 00 00
			85 C0
			0F 85 [4]
			48 8B [5]
			48 8B 11
			FF 92 A8 00 00 00
		}

	condition:
		all of them
}

rule CobaltStrike_Resources_Bypassuactoken_Dll_v3_11_to_v3_14 : hardened
{
	meta:
		description = "Cobalt Strike's resources/bypassuactoken.dll from v3.11 to v3.14 (32-bit version)"
		hash = "df1c7256dfd78506e38c64c54c0645b6a56fc56b2ffad8c553b0f770c5683070"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "b9f25fa5-bd1d-5ba0-9b1d-bb97e1dbf76b"
		score = 80
		vetted_family = "cobalt"

	strings:
		$isHighIntegrityProcess = {
			5?
			5?
			5?
			8B ??
			6A 19
			5?
			FF 15 [4]
			85 C0
			75 ??
			FF 15 [4]
			83 ?? 7A
			75 ??
			FF [2]
			5?
			FF 15 [4]
			8B ??
			8D [2]
			5?
			FF [2]
			5?
			6A 19
			5?
			FF 15 [4]
			85 C0
			74 ??
			FF ??
			FF 15 [4]
			8A ??
			FE C8
			0F B6 C0
			5?
			FF ??
			FF 15 [4]
			B? 01 00 00 00
			5?
			81 ?? 00 30 00 00
		}
		$executeTaskmgr = {
			6A 3C
			8D ?? C4
			8B ??
			6A 00
			5?
			8B ??
			E8 [4]
			83 C4 0C
			C7 [2] 3C 00 00 00
			8D [2]
			C7 [2] 40 00 00 00
			C7 [6]
			C7 [2] 00 00 00 00
			5?
			C7 [2] 00 00 00 00
			C7 [6]
			C7 [2] 00 00 00 00
			FF 15 [4]
			FF 75 FC
		}

	condition:
		all of them
}

rule CobaltStrike_Resources_Bypassuactoken_x64_Dll_v3_11_to_v3_14 : hardened
{
	meta:
		description = "Cobalt Strike's resources/bypassuactoken.x64.dll from v3.11 to v3.14 (64-bit version)"
		hash = "853068822bbc6b1305b2a9780cf1034f5d9d7127001351a6917f9dbb42f30d67"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "c89befcd-a622-5947-9ce3-a6031901a45a"
		score = 80
		vetted_family = "cobalt"

	strings:
		$isHighIntegrityProcess = {
			83 ?? 7A
			75 ??
			8B [3]
			33 ??
			FF 15 [4]
			44 [4]
			8D [2]
			48 8B ??
			48 8D [3]
			48 8B ??
			4C 8B ??
			48 89 [3]
			FF 15 [4]
			85 C0
			74 ??
			48 8B ??
			FF 15 [4]
			8D [2]
			8A ??
			40 [2]
			0F B6 D1
			48 8B 0F
			FF 15 [4]
			81 ?? 00 30 00 00
		}
		$executeTaskmgr = {
			44 8D ?? 70
			48 8D [3]
			E8 [4]
			83 [3] 00
			48 8D [5]
			0F 57 ??
			66 0F 7F [3]
			48 89 [3]
			48 8D [5]
			48 8D [3]
			C7 [3] 70 00 00 00
			C7 [3] 40 00 00 00
			48 89 [3]
			FF 15
		}

	condition:
		all of them
}

rule CobaltStrike_Resources_Command_Ps1_v2_5_to_v3_7_and_Resources_Compress_Ps1_v3_8_to_v4_x : hardened limited
{
	meta:
		description = "Cobalt Strike's resources/command.ps1 for versions 2.5 to v3.7 and resources/compress.ps1 from v3.8 to v4.x"
		hash = "932dec24b3863584b43caf9bb5d0cfbd7ed1969767d3061a7abdc05d3239ed62"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		score = 75
		id = "c0b81deb-ed20-5f7e-8e15-e6a9e9362594"
		score = 80
		vetted_family = "cobalt"

	strings:
		$ps1 = {24 73 3d 4e 65 77 2d 4f 62 6a 65 63 74 20 49 4f 2e 4d 65 6d 6f 72 79 53 74 72 65 61 6d 28 2c 5b 43 6f 6e 76 65 72 74 5d 3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28}
		$ps2 = {29 29 3b 49 45 58 20 28 4e 65 77 2d 4f 62 6a 65 63 74 20 49 4f 2e 53 74 72 65 61 6d 52 65 61 64 65 72 28 4e 65 77 2d 4f 62 6a 65 63 74 20 49 4f 2e 43 6f 6d 70 72 65 73 73 69 6f 6e 2e 47 7a 69 70 53 74 72 65 61 6d 28 24 73 2c 5b 49 4f 2e 43 6f 6d 70 72 65 73 73 69 6f 6e 2e 43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65 5d 3a 3a 44 65 63 6f 6d 70 72 65 73 73 29 29 29 2e 52 65 61 64 54 6f 45 6e 64 28 29 3b}

	condition:
		all of them
}

rule CobaltStrike_Resources_Covertvpn_Dll_v2_1_to_v4_x : hardened limited
{
	meta:
		description = "Cobalt Strike's resources/covertvpn.dll signature for version v2.2 to v4.4"
		hash = "0a452a94d53e54b1df6ba02bc2f02e06d57153aad111171a94ec65c910d22dcf"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "a65b855c-5703-5b9f-bb57-da8ebf898f9b"
		score = 80
		vetted_family = "cobalt"

	strings:
		$dropComponentsAndActivateDriver_prologue = {
			5?
			68 [4]
			68 [4]
			C7 [3-5] 00 00 00 00
			FF 15 [4]
			50
			FF 15 [4]
			8B ??
			85 ??
			74 ??
			8D [3-5]
			5?
			FF 15 [4]
			50
		}
		$dropFile = {
			6A 00
			5?
			E8 [4]
			83 C4 08
			83 F8 FF
			74 ??
			5?
			[0-5]
			E8 [4]
			83 C4 ??
			[0-2]
			6A 00
			68 80 01 00 00
			6A 02
			6A 00
			6A 05
			68 00 00 00 40
			5?
			FF 15 [4]
			8B ??
			83 ?? FF
			75 ??
			FF 15 [4]
			5?
		}
		$nfp = {6e 70 66 2e 73 79 73}
		$wpcap = {77 70 63 61 70 2e 64 6c 6c}

	condition:
		all of them
}

rule CobaltStrike_Resources_Covertvpn_injector_Exe_v1_44_to_v2_0_49 : hardened limited
{
	meta:
		description = "Cobalt Strike's resources/covertvpn-injector.exe signature for version v1.44 to v2.0.49"
		hash = "d741751520f46602f5a57d1ed49feaa5789115aeeba7fa4fc7cbb534ee335462"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "48485ae2-1d99-5fa8-b8e8-0047e92ef447"
		score = 80
		vetted_family = "cobalt"

	strings:
		$dropComponentsAndActivateDriver_prologue = {
			C7 04 24 [4]
			E8 [4]
			83 EC 04
			C7 44 24 04 [4]
			89 04 24
			E8 59 14 00 00
			83 EC 08
			89 45 ??
			83 7D ?? 00
			74 ??
			E8 [4]
			8D [2]
			89 [3]
			89 04 24
		}
		$dropFile = {
			C7 44 24 04 00 00 00 00
			8B [2]
			89 ?? 24
			E8 [4]
			83 F8 FF
			74 ??
			8B [2]
			89 ?? 24 04
			C7 04 24 [4]
			E8 [4]
			E9 [4]
			C7 44 24 18 00 00 00 00
			C7 44 24 14 80 01 00 00
			C7 44 24 10 02 00 00 00
			C7 44 24 0C 00 00 00 00
			C7 44 24 08 05 00 00 00
			C7 44 24 04 00 00 00 40
			8B [2]
			89 04 24
			E8 [4]
			83 EC 1C
			89 45 ??
		}
		$nfp = {6e 70 66 2e 73 79 73}
		$wpcap = {77 70 63 61 70 2e 64 6c 6c}

	condition:
		all of them
}

rule CobaltStrike_Resources_Dnsstager_Bin_v1_47_through_v4_x : hardened
{
	meta:
		description = "Cobalt Strike's resources/dnsstager.bin signature for versions 1.47 to 4.x"
		hash = "10f946b88486b690305b87c14c244d7bc741015c3fef1c4625fa7f64917897f1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "e1b0e368-9bcf-5d9b-b2b3-8414742f213e"
		score = 80
		vetted_family = "cobalt"

	strings:
		$apiLocator = {
			31 ??
			AC
			C1 ?? 0D
			01 ??
			38 ??
			75 ??
			03 [2]
			3B [2]
			75 ??
			5?
			8B ?? 24
			01 ??
			66 8B [2]
			8B ?? 1C
			01 ??
			8B ?? 8B
			01 ??
			89 [3]
			5?
			5?
		}
		$dnsapi = { 68 64 6E 73 61 }

	condition:
		$apiLocator and $dnsapi
}

rule CobaltStrike_Resources_Elevate_Dll_v3_0_to_v3_14_and_Sleeve_Elevate_Dll_v4_x : hardened
{
	meta:
		description = "Cobalt Strike's resources/elevate.dll signature for v3.0 to v3.14 and sleeve/elevate.dll for v4.x"
		hash = "6deeb2cafe9eeefe5fc5077e63cc08310f895e9d5d492c88c4e567323077aa2f"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "170f62a2-ba4f-5be8-9ec5-402eb7bbde4e"
		score = 80
		vetted_family = "cobalt"

	strings:
		$wnd_proc = {
			6A 00
			6A 28
			68 00 01 00 00
			5?
			C7 [5] 01 00 00 00
			FF ??
			6A 00
			6A 27
			68 00 01 00 00
			5?
			FF ??
			6A 00
			6A 00
			68 01 02 00 00
			5?
			FF ??
		}

	condition:
		$wnd_proc
}

rule CobaltStrike_Resources_Elevate_X64_Dll_v3_0_to_v3_14_and_Sleeve_Elevate_X64_Dll_v4_x : hardened
{
	meta:
		description = "Cobalt Strike's resources/elevate.x64.dll signature for v3.0 to v3.14 and sleeve/elevate.x64.dll for v4.x"
		hash = "c3ee8a9181fed39cec3bd645b32b611ce98d2e84c5a9eff31a8acfd9c26410ec"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "91d5c343-1084-5cfc-9dfa-46f530eb9625"
		score = 80
		vetted_family = "cobalt"

	strings:
		$wnd_proc = {
			81 ?? 21 01 00 00
			75 ??
			83 [5] 00
			75 ??
			45 33 ??
			8D [2]
			C7 [5] 01 00 00 00
			45 [2] 28
			FF 15 [4]
			45 33 ??
			8D [2]
			45 [2] 27
			48 [2]
			FF 15 [4]
			45 33 ??
			45 33 ??
			BA 01 02 00 00
			48
		}

	condition:
		$wnd_proc
}

rule CobaltStrike_Resources_Httpsstager64_Bin_v3_2_through_v4_x : hardened
{
	meta:
		description = "Cobalt Strike's resources/httpsstager64.bin signature for versions v3.2 to v4.x"
		hash = "109b8c55816ddc0defff360c93e8a07019ac812dd1a42209ea7e95ba79b5a573"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "c16e73fc-484a-5f7e-8127-d85a0254d842"
		score = 80
		vetted_family = "cobalt"

	strings:
		$apiLocator = {
			48 [2]
			AC
			41 [2] 0D
			41 [2]
			38 ??
			75 ??
			4C [4]
			45 [2]
			75 ??
			5?
			44 [2] 24
			49 [2]
			66 [4]
			44 [2] 1C
			49 [2]
			41 [3]
			48
		}
		$InternetSetOptionA = {
			BA 1F 00 00 00
			6A 00
			68 80 33 00 00
			49 [2]
			41 ?? 04 00 00 00
			41 ?? 75 46 9E 86
		}

	condition:
		$apiLocator and $InternetSetOptionA
}

rule CobaltStrike_Resources_Httpsstager_Bin_v2_5_through_v4_x : hardened
{
	meta:
		description = "Cobalt Strike's resources/httpsstager.bin signature for versions 2.5 to 4.x"
		hash = "5ebe813a4c899b037ac0ee0962a439833964a7459b7a70f275ac73ea475705b3"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "f45aa40a-3936-50f9-a60e-de7181862d19"
		score = 80
		vetted_family = "cobalt"

	strings:
		$apiLocator = {
			31 ??
			AC
			C1 ?? 0D
			01 ??
			38 ??
			75 ??
			03 [2]
			3B [2]
			75 ??
			5?
			8B ?? 24
			01 ??
			66 8B [2]
			8B ?? 1C
			01 ??
			8B ?? 8B
			01 ??
			89 [3]
			5?
			5?
		}
		$InternetSetOptionA = {
			6A 04
			5?
			6A 1F
			5?
			68 75 46 9E 86
			FF
		}

	condition:
		$apiLocator and $InternetSetOptionA
}

rule CobaltStrike_Resources_Httpstager64_Bin_v3_2_through_v4_x : hardened
{
	meta:
		description = "Cobalt Strike's resources/httpstager64.bin signature for versions v3.2 to v4.x"
		hash = "ad93d1ee561bc25be4a96652942f698eac9b133d8b35ab7e7d3489a25f1d1e76"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "5530dce8-e5a1-5133-9b05-464e3397084a"
		score = 80
		vetted_family = "cobalt"

	strings:
		$apiLocator = {
			48 [2]
			AC
			41 [2] 0D
			41 [2]
			38 ??
			75 ??
			4C [4]
			45 [2]
			75 ??
			5?
			44 [2] 24
			49 [2]
			66 [4]
			44 [2] 1C
			49 [2]
			41 [3]
			48
		}
		$postInternetOpenJmp = {
			41 ?? 3A 56 79 A7
			FF ??
			EB
		}

	condition:
		$apiLocator and $postInternetOpenJmp
}

rule CobaltStrike_Resources_Httpstager_Bin_v2_5_through_v4_x : hardened
{
	meta:
		description = "Cobalt Strike's resources/httpstager.bin signature for versions 2.5 to 4.x"
		hash = "a47569af239af092880751d5e7b68d0d8636d9f678f749056e702c9b063df256"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "86109485-c26c-5c51-8d04-dd1add9a8c57"
		score = 80
		vetted_family = "cobalt"

	strings:
		$apiLocator = {
			31 ??
			AC
			C1 ?? 0D
			01 ??
			38 ??
			75 ??
			03 [2]
			3B [2]
			75 ??
			5?
			8B ?? 24
			01 ??
			66 8B [2]
			8B ?? 1C
			01 ??
			8B ?? 8B
			01 ??
			89 [3]
			5?
			5?
		}
		$downloaderLoop = {
			B? 00 2F 00 00
			39 ??
			74 ??
			31 ??
			( E9 | EB )
		}

	condition:
		$apiLocator and $downloaderLoop
}

rule CobaltStrike_Resources_Reverse64_Bin_v2_5_through_v4_x : hardened
{
	meta:
		description = "Cobalt Strike's resources/reverse64.bin signature for versions v2.5 to v4.x"
		hash = "d2958138c1b7ef681a63865ec4a57b0c75cc76896bf87b21c415b7ec860397e8"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "966e6e4c-85e2-5c94-8245-25367802b7d2"
		score = 80
		vetted_family = "cobalt"

	strings:
		$apiLocator = {
			48 [2]
			AC
			41 [2] 0D
			41 [2]
			38 ??
			75 ??
			4C [4]
			45 [2]
			75 ??
			5?
			44 [2] 24
			49 [2]
			66 [4]
			44 [2] 1C
			49 [2]
			41 [3]
			48
		}
		$calls = {
			48 89 C1
			41 BA EA 0F DF E0
			FF D5
			48 [2]
			6A ??
			41 ??
			4C [2]
			48 [2]
			41 BA 99 A5 74 61
			FF D5
		}

	condition:
		$apiLocator and $calls
}

rule CobaltStrike_Resources_Reverse_Bin_v2_5_through_v4_x : hardened
{
	meta:
		description = "Cobalt Strike's resources/reverse.bin signature for versions 2.5 to 4.x"
		hash = "887f666d6473058e1641c3ce1dd96e47189a59c3b0b85c8b8fccdd41b84000c7"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "182dbcd0-1180-5516-abe3-cf2eebbd0e39"
		score = 80
		vetted_family = "cobalt"

	strings:
		$apiLocator = {
			31 ??
			AC
			C1 ?? 0D
			01 ??
			38 ??
			75 ??
			03 [2]
			3B [2]
			75 ??
			5?
			8B ?? 24
			01 ??
			66 8B [2]
			8B ?? 1C
			01 ??
			8B ?? 8B
			01 ??
			89 [3]
			5?
			5?
		}
		$ws2_32 = {
			5D
			68 33 32 00 00
			68 77 73 32 5F
		}
		$connect = {
			6A 10
			5?
			5?
			68 99 A5 74 61
		}

	condition:
		$apiLocator and $ws2_32 and $connect
}

rule CobaltStrike_Resources_Smbstager_Bin_v2_5_through_v4_x : hardened
{
	meta:
		description = "Cobalt Strike's resources/smbstager.bin signature for versions 2.5 to 4.x"
		hash = "946af5a23e5403ea1caccb2e0988ec1526b375a3e919189f16491eeabc3e7d8c"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "074b7d83-e3d8-541c-804b-2417c21f54d5"
		score = 80
		vetted_family = "cobalt"

	strings:
		$apiLocator = {
			31 ??
			AC
			C1 ?? 0D
			01 ??
			38 ??
			75 ??
			03 [2]
			3B [2]
			75 ??
			5?
			8B ?? 24
			01 ??
			66 8B [2]
			8B ?? 1C
			01 ??
			8B ?? 8B
			01 ??
			89 [3]
			5?
			5?
		}
		$smb = { 68 C6 96 87 52 }
		$smbstart = {
			6A 40
			68 00 10 00 00
			68 FF FF 07 00
			6A 00
			68 58 A4 53 E5
		}

	condition:
		$apiLocator and $smb and $smbstart
}

rule CobaltStrike_Resources_Template_Py_v3_3_to_v4_x : hardened
{
	meta:
		description = "Cobalt Strike's resources/template.py signature for versions v3.3 to v4.x"
		hash = "d5cb406bee013f51d876da44378c0a89b7b3b800d018527334ea0c5793ea4006"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "16aef9a9-b217-5462-93dc-f6273c99ddd0"
		score = 80
		vetted_family = "cobalt"

	strings:
		$arch = {70 6c 61 74 66 6f 72 6d 2e 61 72 63 68 69 74 65 63 74 75 72 65 28 29}
		$nope = {57 69 6e 64 6f 77 73 50 45}
		$alloc = {63 74 79 70 65 73 2e 77 69 6e 64 6c 6c 2e 6b 65 72 6e 65 6c 33 32 2e 56 69 72 74 75 61 6c 41 6c 6c 6f 63}
		$movemem = {63 74 79 70 65 73 2e 77 69 6e 64 6c 6c 2e 6b 65 72 6e 65 6c 33 32 2e 52 74 6c 4d 6f 76 65 4d 65 6d 6f 72 79}
		$thread = {63 74 79 70 65 73 2e 77 69 6e 64 6c 6c 2e 6b 65 72 6e 65 6c 33 32 2e 43 72 65 61 74 65 54 68 72 65 61 64}
		$wait = {63 74 79 70 65 73 2e 77 69 6e 64 6c 6c 2e 6b 65 72 6e 65 6c 33 32 2e 57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74}

	condition:
		all of them
}

rule CobaltStrike_Resources_Template_Sct_v3_3_to_v4_x : hardened limited
{
	meta:
		description = "Cobalt Strike's resources/template.sct signature for versions v3.3 to v4.x"
		hash = "fc66cb120e7bc9209882620f5df7fdf45394c44ca71701a8662210cf3a40e142"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "9d2b1dfa-5f76-503f-9198-6ed0d039e0cb"
		score = 80
		vetted_family = "cobalt"

	strings:
		$scriptletstart = {3c 73 63 72 69 70 74 6c 65 74 3e}
		$registration = {3c 72 65 67 69 73 74 72 61 74 69 6f 6e 20 70 72 6f 67 69 64 3d}
		$classid = {63 6c 61 73 73 69 64 3d}
		$scriptlang = {3c 73 63 72 69 70 74 20 6c 61 6e 67 75 61 67 65 3d 22 76 62 73 63 72 69 70 74 22 3e}
		$cdata = {3c 21 5b 43 44 41 54 41 5b}
		$scriptend = {3c 2f 73 63 72 69 70 74 3e}
		$antiregistration = {3c 2f 72 65 67 69 73 74 72 61 74 69 6f 6e 3e}
		$scriptletend = {3c 2f 73 63 72 69 70 74 6c 65 74 3e}

	condition:
		all of them and @scriptletstart [ 1 ] < @registration [ 1 ] and @registration [ 1 ] < @classid [ 1 ] and @classid [ 1 ] < @scriptlang [ 1 ] and @scriptlang [ 1 ] < @cdata [ 1 ]
}

rule CobaltStrike_Resources__Template_Vbs_v3_3_to_v4_x : hardened limited
{
	meta:
		description = "Cobalt Strike's resources/btemplate.vbs signature for versions v3.3 to v4.x"
		hash = "e0683f953062e63b2aabad7bc6d76a78748504b114329ef8e2ece808b3294135"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "62f35d02-1e4e-5651-b575-888ce06b8bdd"
		score = 80
		vetted_family = "cobalt"

	strings:
		$ea = {45 78 63 65 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e}
		$vis = {56 69 73 69 62 6c 65 20 3d 20 46 61 6c 73 65}
		$wsc = {57 73 63 72 69 70 74 2e 53 68 65 6c 6c}
		$regkey1 = {48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 4f 66 66 69 63 65 5c}
		$regkey2 = {5c 45 78 63 65 6c 5c 53 65 63 75 72 69 74 79 5c 41 63 63 65 73 73 56 42 4f 4d}
		$regwrite = {2e 52 65 67 57 72 69 74 65}
		$dw = {52 45 47 5f 44 57 4f 52 44}
		$code = {2e 43 6f 64 65 4d 6f 64 75 6c 65 2e 41 64 64 46 72 6f 6d 53 74 72 69 6e 67}
		$ao = { 41 75 74 6f 5f 4f 70 65 6e }
		$da = {2e 44 69 73 70 6c 61 79 41 6c 65 72 74 73}

	condition:
		all of them
}

rule CobaltStrike_Resources_Template__x32_x64_Ps1_v1_45_to_v2_5_and_v3_11_to_v3_14 : hardened limited
{
	meta:
		description = "Cobalt Strike's resources/template.x64.ps1, resources/template.x32 from v3.11 to v3.14 and resources/template.ps1 from v1.45 to v2.5 "
		hash = "ff743027a6bcc0fee02107236c1f5c96362eeb91f3a5a2e520a85294741ded87"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "c9fa6a39-0098-5dde-9762-94bc6b2df299"
		score = 80
		vetted_family = "cobalt"

	strings:
		$importVA = {5b 44 6c 6c 49 6d 70 6f 72 74 28 22 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 22 29 5d 20 70 75 62 6c 69 63 20 73 74 61 74 69 63 20 65 78 74 65 72 6e 20 49 6e 74 50 74 72 20 56 69 72 74 75 61 6c 41 6c 6c 6f 63}
		$importCT = {5b 44 6c 6c 49 6d 70 6f 72 74 28 22 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 22 29 5d 20 70 75 62 6c 69 63 20 73 74 61 74 69 63 20 65 78 74 65 72 6e 20 49 6e 74 50 74 72 20 43 72 65 61 74 65 54 68 72 65 61 64}
		$importWFSO = {5b 44 6c 6c 49 6d 70 6f 72 74 28 22 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 22 29 5d 20 70 75 62 6c 69 63 20 73 74 61 74 69 63 20 65 78 74 65 72 6e 20 69 6e 74 20 57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74}
		$compiler = {4e 65 77 2d 4f 62 6a 65 63 74 20 4d 69 63 72 6f 73 6f 66 74 2e 43 53 68 61 72 70 2e 43 53 68 61 72 70 43 6f 64 65 50 72 6f 76 69 64 65 72}
		$params = {4e 65 77 2d 4f 62 6a 65 63 74 20 53 79 73 74 65 6d 2e 43 6f 64 65 44 6f 6d 2e 43 6f 6d 70 69 6c 65 72 2e 43 6f 6d 70 69 6c 65 72 50 61 72 61 6d 65 74 65 72 73}
		$paramsSys32 = {2e 52 65 66 65 72 65 6e 63 65 64 41 73 73 65 6d 62 6c 69 65 73 2e 41 64 64 52 61 6e 67 65 28 40 28 22 53 79 73 74 65 6d 2e 64 6c 6c 22 2c 20 5b 50 73 4f 62 6a 65 63 74 5d 2e 41 73 73 65 6d 62 6c 79 2e 4c 6f 63 61 74 69 6f 6e 29 29}
		$paramsGIM = {2e 47 65 6e 65 72 61 74 65 49 6e 4d 65 6d 6f 72 79 20 3d 20 24 54 72 75 65}
		$result = {24 63 6f 6d 70 69 6c 65 72 2e 43 6f 6d 70 69 6c 65 41 73 73 65 6d 62 6c 79 46 72 6f 6d 53 6f 75 72 63 65 28 24 70 61 72 61 6d 73 2c 20 24 61 73 73 65 6d 62 6c 79 29}

	condition:
		all of them
}

rule CobaltStrike_Resources_Template_x64_Ps1_v3_0_to_v4_x_excluding_3_12_3_13 : hardened limited
{
	meta:
		description = "Cobalt Strike's resources/template.x64.ps1, resources/template.hint.x64.ps1 and resources/template.hint.x32.ps1 from v3.0 to v4.x except 3.12 and 3.13"
		hash = "ff743027a6bcc0fee02107236c1f5c96362eeb91f3a5a2e520a85294741ded87"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "5a808113-aacb-56ca-b3ec-166c73c54b85"
		score = 80
		vetted_family = "cobalt"

	strings:
		$dda = {5b 41 70 70 44 6f 6d 61 69 6e 5d 3a 3a 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e 2e 44 65 66 69 6e 65 44 79 6e 61 6d 69 63 41 73 73 65 6d 62 6c 79}
		$imm = {49 6e 4d 65 6d 6f 72 79 4d 6f 64 75 6c 65}
		$mdt = {4d 79 44 65 6c 65 67 61 74 65 54 79 70 65}
		$rd = {4e 65 77 2d 4f 62 6a 65 63 74 20 53 79 73 74 65 6d 2e 52 65 66 6c 65 63 74 69 6f 6e 2e 41 73 73 65 6d 62 6c 79 4e 61 6d 65 28 27 52 65 66 6c 65 63 74 65 64 44 65 6c 65 67 61 74 65 27 29}
		$data = {5b 42 79 74 65 5b 5d 5d 24 76 61 72 5f 63 6f 64 65 20 3d 20 5b 53 79 73 74 65 6d 2e 43 6f 6e 76 65 72 74 5d 3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28}
		$64bitSpecific = {5b 49 6e 74 50 74 72 5d 3a 3a 73 69 7a 65 20 2d 65 71 20 38}
		$mandatory = {4d 61 6e 64 61 74 6f 72 79 20 3d 20 24 54 72 75 65}

	condition:
		all of them
}

rule CobaltStrike_Resources_Template_x86_Vba_v3_8_to_v4_x : hardened limited
{
	meta:
		description = "Cobalt Strike's resources/template.x86.vba signature for versions v3.8 to v4.x"
		hash = "fc66cb120e7bc9209882620f5df7fdf45394c44ca71701a8662210cf3a40e142"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "11c7758e-93b2-5fe3-873d-b98de579d2b4"
		score = 80
		vetted_family = "cobalt"

	strings:
		$createstuff = {46 75 6e 63 74 69 6f 6e 20 43 72 65 61 74 65 53 74 75 66 66 20 4c 69 62 20 22 6b 65 72 6e 65 6c 33 32 22 20 41 6c 69 61 73 20 22 43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 22}
		$allocstuff = {46 75 6e 63 74 69 6f 6e 20 41 6c 6c 6f 63 53 74 75 66 66 20 4c 69 62 20 22 6b 65 72 6e 65 6c 33 32 22 20 41 6c 69 61 73 20 22 56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 22}
		$writestuff = {46 75 6e 63 74 69 6f 6e 20 57 72 69 74 65 53 74 75 66 66 20 4c 69 62 20 22 6b 65 72 6e 65 6c 33 32 22 20 41 6c 69 61 73 20 22 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 22}
		$runstuff = {46 75 6e 63 74 69 6f 6e 20 52 75 6e 53 74 75 66 66 20 4c 69 62 20 22 6b 65 72 6e 65 6c 33 32 22 20 41 6c 69 61 73 20 22 43 72 65 61 74 65 50 72 6f 63 65 73 73 41 22}
		$vars = {44 69 6d 20 72 77 78 70 61 67 65 20 41 73 20 4c 6f 6e 67}
		$res = {52 75 6e 53 74 75 66 66 28 73 4e 75 6c 6c 2c 20 73 50 72 6f 63 2c 20 42 79 56 61 6c 20 30 26 2c 20 42 79 56 61 6c 20 30 26 2c 20 42 79 56 61 6c 20 31 26 2c 20 42 79 56 61 6c 20 34 26 2c 20 42 79 56 61 6c 20 30 26 2c 20 73 4e 75 6c 6c 2c 20 73 49 6e 66 6f 2c 20 70 49 6e 66 6f 29}
		$rwxpage = {41 6c 6c 6f 63 53 74 75 66 66 28 70 49 6e 66 6f 2e 68 50 72 6f 63 65 73 73 2c 20 30 2c 20 55 42 6f 75 6e 64 28 6d 79 41 72 72 61 79 29 2c 20 26 48 31 30 30 30 2c 20 26 48 34 30 29}

	condition:
		all of them and @vars [ 1 ] < @res [ 1 ] and @allocstuff [ 1 ] < @rwxpage [ 1 ]
}

rule CobaltStrike_Resources_Xor_Bin_v2_x_to_v4_x : hardened
{
	meta:
		description = "Cobalt Strike's resource/xor.bin signature for version 2.x through 4.x"
		hash = "211ccc5d28b480760ec997ed88ab2fbc5c19420a3d34c1df7991e65642638a6f"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "1754746c-3a42-5f7d-808a-ba2e1c0a270e"
		score = 80
		vetted_family = "cobalt"

	strings:
		$stub52 = {fc e8 ?? ?? ?? ?? [1-32] eb 27 5? 8b ??    83 c? ?4 8b ??    31 ?? 83 c? ?4 5? 8b ??    31 ?? 89 ??    31 ?? 83 c? ?4 83 e? ?4 31 ?? 39 ?? 74 ?2 eb ea 5? ff e? e8 d4 ff ff ff}
		$stub56 = {fc e8 ?? ?? ?? ?? [1-32] eb 2b 5d 8b ?? ?? 83 c5 ?4 8b ?? ?? 31 ?? 83 c5 ?4 55 8b ?? ?? 31 ?? 89 ?? ?? 31 ?? 83 c5 ?4 83 e? ?4 31 ?? 39 ?? 74 ?2 eb e8 5? ff e? e8 d? ff ff ff}

	condition:
		any of them
}

rule CobaltStrike_Resources_Xor_Bin__64bit_v3_12_to_v4_x : hardened
{
	meta:
		description = "Cobalt Strike's resource/xor64.bin signature for version 3.12 through 4.x"
		hash = "01dba8783768093b9a34a1ea2a20f72f29fd9f43183f3719873df5827a04b744"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		id = "5bb465ee-3bbd-5bfe-8b63-1f243de217bc"
		score = 80
		vetted_family = "cobalt"

	strings:
		$stub58 = {fc e8 ?? ?? ?? ?? [1-32] eb 33 5? 8b ?? 00 4? 83 ?? ?4 8b ?? 00 31 ?? 4? 83 ?? ?4 5? 8b ?? 00 31 ?? 89 ?? 00 31 ?? 4? 83 ?? ?4 83 ?? ?4 31 ?? 39 ?? 74 ?2 eb e7 5? fc 4? 83 ?? f0 ff}
		$stub59 = {fc e8 ?? ?? ?? ?? [1-32] eb 2e 5? 8b ??    48 83 c? ?4 8b ??    31 ?? 48 83 c? ?4 5? 8b ??    31 ?? 89 ??    31 ?? 48 83 c? ?4 83 e? ?4 31 ?? 39 ?? 74 ?2 eb e9 5?    48 83 ec ?8 ff e? e8 cd ff ff ff}
		$stub63 = {fc e8 ?? ?? ?? ?? [1-32] eb 32 5d 8b ?? ?? 48 83 c5 ?4 8b ?? ?? 31 ?? 48 83 c5 ?4 55 8b ?? ?? 31 ?? 89 ?? ?? 31 ?? 48 83 c5 ?4 83 e? ?4 31 ?? 39 ?? 74 ?2 eb e7 5?    48 83 ec ?8 ff e? e8 c9 ff ff ff}

	condition:
		any of them
}

