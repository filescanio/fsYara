rule HttpBrowser_RAT_dropper_Gen1 : hardened
{
	meta:
		description = "Threat Group 3390 APT Sample - HttpBrowser RAT Dropper"
		author = "Florian Roth"
		reference = "http://snip.ly/giNB"
		date = "2015-08-06"
		score = 70
		hash1 = "808de72f1eae29e3c1b2c32be1b84c5064865a235866edf5e790d2a7ba709907"
		hash2 = "f6f966d605c5e79de462a65df437ddfca0ad4eb5faba94fc875aba51a4b894a7"
		hash3 = "f424965a35477d822bbadb821125995616dc980d3d4f94a68c87d0cd9b291df9"
		hash4 = "01441546fbd20487cb2525a0e34e635eff2abe5c3afc131c7182113220f02753"
		hash5 = "8cd8159f6e4689f572e2087394452e80e62297af02ca55fe221fe5d7570ad47b"
		hash6 = "10de38419c9a02b80ab7bf2f1f1f15f57dbb0fbc9df14b9171dc93879c5a0c53"
		hash7 = "c2fa67e970d00279cec341f71577953d49e10fe497dae4f298c2e9abdd3a48cc"

	strings:
		$x1 = {31 30 30 31 3d 63 6d 64 2e 65 78 65}
		$x2 = {31 30 30 33 3d 53 68 65 6c 6c 45 78 65 63 75 74 65 41}
		$x3 = {31 30 30 32 3d 2f 63 20 64 65 6c 20 2f 71 20 25 73}
		$x4 = {31 30 30 34 3d 53 65 74 54 68 72 65 61 64 50 72 69 6f 72 69 74 79}
		$op0 = { e8 71 11 00 00 83 c4 10 ff 4d e4 8b f0 78 07 8b }
		$op1 = { e8 85 34 00 00 59 59 8b 86 b4 }
		$op2 = { 8b 45 0c 83 38 00 0f 84 97 }
		$op3 = { 8b 45 0c 83 38 00 0f 84 98 }
		$op4 = { 89 7e 0c ff 15 a0 50 40 00 59 8b d8 6a 20 59 8d }
		$op5 = { 56 8d 85 cd fc ff ff 53 50 88 9d cc fc ff ff e8 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 400KB and all of ( $x* ) and 1 of ( $op* )
}

rule HttpBrowser_RAT_Sample1 : hardened
{
	meta:
		description = "Threat Group 3390 APT Sample - HttpBrowser RAT Sample update.hancominc.com"
		author = "Florian Roth"
		reference = "http://snip.ly/giNB"
		date = "2015-08-06"
		score = 80
		hash1 = "be334d1f8fa65a723af65200a166c2bbdb06690c8b30fafe772600e4662fc68b"
		hash2 = "1052ad7f4d49542e4da07fa8ea59c15c40bc09a4d726fad023daafdf05866ebb"

	strings:
		$s0 = {75 00 70 00 64 00 61 00 74 00 65 00 2e 00 68 00 61 00 6e 00 63 00 6f 00 6d 00 69 00 6e 00 63 00 2e 00 63 00 6f 00 6d 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 100KB and $s0
}

rule HttpBrowser_RAT_Sample2 : hardened
{
	meta:
		description = "Threat Group 3390 APT Sample - HttpBrowser RAT Sample"
		author = "Florian Roth"
		reference = "http://snip.ly/giNB"
		date = "2015-08-06"
		score = 80
		hash1 = "c57c5a2c322af2835ae136b75283eaaeeaa6aa911340470182a9983ae47b8992"

	strings:
		$s0 = {6e 00 4b 00 45 00 52 00 4e 00 45 00 4c 00 33 00 32 00 2e 00 44 00 4c 00 4c 00}
		$s1 = {57 00 55 00 53 00 45 00 52 00 33 00 32 00 2e 00 44 00 4c 00 4c 00}
		$s2 = {6d 00 73 00 63 00 6f 00 72 00 65 00 65 00 2e 00 64 00 6c 00 6c 00}
		$s3 = {56 50 44 4e 5f 4c 55 2e 65 78 65 55 54}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 250KB and all of them
}

rule HttpBrowser_RAT_Gen : hardened
{
	meta:
		description = "Threat Group 3390 APT Sample - HttpBrowser RAT Generic"
		author = "Florian Roth"
		reference = "http://snip.ly/giNB"
		date = "2015-08-06"
		score = 90
		hash1 = "0299493ccb175d452866f5e21d023d3e92cd8d28452517d1d19c0f05f2c5ca27"
		hash2 = "065d055a90da59b4bdc88b97e537d6489602cb5dc894c5c16aff94d05c09abc7"
		hash3 = "05c7291db880f94c675eea336ecd66338bd0b1d49ad239cc17f9df08106e6684"
		hash4 = "07133f291fe022cd14346cd1f0a649aa2704ec9ccadfab809ca9c48b91a7d81b"
		hash5 = "0f8893e87ddec3d98e39a57f7cd530c28e36d596ea0a1d9d1e993dc2cae0a64d"
		hash6 = "108e6633744da6efe773eb78bd0ac804920add81c3dde4b26e953056ac1b26c5"
		hash7 = "1052ad7f4d49542e4da07fa8ea59c15c40bc09a4d726fad023daafdf05866ebb"
		hash8 = "1277ede988438d4168bb5b135135dd3b9ae7d9badcdf1421132ca4692dd18386"
		hash9 = "19be90c152f7a174835fd05a0b6f722e29c648969579ed7587ae036679e66a7b"
		hash10 = "1e7133bf5a9fe5e462321aafc2b7770b8e4183a66c7fef14364a0c3f698a29af"
		hash11 = "2264e5e8fcbdcb29027798b200939ecd8d1d3ad1ef0aef2b8ce7687103a3c113"
		hash12 = "2a1bdeb0a021fb0bdbb328bd4b65167d1f954c871fc33359cb5ea472bad6e13e"
		hash13 = "259a2e0508832d0cf3f4f5d9e9e1adde17102d2804541a9587a9a4b6f6f86669"
		hash14 = "240d9ce148091e72d8f501dbfbc7963997d5c2e881b4da59a62975ddcbb77ca2"
		hash15 = "211a1b195cf2cc70a2caf8f1aafb8426eb0e4bae955e85266490b12b5322aa16"
		hash16 = "2d25c6868c16085c77c58829d538b8f3dbec67485f79a059f24e0dce1e804438"
		hash17 = "2d932d764dd9b91166361d8c023d64a4480b5b587a6087b0ce3d2ac92ead8a7d"
		hash18 = "3556722d9aa37beadfa6ba248a66576f767e04b09b239d3fb0479fa93e0ba3fd"
		hash19 = "365e1d4180e93d7b87ba28ce4369312cbae191151ac23ff4a35f45440cb9be48"
		hash20 = "36c49f18ce3c205152eef82887eb3070e9b111d35a42b534b2fb2ee535b543c0"
		hash21 = "3eeb1fd1f0d8ab33f34183893c7346ddbbf3c19b94ba3602d377fa2e84aaad81"
		hash22 = "3fa8d13b337671323e7fe8b882763ec29b6786c528fa37da773d95a057a69d9a"

	strings:
		$s0 = {25 00 64 00 7c 00 25 00 73 00 7c 00 25 00 30 00 34 00 64 00 2f 00 25 00 30 00 32 00 64 00 2f 00 25 00 30 00 32 00 64 00 20 00 25 00 30 00 32 00 64 00 3a 00 25 00 30 00 32 00 64 00 3a 00 25 00 30 00 32 00 64 00 7c 00 25 00 6c 00 64 00 7c 00 25 00 64 00}
		$s1 = {48 00 74 00 74 00 70 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 2f 00 31 00 2e 00 30 00}
		$s2 = {73 65 74 20 63 6d 64 20 3a 20 25 73}
		$s3 = {5c 00 63 00 6f 00 6e 00 66 00 69 00 67 00 2e 00 69 00 6e 00 69 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 45KB and filesize > 20KB and all of them
}

rule PlugX_NvSmartMax_Gen : hardened
{
	meta:
		description = "Threat Group 3390 APT Sample - PlugX NvSmartMax Generic"
		author = "Florian Roth"
		reference = "http://snip.ly/giNB"
		date = "2015-08-06"
		score = 70
		hash1 = "718fc72942b9b706488575c0296017971170463f6f40fa19b08fc84b79bf0cef"
		hash2 = "1c0379481d17fc80b3330f148f1b87ff613cfd2a6601d97920a0bcd808c718d0"
		hash3 = "555952aa5bcca4fa5ad5a7269fece99b1a04816d104ecd8aefabaa1435f65fa5"
		hash4 = "71f7a9da99b5e3c9520bc2cc73e520598d469be6539b3c243fb435fe02e44338"
		hash5 = "65bbf0bd8c6e1ccdb60cf646d7084e1452cb111d97d21d6e8117b1944f3dc71e"

	strings:
		$s0 = {4e 76 53 6d 61 72 74 4d 61 78 2e 64 6c 6c}
		$s1 = {4e 76 53 6d 61 72 74 4d 61 78 2e 64 6c 6c 2e 75 72 6c}
		$s2 = {4e 76 2e 65 78 65}
		$s4 = {43 72 79 70 74 50 72 6f 74 65 63 74 4d 65 6d 6f 72 79 20 66 61 69 6c 65 64}
		$s5 = {43 72 79 70 74 55 6e 70 72 6f 74 65 63 74 4d 65 6d 6f 72 79 20 66 61 69 6c 65 64}
		$s7 = {72 00 25 00 2e 00 2a 00 73 00 28 00 25 00 64 00 29 00 25 00 73 00}
		$s8 = {20 00 25 00 73 00 20 00 43 00 52 00 43 00 20 00}
		$op0 = { c6 05 26 49 42 00 01 eb 4a 8d 85 00 f8 ff ff 50 }
		$op1 = { 8d 85 c8 fe ff ff 50 8d 45 c8 50 c6 45 47 00 e8 }
		$op2 = { e8 e6 65 00 00 50 68 10 43 41 00 e8 56 84 00 00 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 800KB and all of ( $s* ) and 1 of ( $op* )
}

rule HttpBrowser_RAT_dropper_Gen2 : hardened
{
	meta:
		description = "Threat Group 3390 APT Sample - HttpBrowser RAT Dropper"
		author = "Florian Roth"
		reference = "http://snip.ly/giNB"
		date = "2015-08-06"
		score = 70
		hash1 = "c57c5a2c322af2835ae136b75283eaaeeaa6aa911340470182a9983ae47b8992"
		hash2 = "dfa984174268a9f364d856fd47cfaca75804640f849624d69d81fcaca2b57166"

	strings:
		$s1 = {6e 61 76 6c 75 2e 64 6c 6c 2e 75 72 6c 55 54}
		$s2 = {56 50 44 4e 5f 4c 55 2e 65 78 65 55 54}
		$s3 = {70 6e 69 70 63 6e 2e 64 6c 6c 55 54}
		$s4 = {5c 73 73 6f 6e 73 76 72 2e 65 78 65}
		$s5 = {2f 63 20 64 65 6c 20 2f 71 20 25 73}
		$s6 = {5c 73 65 74 75 70 2e 65 78 65}
		$s7 = {6d 73 69 2e 64 6c 6c 55 54}
		$op0 = { 8b 45 0c 83 38 00 0f 84 98 }
		$op1 = { e8 dd 07 00 00 ff 35 d8 fb 40 00 8b 35 7c a0 40 }
		$op2 = { 83 fb 08 75 2c 8b 0d f8 af 40 00 89 4d dc 8b 0d }
		$op3 = { c7 43 18 8c 69 40 00 e9 da 01 00 00 83 7d f0 00 }
		$op4 = { 6a 01 e9 7c f8 ff ff bf 1a 40 00 96 1b 40 00 01 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 400KB and 3 of ( $s* ) and 1 of ( $op* )
}

rule ThreatGroup3390_Strings : hardened
{
	meta:
		description = "Threat Group 3390 APT - Strings"
		author = "Florian Roth"
		reference = "http://snip.ly/giNB"
		date = "2015-08-06"
		score = 60

	strings:
		$s1 = {22 63 6d 64 22 20 2f 63 20 63 64 20 2f 64 20 22 63 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c 5c 22 26 63 6f 70 79}
		$s2 = {73 76 63 68 6f 73 74 2e 65 78 65 20 61 20 2d 6b 20 2d 72 20 2d 73 20 2d 6d 35 20 2d 76 31 30 32 34 30 30 30 20 2d 70 61 64 6d 69 6e 2d 77 69 6e 64 6f 77 73 32 30 31 34}
		$s3 = {72 65 6e 20 2a 2e 72 61 72 20 2a 2e 7a 69 70}
		$s4 = {63 3a 5c 74 65 6d 70 5c 69 70 63 61 6e 2e 65 78 65}
		$s5 = {3c 25 65 76 61 6c 28 52 65 71 75 65 73 74 2e 49 74 65 6d 28 22 61 64 6d 69 6e 2d 6e 61 2d 67 6f 6f 67 6c 65 31 32 33 21 40 23}

	condition:
		1 of them and filesize < 30KB
}

rule ThreatGroup3390_C2 : hardened
{
	meta:
		description = "Threat Group 3390 APT - C2 Server"
		author = "Florian Roth"
		reference = "http://snip.ly/giNB"
		date = "2015-08-06"
		score = 60

	strings:
		$s1 = {61 70 69 2e 61 70 69 67 6d 61 69 6c 2e 63 6f 6d}
		$s2 = {61 70 69 67 6d 61 69 6c 2e 63 6f 6d}
		$s3 = {62 61 63 6b 75 70 2e 64 61 72 6b 68 65 72 6f 2e 6f 72 67}
		$s4 = {62 65 6c 2e 75 70 64 61 74 61 77 69 6e 64 6f 77 73 2e 63 6f 6d}
		$s5 = {62 69 6e 61 72 79 2e 75 70 64 61 74 65 2d 6f 6e 6c 69 6e 65 73 2e 6f 72 67}
		$s6 = {62 6c 61 63 6b 63 6d 64 2e 63 6f 6d}
		$s7 = {63 61 73 74 6c 65 2e 62 6c 61 63 6b 63 6d 64 2e 63 6f 6d}
		$s8 = {63 74 63 62 2e 62 6c 61 63 6b 63 6d 64 2e 63 6f 6d}
		$s9 = {64 61 72 6b 68 65 72 6f 2e 6f 72 67}
		$s10 = {64 61 76 2e 6c 6f 63 61 6c 2d 74 65 73 74 2e 63 6f 6d}
		$s11 = {74 65 73 74 2e 6c 6f 63 61 6c 2d 74 65 73 74 2e 63 6f 6d}
		$s12 = {64 65 76 2e 6c 6f 63 61 6c 2d 74 65 73 74 2e 63 6f 6d}
		$s13 = {6f 63 65 61 6e 2e 6c 6f 63 61 6c 2d 74 65 73 74 2e 63 6f 6d}
		$s14 = {67 61 2e 62 6c 61 63 6b 63 6d 64 2e 63 6f 6d}
		$s15 = {68 65 6c 70 64 65 73 6b 2e 62 6c 61 63 6b 63 6d 64 2e 63 6f 6d}
		$s16 = {68 65 6c 70 64 65 73 6b 2e 63 73 63 2d 6e 61 2e 63 6f 6d}
		$s17 = {68 65 6c 70 64 65 73 6b 2e 68 6f 74 6d 61 69 6c 2d 6f 6e 6c 69 6e 65 73 2e 63 6f 6d}
		$s18 = {68 65 6c 70 64 65 73 6b 2e 6c 6e 69 70 2e 6f 72 67}
		$s19 = {68 6f 74 6d 61 69 6c 2d 6f 6e 6c 69 6e 65 73 2e 63 6f 6d}
		$s20 = {6a 6f 62 73 2e 68 6f 74 6d 61 69 6c 2d 6f 6e 6c 69 6e 65 73 2e 63 6f 6d}
		$s21 = {6a 75 73 74 75 66 6f 67 61 6d 65 2e 63 6f 6d}
		$s22 = {6c 6e 69 70 2e 6f 72 67}
		$s23 = {6c 6f 63 61 6c 2d 74 65 73 74 2e 63 6f 6d}
		$s24 = {6c 6f 67 69 6e 2e 68 61 6e 73 6f 66 74 75 70 64 61 74 65 2e 63 6f 6d}
		$s25 = {6c 6f 6e 67 2e 75 70 64 61 74 65 2d 6f 6e 6c 69 6e 65 73 2e 6f 72 67}
		$s26 = {6c 6f 6e 67 6c 6f 6e 67 2e 75 70 64 61 74 65 2d 6f 6e 6c 69 6e 65 73 2e 6f 72 67}
		$s27 = {6c 6f 6e 67 73 68 61 64 6f 77 2e 64 79 6e 64 6e 73 2e 6f 72 67}
		$s28 = {6c 6f 6e 67 73 68 61 64 6f 77 2e 75 70 64 61 74 65 2d 6f 6e 6c 69 6e 65 73 2e 6f 72 67}
		$s29 = {6c 6f 6e 67 79 6b 63 61 69 2e 75 70 64 61 74 65 2d 6f 6e 6c 69 6e 65 73 2e 6f 72 67}
		$s30 = {6c 6f 73 74 73 65 6c 66 2e 75 70 64 61 74 65 2d 6f 6e 6c 69 6e 65 73 2e 6f 72 67}
		$s31 = {6d 61 63 2e 6e 61 76 79 64 6f 63 75 6d 65 6e 74 2e 63 6f 6d}
		$s32 = {6d 61 69 6c 2e 63 73 63 2d 6e 61 2e 63 6f 6d}
		$s33 = {6d 61 6e 74 65 63 68 2e 75 70 64 61 74 61 77 69 6e 64 6f 77 73 2e 63 6f 6d}
		$s34 = {6d 69 63 72 30 73 6f 66 74 2e 6f 72 67}
		$s35 = {6d 69 63 72 6f 73 6f 66 74 2d 6f 75 74 6c 6f 6f 6b 2e 6f 72 67}
		$s36 = {6d 74 63 2e 6e 61 76 79 64 6f 63 75 6d 65 6e 74 2e 63 6f 6d}
		$s37 = {6e 61 76 79 64 6f 63 75 6d 65 6e 74 2e 63 6f 6d}
		$s38 = {6d 74 63 2e 75 70 64 61 74 65 2d 6f 6e 6c 69 6e 65 73 2e 6f 72 67}
		$s39 = {6e 65 77 73 2e 68 6f 74 6d 61 69 6c 2d 6f 6e 6c 69 6e 65 73 2e 63 6f 6d}
		$s40 = {6f 61 63 2e 33 33 32 32 2e 6f 72 67}
		$s41 = {6f 63 65 61 6e 2e 61 70 69 67 6d 61 69 6c 2e 63 6f 6d}
		$s42 = {70 63 68 6f 6d 65 73 65 72 76 65 72 2e 63 6f 6d}
		$s43 = {72 65 67 69 73 74 72 65 2e 6f 72 67 61 6e 69 63 63 72 61 70 2e 63 6f 6d}
		$s44 = {73 65 63 75 72 69 74 79 2e 70 6f 6d 73 79 73 2e 6f 72 67}
		$s45 = {73 65 72 76 69 63 65 73 2e 64 61 72 6b 68 65 72 6f 2e 6f 72 67}
		$s46 = {73 67 6c 2e 75 70 64 61 74 61 77 69 6e 64 6f 77 73 2e 63 6f 6d}
		$s47 = {73 68 61 64 6f 77 2e 75 70 64 61 74 65 2d 6f 6e 6c 69 6e 65 73 2e 6f 72 67}
		$s48 = {73 6f 6e 6f 63 6f 2e 62 6c 61 63 6b 63 6d 64 2e 63 6f 6d}
		$s49 = {74 65 73 74 2e 6c 6f 67 6d 61 73 74 72 65 2e 63 6f 6d}
		$s50 = {75 70 2e 67 74 61 6c 6b 6c 69 74 65 2e 63 6f 6d}
		$s51 = {75 70 64 61 74 61 77 69 6e 64 6f 77 73 2e 63 6f 6d}
		$s52 = {75 70 64 61 74 65 2d 6f 6e 6c 69 6e 65 73 2e 6f 72 67}
		$s53 = {75 70 64 61 74 65 2e 64 65 65 70 73 6f 66 74 75 70 64 61 74 65 2e 63 6f 6d}
		$s54 = {75 70 64 61 74 65 2e 68 61 6e 63 6f 6d 69 6e 63 2e 63 6f 6d}
		$s55 = {75 70 64 61 74 65 2e 6d 69 63 72 30 73 6f 66 74 2e 6f 72 67}
		$s56 = {75 70 64 61 74 65 2e 70 63 68 6f 6d 65 73 65 72 76 65 72 2e 63 6f 6d}
		$s57 = {75 72 73 2e 62 6c 61 63 6b 63 6d 64 2e 63 6f 6d}
		$s58 = {77 61 6e 67 2e 64 61 72 6b 68 65 72 6f 2e 6f 72 67}
		$s59 = {77 65 62 73 2e 6c 6f 63 61 6c 2d 74 65 73 74 2e 63 6f 6d}
		$s60 = {77 6f 72 64 2e 61 70 69 67 6d 61 69 6c 2e 63 6f 6d}
		$s61 = {77 6f 72 64 70 72 65 73 73 2e 62 6c 61 63 6b 63 6d 64 2e 63 6f 6d}
		$s62 = {77 6f 72 6b 69 6e 67 2e 62 6c 61 63 6b 63 6d 64 2e 63 6f 6d}
		$s63 = {77 6f 72 6b 69 6e 67 2e 64 61 72 6b 68 65 72 6f 2e 6f 72 67}
		$s64 = {77 6f 72 6b 69 6e 67 2e 68 6f 74 6d 61 69 6c 2d 6f 6e 6c 69 6e 65 73 2e 63 6f 6d}
		$s65 = {77 77 77 2e 74 72 65 6e 64 6d 69 63 72 6f 2d 75 70 64 61 74 65 2e 6f 72 67}
		$s66 = {77 77 77 2e 75 70 64 61 74 65 2d 6f 6e 6c 69 6e 65 73 2e 6f 72 67}
		$s67 = {78 2e 61 70 69 67 6d 61 69 6c 2e 63 6f 6d}
		$s68 = {79 6b 63 61 69 2e 75 70 64 61 74 65 2d 6f 6e 6c 69 6e 65 73 2e 6f 72 67}
		$s69 = {79 6b 63 61 69 6c 6f 73 74 73 65 6c 66 2e 64 79 6e 64 6e 73 2d 66 72 65 65 2e 63 6f 6d}
		$s70 = {79 6b 63 61 69 6e 6f 62 6f 64 79 2e 64 79 6e 64 6e 73 2e 6f 72 67}
		$s71 = {7a 6a 2e 62 6c 61 63 6b 63 6d 64 2e 63 6f 6d}
		$s72 = {6c 61 78 6e 65 73 73 2d 6c 61 62 2e 63 6f 6d}
		$s73 = {67 6f 6f 67 6c 65 2d 61 6e 61 31 79 74 69 63 73 2e 63 6f 6d}
		$s74 = {77 77 77 2e 67 6f 6f 67 6c 65 2d 61 6e 61 31 79 74 69 63 73 2e 63 6f 6d}
		$s75 = {66 74 70 2e 67 6f 6f 67 6c 65 2d 61 6e 61 31 79 74 69 63 73 2e 63 6f 6d}
		$s76 = {68 6f 74 6d 61 69 6c 63 6f 6e 74 61 63 74 2e 6e 65 74}
		$s77 = {32 30 38 2e 31 31 35 2e 32 34 32 2e 33 36}
		$s78 = {32 30 38 2e 31 31 35 2e 32 34 32 2e 33 37}
		$s79 = {32 30 38 2e 31 31 35 2e 32 34 32 2e 33 38}
		$s80 = {36 36 2e 36 33 2e 31 37 38 2e 31 34 32}
		$s81 = {37 32 2e 31 31 2e 31 34 38 2e 32 32 30}
		$s82 = {37 32 2e 31 31 2e 31 34 31 2e 31 33 33}
		$s83 = {37 34 2e 36 33 2e 31 39 35 2e 32 33 36}
		$s84 = {37 34 2e 36 33 2e 31 39 35 2e 32 33 36}
		$s85 = {37 34 2e 36 33 2e 31 39 35 2e 32 33 37}
		$s86 = {37 34 2e 36 33 2e 31 39 35 2e 32 33 38}
		$s87 = {31 30 33 2e 32 34 2e 30 2e 31 34 32}
		$s88 = {31 30 33 2e 32 34 2e 31 2e 35 34}
		$s89 = {31 30 36 2e 31 38 37 2e 34 35 2e 31 36 32}
		$s90 = {31 39 32 2e 31 35 31 2e 32 33 36 2e 31 33 38}
		$s91 = {31 39 32 2e 31 36 31 2e 36 31 2e 31 39}
		$s92 = {31 39 32 2e 31 36 31 2e 36 31 2e 32 30}
		$s93 = {31 39 32 2e 31 36 31 2e 36 31 2e 32 32}
		$s94 = {31 30 33 2e 32 34 2e 31 2e 35 34}
		$s95 = {36 37 2e 32 31 35 2e 32 33 32 2e 31 37 39}
		$s96 = {39 36 2e 34 34 2e 31 37 37 2e 31 39 35}
		$s97 = {34 39 2e 31 34 33 2e 31 39 32 2e 32 32 31}
		$s98 = {36 37 2e 32 31 35 2e 32 33 32 2e 31 38 31}
		$s99 = {36 37 2e 32 31 35 2e 32 33 32 2e 31 38 32}
		$s100 = {39 36 2e 34 34 2e 31 38 32 2e 32 34 33}
		$s101 = {39 36 2e 34 34 2e 31 38 32 2e 32 34 35}
		$s102 = {39 36 2e 34 34 2e 31 38 32 2e 32 34 36}
		$s103 = {34 39 2e 31 34 33 2e 32 30 35 2e 33 30}
		$s104 = {77 6f 72 6b 69 6e 67 5f 73 75 63 63 65 73 73 40 31 36 33 2e 63 6f 6d}
		$s105 = {79 6b 63 61 69 68 79 6c 40 31 36 33 2e 63 6f 6d}
		$s106 = {77 6f 72 6b 69 6e 67 5f 73 75 63 63 65 73 73 40 31 36 33 2e 63 6f 6d}
		$s107 = {79 75 6d 69 6e 67 40 79 69 6e 73 69 62 61 6f 68 75 2e 61 6c 69 79 75 6e 2e 63 6f 6d}

	condition:
		uint16( 0 ) == 0x5a4d and 1 of them
}

