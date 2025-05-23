rule APT_MAL_RU_WIN_Snake_Malware_May23_1 : hardened
{
	meta:
		author = "Matt Suiche (Magnet Forensics)"
		description = "Hunting Russian Intelligence Snake Malware"
		date = "2023-05-10"
		threat_name = "Windows.Malware.Snake"
		reference = "https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/JOINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF"
		score = 75
		scan_context = "memory"
		license = "MIT"
		id = "53d2de3c-350c-5090-84bb-b6cde16a80ad"

	strings:
		$a = { 25 73 23 31 }
		$b = { 25 73 23 32 }
		$c = { 25 73 23 33 }
		$d = { 25 73 23 34 }
		$e = { 2e 74 6d 70 }
		$g = { 2e 73 61 76 }
		$h = { 2e 75 70 64 }

	condition:
		all of them
}

rule APT_MAL_RU_Snake_Indicators_May23_1 : hardened limited
{
	meta:
		description = "Detects indicators found in Snake malware samples"
		author = "Florian Roth"
		reference = "https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/JOINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF"
		date = "2023-05-10"
		score = 85
		hash1 = "10b854d66240d9ee1ce4296d2f7857d2b1c6f062ca836d13d777930d678b3ca6"
		hash2 = "15ac5a61fb3e751045de2d7f5ff26c673f3883e326cd1b3a63889984a4fb2a8f"
		hash3 = "315ec991709eb45eccf724dfe31bccb7affcac7f8e8007e688ba8d02827205e0"
		hash4 = "417eb4fb9ada270af35562ff317807ac5ca9ee26181fe89990858f0944d3a6a7"
		hash5 = "48112970de6ea0f925f0657b30adcd0723df94afc98cfafdc991d70ad3602119"
		hash6 = "55ea557bcf4c143f20c616abe9075f7faafbf825aeef9ddb4f2b201acc44414b"
		hash7 = "6568bbeeb417e1111bf284e73152d90fe17e5497da7630ccddcbc666730dccef"
		hash8 = "81d620cb645006ffc9ac1b9d98a53aa286ae92b025bda075962079633f020482"
		hash9 = "888a3029b1b8b664eb1fc77dd511c4088a1e28ae5535a8683642bb3dca011d00"
		hash10 = "9027b4fef50b36289d630059425dc1137c88328329c3ea9dbc348dccd001adc0"
		hash11 = "9ac199572cab67433726976a0e9ba39d6feed1d567d6d230ebe3133df8dcb7fa"
		hash12 = "a64e5d872421991226ee040b4cd49a89ca681bdef4c10c4798b6c7b5c832c6df"
		hash13 = "b5d2da5eb57b5ab26edb927469552629f3cf43bbce2b1a128f6daac7cf57f6f7"
		hash14 = "bc15de1d1c6c62c0bf856e0368adabc4941e7b687a969912494c173233e6d28d"
		hash15 = "bdf94311313c39a3413464f623bd75a3db2eb05cc01090acd6dcd462a605eb4a"
		hash16 = "e4311892ae00bf8148a94fa900fc8e2c279a2acd3b4b4b4c3d0c99dd1d32353c"
		hash17 = "ed74288b367a93c6b47343bc696e751b9c465761ce9c4208901726baa758b234"
		hash18 = "ef1f1c7692b92a730f76b6227643b2d02a6e353af6e930166e3b48e3903e4ffd"
		hash19 = "f5e982b76af7f447742753f0b57eec3d7dd2e3c8e5506c35d4cf6c860b829f45"
		id = "0d4fa8a7-447c-5905-bab9-b63de6209036"

	strings:
		$s1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 5c 5c 2e 5c 25 73 5c 5c (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 72 65 61 64 5f 70 65 65 72 5f 6e 66 6f (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 72 63 76 5f 62 75 66 3d 25 64 25 63 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s4 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 25 73 3a 20 28 30 78 25 30 38 78 29 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s5 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 6e 6f 5f 69 6d 70 65 72 73 6f 6e 61 74 65 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		all of them
}

