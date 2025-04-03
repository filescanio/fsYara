rule Ysoserial_Payload_MozillaRhino1 : hardened limited
{
	meta:
		description = "Ysoserial Payloads - file MozillaRhino1.bin"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/frohoff/ysoserial"
		date = "2017-02-04"
		hash1 = "0143fee12fea5118be6dcbb862d8ba639790b7505eac00a9f1028481f874baa8"
		id = "c269e032-b6ce-5faa-b3ce-a5304f3e9dab"

	strings:
		$s3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 79 73 6f 73 65 72 69 61 6c 2e 70 61 79 6c 6f 61 64 73 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		( uint16( 0 ) == 0xedac and filesize < 40KB and all of them )
}

rule Ysoserial_Payload_C3P0 : hardened limited
{
	meta:
		description = "Ysoserial Payloads - file C3P0.bin"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/frohoff/ysoserial"
		date = "2017-02-04"
		hash1 = "9932108d65e26d309bf7d97d389bc683e52e91eb68d0b1c8adfe318a4ec6e58b"
		id = "c269e032-b6ce-5faa-b3ce-a5304f3e9dab"

	strings:
		$x1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 65 78 70 6c 6f 69 74 70 70 70 70 77 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		( uint16( 0 ) == 0xedac and filesize < 3KB and all of them )
}

rule Ysoserial_Payload_Spring1 : hardened
{
	meta:
		description = "Ysoserial Payloads - file Spring1.bin"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/frohoff/ysoserial"
		date = "2017-02-04"
		hash1 = "bf9b5f35bc1556d277853b71da24faf23cf9964d77245018a0fdf3359f3b1703"
		hash2 = "9c0be107d93096066e82a5404eb6829b1daa6aaa1a7b43bcda3ddac567ce715a"
		hash3 = "8cfa85c16d37fb2c38f277f39cafb6f0c0bd7ee62b14d53ad1dd9cb3f4b25dd8"
		hash4 = "5c44482350f1c6d68749c8dec167660ca6427999c37bfebaa54f677345cdf63c"
		hash5 = "95f966f2e8c5d0bcdfb34e603e3c0b911fa31fc960308e41fcd4459e4e07b4d1"
		hash6 = "1da04d838141c64711d87695a4cdb4eedfd4a206cc80922a41cfc82df8e24187"
		hash7 = "adf895fa95526c9ce48ec33297156dd69c3dbcdd2432000e61b2dd34ffc167c7"
		id = "c269e032-b6ce-5faa-b3ce-a5304f3e9dab"

	strings:
		$x1 = {79 73 6f 73 65 72 69 61 6c 2f 50 77 6e 65 72}

	condition:
		1 of them
}

rule Ysoserial_Payload : hardened limited
{
	meta:
		description = "Ysoserial Payloads"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/frohoff/ysoserial"
		date = "2017-02-04"
		super_rule = 1
		hash1 = "9c0be107d93096066e82a5404eb6829b1daa6aaa1a7b43bcda3ddac567ce715a"
		hash2 = "adf895fa95526c9ce48ec33297156dd69c3dbcdd2432000e61b2dd34ffc167c7"
		hash3 = "1da04d838141c64711d87695a4cdb4eedfd4a206cc80922a41cfc82df8e24187"
		hash4 = "5c44482350f1c6d68749c8dec167660ca6427999c37bfebaa54f677345cdf63c"
		hash5 = "747ba6c6d88470e4d7c36107dfdff235f0ed492046c7ec8a8720d169f6d271f4"
		hash6 = "f0d2f1095da0164c03a0e801bd50f2f06793fb77938e53b14b57fd690d036929"
		hash7 = "5466d47363e11cd1852807b57d26a828728b9d5a0389214181b966bd0d8d7e56"
		hash8 = "95f966f2e8c5d0bcdfb34e603e3c0b911fa31fc960308e41fcd4459e4e07b4d1"
		hash9 = "1fea8b54bb92249203d68d5564a01599b42b46fc3a828fe0423616ee2a2f2d99"
		hash10 = "0143fee12fea5118be6dcbb862d8ba639790b7505eac00a9f1028481f874baa8"
		hash11 = "8cfa85c16d37fb2c38f277f39cafb6f0c0bd7ee62b14d53ad1dd9cb3f4b25dd8"
		hash12 = "bf9b5f35bc1556d277853b71da24faf23cf9964d77245018a0fdf3359f3b1703"
		hash13 = "f756c88763d48cb8d99e26b4773eb03814d0bd9bd467cc743ebb1479b2c4073e"
		id = "c269e032-b6ce-5faa-b3ce-a5304f3e9dab"

	strings:
		$x1 = {79 73 6f 73 65 72 69 61 6c 2f 70 61 79 6c 6f 61 64 73 2f}
		$s1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 53 74 75 62 54 72 61 6e 73 6c 65 74 50 61 79 6c 6f 61 64 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 50 77 6e 72 70 77 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		( uint16( 0 ) == 0xedac and filesize < 40KB and $x1 ) or ( all of them )
}

rule Ysoserial_Payload_3 : hardened limited
{
	meta:
		description = "Ysoserial Payloads - from files JavassistWeld1.bin, JBossInterceptors.bin"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/frohoff/ysoserial"
		date = "2017-02-04"
		super_rule = 1
		hash1 = "f0d2f1095da0164c03a0e801bd50f2f06793fb77938e53b14b57fd690d036929"
		hash2 = "5466d47363e11cd1852807b57d26a828728b9d5a0389214181b966bd0d8d7e56"
		id = "7fb67f48-66dc-57a4-9075-49b2277fa186"

	strings:
		$x1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 79 73 6f 73 65 72 69 61 6c 71 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 74 61 72 67 65 74 43 6c 61 73 73 49 6e 74 65 72 63 65 70 74 6f 72 4d 65 74 61 64 61 74 61 74 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 74 61 72 67 65 74 49 6e 73 74 61 6e 63 65 74 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 74 61 72 67 65 74 43 6c 61 73 73 4c (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s4 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 50 4f 53 54 5f 41 43 54 49 56 41 54 45 73 72 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s5 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 50 52 45 5f 44 45 53 54 52 4f 59 73 71 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		( uint16( 0 ) == 0xedac and filesize < 10KB and $x1 ) or ( all of them )
}

