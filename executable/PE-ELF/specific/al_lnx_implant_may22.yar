rule MAL_LNX_RedMenshen_BPFDoor_May23_1 : hardened
{
	meta:
		description = "Detects BPFDoor malware"
		author = "Florian Roth"
		reference = "https://www.deepinstinct.com/blog/bpfdoor-malware-evolves-stealthy-sniffing-backdoor-ups-its-game"
		date = "2023-05-11"
		score = 80
		hash1 = "afa8a32ec29a31f152ba20a30eb483520fe50f2dce6c9aa9135d88f7c9c511d7"
		id = "25df4dba-ec6e-5999-b6be-56fe933cb0d0"

	strings:
		$x1 = {5b 2d 5d 20 45 78 65 63 75 74 65 20 63 6f 6d 6d 61 6e 64 20 66 61 69 6c 65 64}
		$x2 = {2f 76 61 72 2f 72 75 6e 2f 69 6e 69 74 64 2e 6c 6f 63 6b}
		$xc1 = { 2F 00 3E 3E 00 65 78 69 74 00 72 00 }
		$sc1 = { 9F CD 30 44 }
		$sc2 = { 66 27 14 5E }
		$sa1 = {54 4c 53 2d 43 48 41 43 48 41 32 30 2d 50 4f 4c 59 31 33 30 35 2d 53 48 41 32 35 36}
		$sop1 = { 48 83 c0 01 4c 39 f8 75 ea 4c 89 7c 24 68 48 69 c3 d0 00 00 00 48 8b 5c 24 50 48 8b 54 24 78 48 c7 44 24 38 00 00 00 00 }
		$sop2 = { 48 89 de f3 a5 89 03 8b 44 24 2c 39 44 24 28 44 89 4b 04 48 89 53 10 0f 95 c0 }
		$sop3 = { 49 d3 cd 4d 31 cd b1 29 49 89 e9 49 d3 c8 4d 31 c5 4c 03 68 10 48 89 f9 }

	condition:
		uint16( 0 ) == 0x457f and filesize < 900KB and ( ( 1 of ( $x* ) and 1 of ( $s* ) ) or 4 of them or ( all of ( $sc* ) and $sc1 in ( @sc2 [ 1 ] - 50 .. @sc2 [ 1 ] + 50 ) ) ) or ( 2 of ( $x* ) or 5 of them )
}

rule APT_MAL_LNX_RedMenshen_BPFDoor_Controller_May22_1 : hardened
{
	meta:
		description = "Detects unknown Linux implants (uploads from KR and MO)"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://doublepulsar.com/bpfdoor-an-active-chinese-global-surveillance-tool-54b078f1a896"
		date = "2022-05-05"
		score = 90
		hash1 = "07ecb1f2d9ffbd20a46cd36cd06b022db3cc8e45b1ecab62cd11f9ca7a26ab6d"
		hash2 = "4c5cf8f977fc7c368a8e095700a44be36c8332462c0b1e41bff03238b2bf2a2d"
		hash3 = "599ae527f10ddb4625687748b7d3734ee51673b664f2e5d0346e64f85e185683"
		hash4 = "5b2a079690efb5f4e0944353dd883303ffd6bab4aad1f0c88b49a76ddcb28ee9"
		hash5 = "5faab159397964e630c4156f8852bcc6ee46df1cdd8be2a8d3f3d8e5980f3bb3"
		hash6 = "93f4262fce8c6b4f8e239c35a0679fbbbb722141b95a5f2af53a2bcafe4edd1c"
		hash7 = "97a546c7d08ad34dfab74c9c8a96986c54768c592a8dae521ddcf612a84fb8cc"
		hash8 = "c796fc66b655f6107eacbe78a37f0e8a2926f01fecebd9e68a66f0e261f91276"
		hash9 = "f8a5e735d6e79eb587954a371515a82a15883cf2eda9d7ddb8938b86e714ea27"
		hash10 = "fd1b20ee5bd429046d3c04e9c675c41e9095bea70e0329bd32d7edd17ebaf68a"
		id = "1438c3bf-3c42-59d5-9f3f-2d72bdaaac42"

	strings:
		$s1 = {5b 2d 5d 20 43 6f 6e 6e 65 63 74 20 66 61 69 6c 65 64 2e}
		$s2 = {65 78 70 6f 72 74 20 4d 59 53 51 4c 5f 48 49 53 54 46 49 4c 45 3d}
		$s3 = {75 64 70 63 6d 64}
		$s4 = {67 65 74 73 68 65 6c 6c}
		$op1 = { e8 ?? ff ff ff 80 45 ee 01 0f b6 45 ee 3b 45 d4 7c 04 c6 45 ee 00 80 45 ff 01 80 7d ff 00 }
		$op2 = { 55 48 89 e5 48 83 ec 30 89 7d ec 48 89 75 e0 89 55 dc 83 7d dc 00 75 0? }
		$op3 = { e8 a? fe ff ff 0f b6 45 f6 48 03 45 e8 0f b6 10 0f b6 45 f7 48 03 45 e8 0f b6 00 8d 04 02 }
		$op4 = { c6 80 01 01 00 00 00 48 8b 45 c8 0f b6 90 01 01 00 00 48 8b 45 c8 88 90 00 01 00 00 c6 45 ef 00 0f b6 45 ef 88 45 ee }

	condition:
		uint16( 0 ) == 0x457f and filesize < 80KB and 2 of them or 5 of them
}

rule APT_MAL_LNX_RedMenshen_BPFDoor_Controller_May22_2 : hardened
{
	meta:
		description = "Detects BPFDoor implants used by Chinese actor Red Menshen"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://doublepulsar.com/bpfdoor-an-active-chinese-global-surveillance-tool-54b078f1a896"
		date = "2022-05-07"
		score = 85
		hash1 = "76bf736b25d5c9aaf6a84edd4e615796fffc338a893b49c120c0b4941ce37925"
		hash2 = "96e906128095dead57fdc9ce8688bb889166b67c9a1b8fdb93d7cff7f3836bb9"
		hash3 = "c80bd1c4a796b4d3944a097e96f384c85687daeedcdcf05cc885c8c9b279b09c"
		hash4 = "f47de978da1dbfc5e0f195745e3368d3ceef034e964817c66ba01396a1953d72"
		id = "d5c3d530-ed6f-563e-a3b0-55d4c82e4899"

	strings:
		$opx1 = { 48 83 c0 0c 48 8b 95 e8 fe ff ff 48 83 c2 0c 8b 0a 8b 55 f0 01 ca 89 10 c9 }
		$opx2 = { 48 01 45 e0 83 45 f4 01 8b 45 f4 3b 45 dc 7c cd c7 45 f4 00 00 00 00 eb 2? 48 8b 05 ?? ?? 20 00 }
		$op1 = { 48 8d 14 c5 00 00 00 00 48 8b 45 d0 48 01 d0 48 8b 00 48 89 c7 e8 ?? ?? ff ff 48 83 c0 01 48 01 45 e0 }
		$op2 = { 89 c2 8b 85 fc fe ff ff 01 c2 8b 45 f4 01 d0 2d 7b cf 10 2b 89 45 f4 c1 4d f4 10 }
		$op3 = { e8 ?? d? ff ff 8b 45 f0 eb 12 8b 85 3c ff ff ff 89 c7 e8 ?? d? ff ff b8 ff ff ff ff c9 }

	condition:
		uint16( 0 ) == 0x457f and filesize < 100KB and 2 of ( $opx* ) or 4 of them
}

rule APT_MAL_LNX_RedMenshen_BPFDoor_Controller_May22_3 : hardened
{
	meta:
		description = "Detects BPFDoor implants used by Chinese actor Red Menshen"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://doublepulsar.com/bpfdoor-an-active-chinese-global-surveillance-tool-54b078f1a896"
		date = "2022-05-08"
		score = 85
		hash1 = "144526d30ae747982079d5d340d1ff116a7963aba2e3ed589e7ebc297ba0c1b3"
		hash2 = "fa0defdabd9fd43fe2ef1ec33574ea1af1290bd3d763fdb2bed443f2bd996d73"
		id = "91c2153a-a6e0-529e-852c-61f799838798"

	strings:
		$s1 = {68 61 6c 64 2d 61 64 64 6f 6e 2d 61 63 70 69 3a 20 6c 69 73 74 65 6e 69 6e 67 20 6f 6e 20 61 63 70 69 20 6b 65 72 6e 65 6c 20 69 6e 74 65 72 66 61 63 65 20 2f 70 72 6f 63 2f 61 63 70 69 2f 65 76 65 6e 74}
		$s2 = {2f 73 62 69 6e 2f 6d 69 6e 67 65 74 74 79 20 2f 64 65 76}
		$s3 = {70 69 63 6b 75 70 20 2d 6c 20 2d 74 20 66 69 66 6f 20 2d 75}

	condition:
		uint16( 0 ) == 0x457f and filesize < 200KB and 2 of them or all of them
}

rule APT_MAL_LNX_RedMenshen_BPFDoor_Controller_Generic_May22_1 : hardened
{
	meta:
		description = "Detects BPFDoor malware"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://doublepulsar.com/bpfdoor-an-active-chinese-global-surveillance-tool-54b078f1a896"
		date = "2022-05-09"
		score = 90
		hash1 = "07ecb1f2d9ffbd20a46cd36cd06b022db3cc8e45b1ecab62cd11f9ca7a26ab6d"
		hash2 = "1925e3cd8a1b0bba0d297830636cdb9ebf002698c8fa71e0063581204f4e8345"
		hash3 = "4c5cf8f977fc7c368a8e095700a44be36c8332462c0b1e41bff03238b2bf2a2d"
		hash4 = "591198c234416c6ccbcea6967963ca2ca0f17050be7eed1602198308d9127c78"
		hash5 = "599ae527f10ddb4625687748b7d3734ee51673b664f2e5d0346e64f85e185683"
		hash6 = "5b2a079690efb5f4e0944353dd883303ffd6bab4aad1f0c88b49a76ddcb28ee9"
		hash7 = "5faab159397964e630c4156f8852bcc6ee46df1cdd8be2a8d3f3d8e5980f3bb3"
		hash8 = "76bf736b25d5c9aaf6a84edd4e615796fffc338a893b49c120c0b4941ce37925"
		hash9 = "93f4262fce8c6b4f8e239c35a0679fbbbb722141b95a5f2af53a2bcafe4edd1c"
		hash10 = "96e906128095dead57fdc9ce8688bb889166b67c9a1b8fdb93d7cff7f3836bb9"
		hash11 = "97a546c7d08ad34dfab74c9c8a96986c54768c592a8dae521ddcf612a84fb8cc"
		hash12 = "c796fc66b655f6107eacbe78a37f0e8a2926f01fecebd9e68a66f0e261f91276"
		hash13 = "c80bd1c4a796b4d3944a097e96f384c85687daeedcdcf05cc885c8c9b279b09c"
		hash14 = "f47de978da1dbfc5e0f195745e3368d3ceef034e964817c66ba01396a1953d72"
		hash15 = "f8a5e735d6e79eb587954a371515a82a15883cf2eda9d7ddb8938b86e714ea27"
		hash16 = "fa0defdabd9fd43fe2ef1ec33574ea1af1290bd3d763fdb2bed443f2bd996d73"
		hash17 = "fd1b20ee5bd429046d3c04e9c675c41e9095bea70e0329bd32d7edd17ebaf68a"
		id = "d30df2ae-7008-53c0-9a61-8346a9c9f465"

	strings:
		$op1 = { c6 80 01 01 00 00 00 48 8b 45 ?8 0f b6 90 01 01 00 00 48 8b 45 ?8 88 90 00 01 00 00 c6 45 ?? 00 0f b6 45 ?? 88 45 }
		$op2 = { 48 89 55 c8 48 8b 45 c8 48 89 45 ?? 48 8b 45 c8 0f b6 80 00 01 00 00 88 45 f? 48 8b 45 c8 0f b6 80 01 01 00 00 }
		$op3 = { 48 89 45 ?? 48 8b 45 c8 0f b6 80 00 01 00 00 88 45 f? 48 8b 45 c8 0f b6 80 01 01 00 00 88 45 f? c7 45 f8 00 00 00 00 }
		$op4 = { 48 89 7d d8 89 75 d4 48 89 55 c8 48 8b 45 c8 48 89 45 ?? 48 8b 45 c8 0f b6 80 00 01 00 00 88 45 f? }
		$op5 = { 48 8b 45 ?8 c6 80 01 01 00 00 00 48 8b 45 ?8 0f b6 90 01 01 00 00 48 8b 45 ?8 88 90 00 01 00 00 c6 45 ?? 00 0f b6 45 }
		$op6 = { 89 75 d4 48 89 55 c8 48 8b 45 c8 48 89 45 ?? 48 8b 45 c8 0f b6 80 00 01 00 00 88 45 f? 48 8b 45 c8 }

	condition:
		uint16( 0 ) == 0x457f and filesize < 200KB and 2 of them or 4 of them
}

