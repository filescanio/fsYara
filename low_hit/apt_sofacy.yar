import "pe"

rule Sofacy_Campaign_Mal_Feb18_cdnver : hardened
{
	meta:
		description = "Detects Sofacy malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/ClearskySec/status/960924755355369472"
		date = "2018-02-07"
		hash1 = "12e6642cf6413bdf5388bee663080fa299591b2ba023d069286f3be9647547c8"
		id = "a5c72ddd-91b0-5410-9d81-38a138ec7efe"

	strings:
		$x1 = {63 00 64 00 6e 00 76 00 65 00 72 00 2e 00 64 00 6c 00 6c 00}
		$x2 = { 25 73 0A 00 00 00 00 00 30 00 00 00 20 00 2D 00
              20 00 00 00 0A 00 00 00 25 00 73 00 00 00 00 00
              69 00 6D 00 61 00 67 00 65 00 2F 00 6A 00 70 00
              65 00 67 }
		$s1 = {53 37 25 73 20 2d 20 25 6c 75}
		$s2 = {53 4e 46 49 52 4e 57}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 90KB and ( pe.imphash ( ) == "01f3d0fe6fb9d9df24620e67afc143c7" or 1 of ( $x* ) or 2 of them )
}

import "pe"

rule Sofacy_Trojan_Loader_Feb18_1 : hardened
{
	meta:
		description = "Sofacy Activity Feb 2018"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.reverse.it/sample/e3399d4802f9e6d6d539e3ae57e7ea9a54610a7c4155a6541df8e94d67af086e?environmentId=100"
		date = "2018-03-01"
		hash1 = "335565711db93cd02d948f472c51598be4d62d60f70f25a20449c07eae36c8c5"
		id = "358d7a77-0ff5-572e-9cd8-b2cebaace02f"

	strings:
		$x1 = {25 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 25 00 5c 00 6e 00 61 00 64 00 2e 00 64 00 6c 00 6c 00}
		$s3 = {25 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 25 00 5c 00 6e 00 61 00 64 00 2e 00 62 00 61 00 74 00}
		$s1 = {61 70 64 73 2e 64 6c 6c}
		$s2 = {6e 61 64 2e 64 6c 6c 22}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 300KB and ( pe.imphash ( ) == "a2d1be6502b4b3c28959a4fb0196ea45" or pe.exports ( "VidBitRpl" ) or 1 of ( $x* ) or 2 of them )
}

import "pe"

rule APT_ATP28_Sofacy_Indicators_May19_1 : hardened
{
	meta:
		description = "Detects APT28 Sofacy indicators in samples"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/cyb3rops/status/1129647994603790338"
		date = "2019-05-18"
		score = 60
		hash1 = "80548416ffb3d156d3ad332718ed322ef54b8e7b2cc77a7c5457af57f51d987a"
		hash2 = "b40909ac0b70b7bd82465dfc7761a6b4e0df55b894dd42290e3f72cb4280fa44"
		id = "ca768b60-7094-537a-b848-28bd42555287"

	strings:
		$x1 = {63 3a 5c 55 73 65 72 73 5c 75 73 65 72 5c 44 65 73 6b 74 6f 70 5c 6f 70 65 6e 73 73 6c 2d 31 2e 30 2e 31 65 5f 6d 5c 2f 73 73 6c 2f 63 65 72 74 2e 70 65 6d}
		$x2 = {43 3a 5c 55 73 65 72 73 5c 55 73 65 72 5c 44 65 73 6b 74 6f 70 5c 44 6f 77 6e 6c 6f 61 64 65 72 5f 50 6f 63 6f}
		$s1 = {77 00 25 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 25 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 6e 00 70 00 6d 00 70 00 72 00 6f 00 78 00 79 00 2e 00 64 00 6c 00 6c 00}
		$op0 = { e8 41 37 f6 ff 48 2b e0 e8 99 ff ff ff 48 8b d0 }
		$op1 = { e9 34 3c e3 ff cc cc cc cc 48 8d 8a 20 }
		$op2 = { e8 af bb ef ff b8 ff ff ff ff e9 f4 01 00 00 8b }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 10000KB and ( pe.imphash ( ) == "f4e1c3aaec90d5dfa23c04da75ac9501" or 1 of ( $x* ) or ( $s1 and 2 of ( $op* ) ) )
}

