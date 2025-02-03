import "pe"

rule MAL_WIPER_IsaacWiper_Mar22_1 : hardened
{
	meta:
		description = "Detects IsaacWiper malware"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.welivesecurity.com/2022/03/01/isaacwiper-hermeticwizard-wiper-worm-targeting-ukraine/"
		date = "2022-03-03"
		score = 85
		hash1 = "13037b749aa4b1eda538fda26d6ac41c8f7b1d02d83f47b0d187dd645154e033"
		hash2 = "7bcd4ec18fc4a56db30e0aaebd44e2988f98f7b5d8c14f6689f650b4f11e16c0"
		id = "97d8d8dd-db65-5156-8f97-56c620cf2d56"

	strings:
		$s1 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 6c 00 6f 00 67 00 2e 00 74 00 78 00 74 00}
		$s2 = {43 6c 65 61 6e 65 72 2e 64 6c 6c}
		$s3 = {2d 00 2d 00 20 00 73 00 79 00 73 00 74 00 65 00 6d 00 20 00 6c 00 6f 00 67 00 69 00 63 00 61 00 6c 00 20 00 64 00 72 00 69 00 76 00 65 00 3a 00 20 00}
		$s4 = {2d 00 2d 00 20 00 46 00 41 00 49 00 4c 00 45 00 44 00}
		$op1 = { 8b f1 80 3d b0 66 03 10 00 0f 85 96 00 00 00 33 c0 40 b9 a8 66 03 10 87 01 33 db }
		$op2 = { 8b 40 04 2b c2 c1 f8 02 3b c8 74 34 68 a2 c8 01 10 2b c1 6a 04 }
		$op3 = { 8d 4d f4 ff 75 08 e8 12 ff ff ff 68 88 39 03 10 8d 45 f4 50 e8 2d 1d 00 00 cc }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 700KB and ( pe.imphash ( ) == "a4b162717c197e11b76a4d9bc58ea25d" or 3 of them )
}

