rule MAL_RANSOM_DarkBit_Feb23_1 : hardened
{
	meta:
		description = "Detects indicators found in DarkBit ransomware"
		author = "Florian Roth"
		reference = "https://twitter.com/idonaor1/status/1624703255770005506?s=12&t=mxHaauzwR6YOj5Px8cIeIw"
		date = "2023-02-13"
		score = 75
		id = "d209a0c2-f649-5fb1-9ecd-f1c35caa796f"

	strings:
		$s1 = {2e 6f 6e 69 6f 6e}
		$s2 = {47 65 74 4d 4f 54 57 48 6f 73 74 55 72 6c}
		$x1 = {68 75 73 33 31 6d 37 63 37 61 64 2e 6f 6e 69 6f 6e}
		$x2 = {69 77 36 76 32 70 33 63 72 75 79}
		$xn1 = {59 6f 75 20 77 69 6c 6c 20 72 65 63 65 69 76 65 20 64 65 63 72 79 70 74 69 6e 67 20 6b 65 79 20 61 66 74 65 72 20 74 68 65 20 70 61 79 6d 65 6e 74 2e}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 10MB and ( 1 of ( $x* ) or 2 of them ) or 4 of them or ( filesize < 10MB and $xn1 )
}

rule MAL_RANSOM_DarkBit_Feb23_2 : hardened
{
	meta:
		description = "Detects Go based DarkBit ransomware (garbled code; could trigger on other obfuscated samples, too)"
		author = "Florian Roth"
		reference = "https://www.hybrid-analysis.com/sample/9107be160f7b639d68fe3670de58ed254d81de6aec9a41ad58d91aa814a247ff?environmentId=160"
		date = "2023-02-13"
		score = 75
		hash1 = "9107be160f7b639d68fe3670de58ed254d81de6aec9a41ad58d91aa814a247ff"
		id = "f530815c-68e7-55f1-8e36-bc74a1059584"

	strings:
		$s1 = {72 75 6e 74 69 6d 65 2e 69 6e 69 74 4c 6f 6e 67 50 61 74 68 53 75 70 70 6f 72 74}
		$s2 = {72 65 66 6c 65 63 74 2e}
		$s3 = {20 20 20 20 22 70 72 6f 63 65 73 73 65 73 22 3a 20 5b 5d 2c}
		$s4 = {5e 21 2a 20 25 21 28 21}
		$op1 = { 4d 8b b6 00 00 00 00 48 8b 94 24 40 05 00 00 31 c0 87 82 30 03 00 00 b8 01 00 00 00 f0 0f c1 82 00 03 00 00 48 8b 44 24 48 48 8b 0d ba 1f 32 00 }
		$op2 = { 49 8d 49 01 0f 1f 00 48 39 d9 7c e2 b9 0b 00 00 00 49 89 d8 e9 28 fc ff ff e8 89 6c d7 ff }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 20000KB and all of them
}

