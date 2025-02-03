import "pe"

rule MAL_RANSOM_Venus_Nov22_1 : hardened
{
	meta:
		description = "Detects Venus Ransomware samples"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/dyngnosis/status/1592588860168421376"
		date = "2022-11-16"
		score = 85
		hash1 = "46f9cbc3795d6be0edd49a2c43efe6e610b82741755c5076a89eeccaf98ee834"
		hash2 = "6d8e2d8f6aeb0f4512a53fe83b2ef7699513ebaff31735675f46d1beea3a8e05"
		hash3 = "931cab7fbc0eb2bbc5768f8abdcc029cef76aff98540d9f5214786dccdb6a224"
		hash4 = "969bfe42819e30e35ca601df443471d677e04c988928b63fccb25bf0531ea2cc"
		hash5 = "db6fcd33dcb3f25890c28e47c440845b17ce2042c34ade6d6508afd461bfa21c"
		hash6 = "ee036f333a0c4a24d9aa09848e635639e481695a9209474900eb71c9e453256b"
		hash7 = "fa7ba459236c7b27a0429f1961b992ab87fc8b3427469fd98bfc272ae6852063"
		id = "0f7e0ca4-c5e2-5557-92de-2e0d73035f12"

	strings:
		$x1 = {3c 68 74 6d 6c 3e 3c 68 65 61 64 3e 3c 74 69 74 6c 65 3e 56 65 6e 75 73 3c 2f 74 69 74 6c 65 3e 3c 73 74 79 6c 65 20 74 79 70 65 20 3d 20 22 74 65 78 74}
		$x2 = {78 58 42 4c 54 5a 4b 6d 41 75 39 70 6a 63 66 78 72 49 4b 34 67 6b 44 70 2f 4a 39 58 58 41 54 6a 75 79 73 46 52 58 47 34 72 48 34 3d}
		$x3 = {25 00 73 00 25 00 78 00 25 00 78 00 25 00 78 00 25 00 78 00 2e 00 67 00 6f 00 6f 00 64 00 67 00 61 00 6d 00 65 00}
		$s1 = {2f 63 20 70 69 6e 67 20 6c 6f 63 61 6c 68 6f 73 74 20 2d 6e 20 33 20 3e 20 6e 75 6c 20 26 20 64 65 6c 20 25 73}
		$s2 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 25 00 73 00 2e 00 70 00 6e 00 67 00}
		$op1 = { 8b 4c 24 24 46 8b 7c 24 14 41 8b 44 24 30 81 c7 00 04 00 00 81 44 24 10 00 04 00 00 40 }
		$op2 = { 57 c7 45 fc 00 00 00 00 7e 3f 50 33 c0 74 03 9b 6e }
		$op3 = { 66 89 45 d4 0f 11 45 e8 e8 a8 e7 ff ff 83 c4 14 8d 45 e8 50 8d 45 a4 50 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 700KB and ( pe.imphash ( ) == "bb2600e94092da119ee6acbbd047be43" or 1 of ( $x* ) or 2 of them ) or 4 of them
}

