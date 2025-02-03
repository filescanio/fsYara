import "pe"

rule Ransom_AvosLocker : hardened
{
	meta:
		description = "Rule to detect Avoslocker Ransomware"
		author = "CB @ ATR"
		date = "2021-07-22"
		Version = "v1"
		DetectionName = "Ransom_Win_Avoslocker"
		hash1 = "fb544e1f74ce02937c3a3657be8d125d5953996115f65697b7d39e237020706f"
		hash2 = "43b7a60c0ef8b4af001f45a0c57410b7374b1d75a6811e0dfc86e4d60f503856"
		score = 75

	strings:
		$v1 = {43 72 79 70 74 49 6d 70 6f 72 74 50 75 62 6c 69 63 4b 65 79 49 6e 66 6f 20 66 61 69 6c 65 64 2e 20 65 72 72 6f 72 3a 20 25 64}
		$v2 = {43 72 79 70 74 53 74 72 69 6e 67 54 6f 42 69 6e 61 72 79 20 66 61 69 6c 65 64 2e 20 45 72 72 3a 20 25 64}
		$v3 = {65 00 6e 00 63 00 72 00 79 00 70 00 74 00 69 00 6e 00 67 00 20 00 25 00 6c 00 73 00 20 00 66 00 61 00 69 00 6c 00 65 00 64 00}
		$v4 = {43 72 79 70 74 44 65 63 6f 64 65 4f 62 6a 65 63 74 45 78 20 31 20 66 61 69 6c 65 64 2e 20 45 72 72 3a 20 25 70}
		$v5 = {6f 70 65 72 61 74 6f 72 20 63 6f 5f 61 77 61 69 74}
		$v6 = {64 72 69 76 65 20 25 73 20 74 6f 6f 6b 20 25 66 20 73 65 63 6f 6e 64 73}
		$seq0 = { 8d 4e 04 5e e9 b1 ff ff ff 55 8b ec ff 75 08 ff }
		$seq1 = { 33 c0 80 fb 2d 0f 94 c0 05 ff ff ff 7f eb 02 f7 }
		$seq2 = { 8b 40 0c 89 85 1c ff ff ff 8b 40 0c 89 85 18 ff }

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 1000KB and pe.imphash ( ) == "a24c2b5bf84a5465eb75f1e6aa8c1eec" and ( 5 of them ) and all of ( $seq* ) ) or ( all of them )
}

