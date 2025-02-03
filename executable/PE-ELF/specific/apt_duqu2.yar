rule Duqu2_Sample1 : hardened
{
	meta:
		description = "Detects malware - Duqu2 (cross-matches with IronTiger malware and Derusbi)"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/70504/the-mystery-of-duqu-2-0-a-sophisticated-cyberespionage-actor-returns/"
		date = "2016-07-02"
		score = 80
		hash1 = "6b146e3a59025d7085127b552494e8aaf76450a19c249bfed0b4c09f328e564f"
		hash2 = "8e97c371633d285cd8fc842f4582705052a9409149ee67d97de545030787a192"
		hash3 = "2796a119171328e91648a73d95eb297edc220e8768f4bbba5fb7237122a988fc"
		hash4 = "5559fcc93eef38a1c22db66a3e0f9e9f026c99e741cc8b1a4980d166f2696188"
		id = "39ba04f1-df45-5513-ab8f-12097a79cdc7"

	strings:
		$x1 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 60 00 44 00 61 00 74 00 61 00 60 00 20 00 46 00 52 00 4f 00 4d 00 20 00 60 00 42 00 69 00 6e 00 61 00 72 00 79 00 60 00 20 00 57 00 48 00 45 00 52 00 45 00 20 00 60 00 4e 00 61 00 6d 00 65 00 60 00 3d 00 27 00 25 00 73 00 25 00 69 00 27 00}
		$s2 = {4d 53 49 2e 64 6c 6c}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 40KB and $x1 ) or ( all of them )
}

rule Duqu2_Sample2 : hardened
{
	meta:
		description = "Detects Duqu2 Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/70504/the-mystery-of-duqu-2-0-a-sophisticated-cyberespionage-actor-returns/"
		date = "2016-07-02"
		score = 80
		hash1 = "d12cd9490fd75e192ea053a05e869ed2f3f9748bf1563e6e496e7153fb4e6c98"
		hash2 = "5ba187106567e8d036edd5ddb6763f89774c158d2a571e15d76572d8604c22a0"
		hash3 = "6e09e1a4f56ea736ff21ad5e188845615b57e1a5168f4bdaebe7ddc634912de9"
		hash4 = "c16410c49dc40a371be22773f420b7dd3cfd4d8205cf39909ad9a6f26f55718e"
		hash5 = "2ecb26021d21fcef3d8bba63de0c888499110a2b78e4caa6fa07a2b27d87f71b"
		hash6 = "2c9c3ddd4d93e687eb095444cef7668b21636b364bff55de953bdd1df40071da"
		id = "a32f54a3-8656-5592-ac40-17330bfca319"

	strings:
		$s1 = {3d 3c 3d 51 3d 57 3d 61 3d 67 3d 70 3d 76 3d 7c 3d}
		$s2 = {3e 23 3e 28 3e 2e 3e 33 3e 3d 3e 5d 3e 64 3e 70 3e}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 50KB and all of ( $s* )
}

rule Duqu2_Sample3 : hardened
{
	meta:
		description = "Detects Duqu2 Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/70504/the-mystery-of-duqu-2-0-a-sophisticated-cyberespionage-actor-returns/"
		date = "2016-07-02"
		score = 80
		hash1 = "2a9a5afc342cde12c6eb9a91ad29f7afdfd8f0fb17b983dcfddceccfbc17af69"
		id = "c558445f-fbe3-57db-80f7-09a87b097921"

	strings:
		$s1 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 60 00 25 00 73 00 60 00 20 00 46 00 52 00 4f 00 4d 00 20 00 60 00 25 00 73 00 60 00 20 00 57 00 48 00 45 00 52 00 45 00 20 00 60 00 25 00 73 00 60 00 3d 00 27 00 43 00 41 00 44 00 61 00 74 00 61 00 25 00 69 00 27 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 50KB and $s1 )
}

rule Duqu2_Sample4 : hardened
{
	meta:
		description = "Detects Duqu2 Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/70504/the-mystery-of-duqu-2-0-a-sophisticated-cyberespionage-actor-returns/"
		date = "2016-07-02"
		score = 80
		hash1 = "3536df7379660d931256b3cf49be810c0d931c3957c464d75e4cba78ba3b92e3"
		id = "8c5ca68d-762c-5d2e-8d37-f58dc66bcae2"

	strings:
		$x1 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 60 00 44 00 61 00 74 00 61 00 60 00 20 00 46 00 52 00 4f 00 4d 00 20 00 60 00 42 00 69 00 6e 00 61 00 72 00 79 00 60 00 20 00 57 00 48 00 45 00 52 00 45 00 20 00 60 00 4e 00 61 00 6d 00 65 00 60 00 3d 00 27 00 43 00 72 00 79 00 70 00 74 00 48 00 61 00 73 00 68 00 25 00 69 00 27 00}
		$s2 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 60 00 55 00 73 00 65 00 72 00 4e 00 61 00 6d 00 65 00 60 00 2c 00 20 00 60 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 60 00 2c 00 20 00 60 00 41 00 74 00 74 00 72 00 69 00 62 00 75 00 74 00 65 00 73 00 60 00 20 00 46 00 52 00 4f 00 4d 00 20 00 60 00 43 00 75 00 73 00 74 00 6f 00 6d 00 55 00 73 00 65 00 72 00 41 00 63 00 63 00 6f 00 75 00 6e 00 74 00 73 00 60 00}
		$s3 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 60 00 55 00 73 00 65 00 72 00 4e 00 61 00 6d 00 65 00 60 00 20 00 46 00 52 00 4f 00 4d 00 20 00 60 00 43 00 75 00 73 00 74 00 6f 00 6d 00 55 00 73 00 65 00 72 00 41 00 63 00 63 00 6f 00 75 00 6e 00 74 00 73 00 60 00}
		$s4 = {50 72 6f 63 65 73 73 55 73 65 72 41 63 63 6f 75 6e 74 73}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 30KB and 1 of ( $x* ) ) or ( all of them )
}

rule Duqu2_UAs : hardened
{
	meta:
		description = "Detects Duqu2 Executable based on the specific UAs in the file"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/70504/the-mystery-of-duqu-2-0-a-sophisticated-cyberespionage-actor-returns/"
		date = "2016-07-02"
		score = 60
		hash1 = "52fe506928b0262f10de31e783af8540b6a0b232b15749d647847488acd0e17a"
		hash2 = "81cdbe905392155a1ba8b687a02e65d611b60aac938e470a76ef518e8cffd74d"
		id = "d82f6351-fab0-5324-850f-dd40a172fceb"

	strings:
		$x1 = {4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 2f 00 35 00 2e 00 30 00 20 00 28 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 20 00 36 00 2e 00 31 00 3b 00 20 00 55 00 3b 00 20 00 72 00 75 00 3b 00 20 00 72 00 76 00 3a 00 35 00 2e 00 30 00 2e 00 31 00 2e 00 36 00 29 00 20 00 47 00 65 00 63 00 6b 00 6f 00 2f 00 32 00 30 00 31 00 31 00 30 00 35 00 30 00 31 00 20 00 46 00 69 00 72 00 65 00 66 00 6f 00 78 00 2f 00 35 00 2e 00 30 00 2e 00 31 00 20 00 46 00 69 00 72 00 65 00 66 00 6f 00 78 00 2f 00 35 00 2e 00 30 00 2e 00 31 00}
		$x2 = {4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 2f 00 35 00 2e 00 30 00 20 00 28 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 20 00 36 00 2e 00 31 00 3b 00 20 00 57 00 4f 00 57 00 36 00 34 00 29 00 20 00 41 00 70 00 70 00 6c 00 65 00 57 00 65 00 62 00 4b 00 69 00 74 00 2f 00 35 00 33 00 35 00 2e 00 37 00 20 00 28 00 4b 00 48 00 54 00 4d 00 4c 00 2c 00 20 00 6c 00 69 00 6b 00 65 00 20 00 47 00 65 00 63 00 6b 00 6f 00 29 00 20 00 43 00 68 00 72 00 6f 00 6d 00 65 00 2f 00 31 00 36 00 2e 00 30 00 2e 00 39 00 31 00 32 00 2e 00 36 00 33 00 20 00 53 00 61 00 66 00 61 00 72 00 69 00 2f 00 35 00 33 00 35 00 2e 00 37 00 78 00 73 00 35 00 44 00 39 00 72 00 52 00 44 00 46 00 70 00 67 00 32 00 67 00}
		$x3 = {4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 2f 00 34 00 2e 00 30 00 20 00 28 00 63 00 6f 00 6d 00 70 00 61 00 74 00 69 00 62 00 6c 00 65 00 3b 00 20 00 4d 00 53 00 49 00 45 00 20 00 37 00 2e 00 30 00 62 00 3b 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 20 00 35 00 2e 00 31 00 3b 00 20 00 46 00 44 00 4d 00 3b 00 20 00 2e 00 4e 00 45 00 54 00 20 00 43 00 4c 00 52 00 20 00 31 00 2e 00 31 00 2e 00 34 00 33 00 32 00 32 00 29 00}
		$x4 = {4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 2f 00 35 00 2e 00 30 00 20 00 28 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 20 00 36 00 2e 00 31 00 3b 00 20 00 57 00 4f 00 57 00 36 00 34 00 3b 00 20 00 72 00 76 00 3a 00 36 00 2e 00 30 00 61 00 32 00 29 00 20 00 47 00 65 00 63 00 6b 00 6f 00 2f 00 32 00 30 00 31 00 31 00 30 00 36 00 31 00 32 00 20 00 46 00 69 00 72 00 65 00 66 00 6f 00 78 00 2f 00 36 00 2e 00 30 00 61 00 32 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 800KB and all of them )
}

