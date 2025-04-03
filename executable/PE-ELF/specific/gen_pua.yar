rule WinDivert_Driver : hardened limited
{
	meta:
		description = "Detects WinDivert User-Mode packet capturing driver"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.reqrypt.org/windivert.html"
		date = "2017-10-02"
		score = 40
		hash1 = "33c657fa27b92cfcced66b331cfea7a880460a98cf037e4277faa1420fe59d1c"
		hash2 = "9b834e8f9d117bf2c564a37434973dc0717270ebfac8d8251711905d18da3858"
		hash3 = "5ef707ea68a9bd3a3e568793a0f7d66d166694801ada067d9ebac1d13e53153e"
		hash4 = "df12afa691e529f01c75b3dd734f6b45bf1488dbf90ced218657f0d205bff319"
		id = "95e89577-bb5a-5391-9130-155746d4783f"

	strings:
		$s1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 57 69 6e 44 69 76 65 72 74 44 6c 6c 45 6e 74 72 79 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 57 69 6e 44 69 76 65 72 74 48 65 6c 70 65 72 50 61 72 73 65 49 50 76 34 41 64 64 72 65 73 73 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s3 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 57 00 69 00 6e 00 44 00 69 00 76 00 65 00 72 00 74 00 20 00 28 00 77 00 65 00 62 00 3a 00 20 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 72 00 65 00 71 00 72 00 79 00 70 00 74 00 2e 00 6f 00 72 00 67 00 2f 00 77 00 69 00 6e 00 64 00 69 00 76 00 65 00 72 00 74 00 2e 00 68 00 74 00 6d 00 6c 00 29 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 80KB and 1 of them )
}

