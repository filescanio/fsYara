rule WinDivert_Driver : hardened
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
		$s1 = {57 69 6e 44 69 76 65 72 74 44 6c 6c 45 6e 74 72 79}
		$s2 = {57 69 6e 44 69 76 65 72 74 48 65 6c 70 65 72 50 61 72 73 65 49 50 76 34 41 64 64 72 65 73 73}
		$s3 = {57 00 69 00 6e 00 44 00 69 00 76 00 65 00 72 00 74 00 20 00 28 00 77 00 65 00 62 00 3a 00 20 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 72 00 65 00 71 00 72 00 79 00 70 00 74 00 2e 00 6f 00 72 00 67 00 2f 00 77 00 69 00 6e 00 64 00 69 00 76 00 65 00 72 00 74 00 2e 00 68 00 74 00 6d 00 6c 00 29 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 80KB and 1 of them )
}

