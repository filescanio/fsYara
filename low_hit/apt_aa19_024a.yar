rule APT_MAL_DNS_Hijacking_Campaign_AA19_024A : hardened
{
	meta:
		description = "Detects malware used in DNS Hijackign campaign"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.us-cert.gov/ncas/alerts/AA19-024A"
		date = "2019-01-25"
		hash1 = "2010f38ef300be4349e7bc287e720b1ecec678cacbf0ea0556bcf765f6e073ec"
		hash2 = "45a9edb24d4174592c69d9d37a534a518fbe2a88d3817fc0cc739e455883b8ff"
		id = "6a476052-ba4e-5049-9c7a-f8949d26e7b5"

	strings:
		$s2 = {2f 43 6c 69 65 6e 74 2f 4c 6f 67 69 6e 3f 69 64 3d}
		$s3 = {4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 6f 77 73 20 4e 54 20 36 2e 31 3b 20 54 72 69 64 65 6e 74 2f 37 2e 30 3b 20 72 76 3a 31 31 2e 30 29 20 6c 69 6b 65 20 47 65 63 6b 6f}
		$s4 = {2e 5c 43 6f 6e 66 69 67 75 72 65 2e 74 78 74}
		$s5 = {43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65 3d 22 66 69 6c 65 73 22 3b 20 66 69 6c 65 6e 61 6d 65 3d 22}
		$s6 = {43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65 3d 22 74 78 74 73 22}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1000KB and 2 of them
}

