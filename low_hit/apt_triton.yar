rule Triton_trilog : hardened limited
{
	meta:
		description = "Detects Triton APT malware - file trilog.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/vtQoCQ"
		date = "2017-12-14"
		hash1 = "e8542c07b2af63ee7e72ce5d97d91036c5da56e2b091aa2afe737b224305d230"
		id = "ae2c9b47-2a67-50c6-9d2a-dc47b4fa69ef"

	strings:
		$s1 = {69 6e 6a 65 63 74 2e 62 69 6e}
		$s2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 50 59 54 48 4f 4e 32 37 2e 44 4c 4c (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s3 = {70 61 79 6c 6f 61 64}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 60KB and all of them
}

