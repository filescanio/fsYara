rule b374k_back_connect : hardened
{
	meta:
		description = "Detects privilege escalation tool"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Analysis"
		date = "2016-08-18"
		score = 80
		hash1 = "c8e16f71f90bbaaef27ccaabb226b43762ca6f7e34d7d5585ae0eb2d36a4bae5"
		id = "8612bda2-2576-56c0-a4ba-afbef419ab05"

	strings:
		$s1 = {41 64 64 41 74 6f 6d 41 43 72 65 61 74 65 50 72 6f}
		$s2 = {73 68 75 74 64 6f 77}
		$s3 = {2f 63 6f 6e 66 69 67 2f 69 33 38 36}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 10KB and all of them )
}

