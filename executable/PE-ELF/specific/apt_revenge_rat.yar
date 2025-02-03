rule RevengeRAT_Sep17 : hardened
{
	meta:
		description = "Detects RevengeRAT malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-09-04"
		modified = "2020-07-27"
		hash1 = "2a86a4b2dcf1657bcb2922e70fc787aa9b66ec1c26dc2119f669bd2ce3f2e94a"
		hash2 = "7c271484c11795876972aabeb277c7b3035f896c9e860a852d69737df6e14213"
		hash3 = "fe00c4f9c8439eea50b44f817f760d8107f81e2dba7f383009fde508ff4b8967"
		id = "7e58af06-a0ce-532c-9483-b1eca5e3cc28"

	strings:
		$x1 = {4e 75 63 6c 65 61 72 20 45 78 70 6c 6f 73 69 6f 6e 2e 67 2e 72 65 73 6f 75 72 63 65 73}
		$x4 = {35 42 31 45 45 37 43 41 44 33 44 46 46 32 32 30 41 39 35 44 31 44 36 42 39 31 34 33 35 44 39 45 31 35 32 30 41 43 34 31}
		$x5 = {5c 52 65 76 65 6e 67 65 52 41 54 5c}
		$x6 = {52 65 76 65 6e 67 65 2d 52 41 54 20 63 6c 69 65 6e 74 20 68 61 73 20 62 65 65 6e 20 73 75 63 63 65 73 73 66 75 6c 6c 79 20 69 6e 73 74 61 6c 6c 65 64 2e}
		$x7 = {4e 75 63 6c 65 61 72 20 45 78 70 6c 6f 73 69 6f 6e 2e 65 78 65}
		$x8 = {20 00 52 00 65 00 76 00 65 00 6e 00 67 00 65 00 2d 00 52 00 41 00 54 00 20 00 32 00 30 00 31 00}
		$s1 = {7b 00 31 00 31 00 31 00 31 00 31 00 2d 00 32 00 32 00 32 00 32 00 32 00 2d 00 32 00 30 00 30 00 30 00 31 00 2d 00 30 00 30 00 30 00 30 00 31 00 7d 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 500KB and 1 of ( $x* ) ) or ( 3 of them )
}

