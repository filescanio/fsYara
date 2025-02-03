rule Backdoor_Redosdru_Jun17 : HIGHVOL hardened
{
	meta:
		description = "Detects malware Redosdru - file systemHome.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/OOB3mH"
		date = "2017-06-04"
		hash1 = "4f49e17b457ef202ab0be905691ef2b2d2b0a086a7caddd1e70dd45e5ed3b309"
		id = "ea038142-6903-5d08-ac89-70c1bbef716c"
		score = 90

	strings:
		$x1 = {25 73 5c 25 64 2e 67 68 6f}
		$x2 = {25 73 5c 6e 74 25 73 2e 64 6c 6c}
		$x3 = {62 61 69 6a 69 6e 55 50 64 61 74 65}
		$s1 = {52 65 67 51 75 65 72 79 56 61 6c 75 65 45 78 28 53 76 63 68 6f 73 74 5c 6e 65 74 73 76 63 73 29}
		$s2 = {73 65 72 76 69 63 65 6f 6e 65}
		$s3 = {1f 23 70 20 1f 23 70 20 1f 23 70 20 1f 23 70 20 1f 23 70 20 1f 23 70 20 1f 23 70 20 1f 23 70 20 1f 23 70 20 1f 23 70 20 1f 23 70 20 1f 23 70 20 1f 23 70 20 1f 23 70 20 1f 23 70 20 1f 23 70 20 1f 23 70 20 1f 23 70 20 1f 23 70 20 1f 23 70 20 1f 23 70 20 1f 23 70 20 1f 23 70 20 1f 23 70 20 1f 23 66 20 1f 23}
		$s4 = {73 65 72 76 69 63 65 74 77 6f}
		$s5 = {55 70 64 61 74 65 43 72 63}
		$s6 = {1f 23 5b 20 1f 23 78 20 1f 23 78 20 1f 23 78 20 1f 23 78 20 1f 23 78 20 1f 23 78 20 1f 23 78 20 1f 23 78 20 1f 23 78 20 1f 23 78 20 1f 23 78 20 1f 23 78 20 1f 23 78 20 1f 23 78 20 1f 23 78 20 1f 23 78 20 1f 23 78 20 1f 23 78 20 1f 23 78 20 1f 23 78 20 1f 23}
		$s7 = {6e 77 73 61 50 41 67 45 6e 54}
		$s8 = {25 2d 32 34 73 20 25 2d 31 35 73 20 30 78 25 78 28 25 64 29 20}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 700KB and 1 of ( $x* ) or 4 of them )
}

rule Backdoor_Nitol_Jun17 : hardened
{
	meta:
		description = "Detects malware backdoor Nitol - file wyawou.exe - Attention: this rule also matches on Upatre Downloader"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/OOB3mH"
		date = "2017-06-04"
		modified = "2023-01-07"
		hash1 = "cba19d228abf31ec8afab7330df3c9da60cd4dae376552b503aea6d7feff9946"
		id = "7dd26868-59e0-51a1-b12a-3b69d6246ff5"

	strings:
		$x1 = {55 73 65 72 2d 41 67 65 6e 74 3a 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 25 64 2e 30 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 25 64 2e 30 3b 20 4d 79 49 45 20 33 2e 30 31 29}
		$x2 = {55 73 65 72 2d 41 67 65 6e 74 3a 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 25 64 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 25 64 2e 31 3b 20 53 56 31 29}
		$x3 = {54 43 50 43 6f 6e 6e 65 63 74 46 6c 6f 6f 64 54 68 72 65 61 64 2e 74 61 72 67 65 74 20 3d 20 25 73}
		$s1 = {5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65}
		$s2 = {25 63 25 63 25 63 25 63 25 63 25 63 2e 65 78 65}
		$s3 = {47 45 54 20 25 73 25 73 20 48 54 54 50 2f 31 2e 31}
		$s4 = {43 43 41 74 74 61 63 6b 2e 74 61 72 67 65 74 20 3d 20 25 73}
		$s5 = {41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 20 7a 68 2d 63 6e}
		$s6 = {6a 64 66 77 6b 65 79}
		$s7 = {68 61 63 6b 71 7a 2e 66 33 33 32 32 2e 6f 72 67 3a 38 38 38 30}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 200KB and ( 1 of ( $x* ) and 2 of ( $s* ) ) ) or ( all of them )
}

