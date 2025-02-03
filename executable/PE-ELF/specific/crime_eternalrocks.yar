rule EternalRocks_taskhost : hardened
{
	meta:
		description = "Detects EternalRocks Malware - file taskhost.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/stamparm/status/864865144748298242"
		date = "2017-05-18"
		hash1 = "cf8533849ee5e82023ad7adbdbd6543cb6db596c53048b1a0c00b3643a72db30"
		id = "8926cdf8-6a3c-5237-80f5-bda9efb39a32"
		score = 60

	strings:
		$x1 = {45 00 74 00 65 00 72 00 6e 00 61 00 6c 00 52 00 6f 00 63 00 6b 00 73 00 2e 00 65 00 78 00 65 00}
		$s1 = {73 54 61 72 67 65 74 49 50}
		$s2 = {53 45 52 56 45 52 5f 32 30 30 38 52 32 5f 53 50 30}
		$s3 = {32 30 44 35 43 43 45 45 39 43 39 31 41 31 45 36 31 46 37 32 46 34 36 46 41 31 31 37 42 39 33 46 42 30 30 36 44 42 35 31}
		$s4 = {39 45 42 46 37 35 31 31 39 42 38 46 43 37 37 33 33 46 37 37 42 30 36 33 37 38 46 39 45 37 33 35 44 33 34 36 36 34 46 36}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 15000KB and 1 of ( $x* ) or 3 of them )
}

rule EternalRocks_svchost : hardened
{
	meta:
		description = "Detects EternalRocks Malware - file taskhost.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/stamparm/status/864865144748298242"
		date = "2017-05-18"
		hash1 = "589af04a85dc66ec6b94123142a17cf194decd61f5d79e76183db026010e0d31"
		id = "c38d3faa-06a2-5f57-a917-91974941352f"

	strings:
		$s1 = {57 63 7a 54 6b 61 4a 70 68 72 75 4d 79 42 4f 51 6d 47 75 4e 52 74 53 4e 54 4c 45 73}
		$s2 = {73 76 63 68 6f 73 74 2e 74 61 73 6b 68 6f 73 74 2e 65 78 65}
		$s3 = {43 6f 6e 66 75 73 65 72 45 78 20 76}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 500KB and 2 of them )
}

