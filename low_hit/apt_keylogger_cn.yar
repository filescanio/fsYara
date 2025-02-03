rule Keylogger_CN_APT : hardened
{
	meta:
		description = "Keylogger - generic rule for a Chinese variant"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2016-03-07"
		score = 75
		hash = "3efb3b5be39489f19d83af869f11a8ef8e9a09c3c7c0ad84da31fc45afcf06e7"
		id = "7be0b175-05a4-5725-ba21-9438c0fcd740"

	strings:
		$x1 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 36 2e 30 3b 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 31 29}
		$x2 = {61 74 74 72 69 62 20 2d 73 20 2d 68 20 2d 72 20 63 3a 5c 6e 74 6c 64 72}
		$x3 = {25 73 57 69 6e 64 6f 77 73 20 4e 54 20 25 64 2e 25 64}
		$x4 = {52 65 66 65 72 65 72 3a 20 68 74 74 70 3a 2f 2f 25 73 2f 25 73 2e 61 73 70 78 3f 6e 3d}
		$s1 = {5c 63 6d 64 2e 65 78 65 20 2f 63 20 22 73 79 73 74 65 6d 69 6e 66 6f 2e 65 78 65 20 3e 3e 20}
		$s2 = {25 73 5c 63 6d 64 2e 65 78 65 20 2f 63 20 25 73 20 3e 3e 20 22 25 73 22}
		$s3 = {73 68 75 74 64 6f 77 6e 2e 65 78 65 20 2d 72 20 2d 74 20 30}
		$s4 = {64 69 72 20 22 25 53 79 73 74 65 6d 44 72 69 76 65 25 5c 5c 22 20 2f 73 20 2f 61}
		$s5 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 36 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 31 3b}
		$s6 = {68 74 74 70 5f 73 2e 65 78 65}
		$s7 = {55 73 65 72 20 41 67 65 6e 74 5c 50 6f 73 74 20 50 6c 61 74 66 6f 72 6d 5c}
		$s8 = {64 65 73 6b 74 6f 70 2e 74 6d 70}
		$s9 = {5c 73 75 70 70 6f 72 74 2e 69 63 77}
		$s10 = {61 67 63 2e 74 6d 70}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 100KB and 1 of ( $x* ) ) or 3 of them
}

