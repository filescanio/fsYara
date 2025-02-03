rule RocketKitten_Keylogger : hardened
{
	meta:
		description = "Detects Keylogger used in Rocket Kitten APT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/SjQhlp"
		date = "2015-09-01"
		super_rule = 1
		hash1 = "1c9e519dca0468a87322bebe2a06741136de7969a4eb3efda0ab8db83f0807b4"
		hash2 = "495a15f9f30d6f6096a97c2bd8cc5edd4d78569b8d541b1d5a64169f8109bc5b"
		id = "558341db-a30d-586e-8efc-0fff1d8f94a1"

	strings:
		$x1 = {5c 52 65 6c 65 61 73 65 5c 43 57 6f 6f 6c 67 65 72 2e 70 64 62}
		$x2 = {57 6f 6f 6c 65 6e 4c 6f 67 65 72 5c 6f 62 6a 5c 78 38 36 5c 52 65 6c 65 61 73 65}
		$x3 = {44 3a 5c 59 61 73 65 72 20 4c 6f 67 65 72 73 5c}
		$z1 = {77 00 6f 00 6f 00 6c 00 67 00 65 00 72 00}
		$s1 = {6f 53 68 65 6c 6c 4c 69 6e 6b 2e 54 61 72 67 65 74 50 61 74 68 20 3d 20 22}
		$s2 = {77 73 63 72 69 70 74 2e 65 78 65 20}
		$s3 = {73 74 72 53 54 55 50 20 3d 20 57 73 68 53 68 65 6c 6c 2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 22 53 74 61 72 74 75 70 22 29}
		$s4 = {5b 43 61 70 73 4c 6f 63 6b 5d}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 200KB and ( 1 of ( $x* ) or ( $z1 and 2 of ( $s* ) ) ) ) or ( $z1 and all of ( $s* ) )
}

