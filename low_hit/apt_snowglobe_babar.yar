rule SNOWGLOBE_Babar_Malware : hardened
{
	meta:
		description = "Detects the Babar Malware used in the SNOWGLOBE attacks - file babar.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://motherboard.vice.com/read/meet-babar-a-new-malware-almost-certainly-created-by-france"
		date = "2015/02/18"
		hash = "27a0a98053f3eed82a51cdefbdfec7bb948e1f36"
		score = 80
		id = "53a61065-a3b3-563e-8ecc-513d8da68085"

	strings:
		$z0 = {61 64 6d 69 6e 5c 44 65 73 6b 74 6f 70 5c 42 61 62 61 72 36 34 5c 42 61 62 61 72 36 34 5c 6f 62 6a 5c 44 6c 6c 57 72 61 70 70 65 72}
		$z1 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 20 36 2e 30 3b}
		$z2 = {45 78 65 63 51 75 65 72 79 46 61 69 6c 6c 65 64 21}
		$z3 = {4e 42 4f 54 5f 43 4f 4d 4d 41 4e 44 5f 4c 49 4e 45}
		$z4 = {21 21 21 45 58 54 52 41 43 54 20 45 52 52 4f 52 21 21 21 46 69 6c 65 20 44 6f 65 73 20 4e 6f 74 20 45 78 69 73 74 73 2d 2d 3e 5b 25 73 5d}
		$s1 = {2f 73 20 2f 6e 20 25 73 20 22 25 73 22}
		$s2 = {25 25 57 49 4e 44 49 52 25 25 5c 25 73 5c 25 73}
		$s3 = {2f 63 20 73 74 61 72 74 20 2f 77 61 69 74 20}
		$s4 = {28 44 3b 4f 49 43 49 3b 46 41 3b 3b 3b 41 4e 29 28 41 3b 4f 49 43 49 3b 46 41 3b 3b 3b 42 47 29 28 41 3b 4f 49 43 49 3b 46 41 3b 3b 3b 53 59 29 28 41 3b 4f 49 43 49 3b 46 41 3b 3b 3b 4c 53 29}
		$x1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d 5c}
		$x2 = {25 43 4f 4d 4d 4f 4e 5f 41 50 50 44 41 54 41 25}
		$x4 = {43 4f 4e 4f 55 54 24}
		$x5 = {63 6d 64 2e 65 78 65}
		$x6 = {44 4c 4c 50 41 54 48}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1MB and ( ( 1 of ( $z* ) and 1 of ( $x* ) ) or ( 3 of ( $s* ) and 4 of ( $x* ) ) )
}

