rule CACTUSTORCH : hardened
{
	meta:
		description = "Detects CactusTorch Hacktool"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/mdsecactivebreach/CACTUSTORCH"
		date = "2017-07-31"
		hash1 = "314e6d7d863878b6dca46af165e7f08fedd42c054d7dc3828dc80b86a3a9b98c"
		hash2 = "0305aa32d5f8484ca115bb4888880729af7f33ac99594ec1aa3c65644e544aea"
		hash3 = "a52d802e34ac9d7d3539019d284b04ded3b8e197d5e3b38ed61f523c3d68baa7"
		id = "75606b9e-97d5-5b8b-87f5-69b7e415b73c"

	strings:
		$x1 = {24 70 61 79 6c 6f 61 64 20 3d 20 73 68 65 6c 6c 63 6f 64 65 28 25 6f 70 74 69 6f 6e 73 5b 22 6c 69 73 74 65 6e 65 72 22 5d 2c 20 22 74 72 75 65 22 2c 20 22 78 38 36 22 29 3b}
		$x2 = {43 6f 70 79 20 74 68 65 20 62 61 73 65 36 34 20 65 6e 63 6f 64 65 64 20 70 61 79 6c 6f 61 64 20 69 6e 74 6f 20 74 68 65 20 63 6f 64 65 20 76 61 72 69 61 62 6c 65 20 62 65 6c 6f 77 2e}
		$x3 = {20 43 41 43 54 55 53 54 4f 52 43 48 20 50 61 79 6c 6f 61 64}
		$x4 = {6d 73 2e 57 72 69 74 65 20 74 72 61 6e 73 66 6f 72 6d 2e 54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b 28 65 6e 63 2e 47 65 74 42 79 74 65 73 5f 34 28 62 29 2c 20 30 2c 20 6c 65 6e 67 74 68 29 2c 20 30 2c 20 28 28 6c 65 6e 67 74 68 20 2f 20 34 29 20 2a 20 33 29}
		$x5 = {27 20 41 75 74 68 6f 72 3a 20 56 69 6e 63 65 6e 74 20 59 69 75 20 28 40 76 79 73 65 63 75 72 69 74 79 29}
		$x6 = {44 69 6d 20 62 69 6e 61 72 79 20 3a 20 62 69 6e 61 72 79 20 3d 20 22 72 75 6e 64 6c 6c 33 32 2e 65 78 65 22}
		$a1 = {63 6f 64 65 20 3d 20 63 6f 64 65 20 26 20 22}
		$a2 = {73 65 72 69 61 6c 69 7a 65 64 5f 6f 62 6a 20 3d 20 73 65 72 69 61 6c 69 7a 65 64 5f 6f 62 6a 20 26 20 22}
		$s1 = {62 69 6e 61 72 79 20 3d 20 22 72 75 6e 64 6c 6c 33 32 2e 65 78 65 22}
		$s2 = {45 4c 2e 44 61 74 61 54 79 70 65 20 3d 20 22 62 69 6e 2e 68 65 78 22}
		$s3 = {53 65 74 20 73 74 6d 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 79 73 74 65 6d 2e 49 4f 2e 4d 65 6d 6f 72 79 53 74 72 65 61 6d 22 29}
		$s4 = {76 61 72 20 62 69 6e 61 72 79 20 3d 20 22 72 75 6e 64 6c 6c 33 32 2e 65 78 65 22 3b}
		$s5 = {76 61 72 20 73 65 72 69 61 6c 69 7a 65 64 5f 6f 62 6a 20 3d 20 22}

	condition:
		( filesize < 800KB and ( 1 of ( $x* ) or ( 1 of ( $a* ) and 1 of ( $s* ) ) ) ) or ( 3 of them )
}

