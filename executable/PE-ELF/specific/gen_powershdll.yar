rule PowerShdll : hardened
{
	meta:
		description = "Detects hack tool PowerShdll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/p3nt4/PowerShdll"
		date = "2017-08-03"
		hash1 = "4d33bc7cfa79d7eefc5f7a99f1b052afdb84895a411d7c30045498fd4303898a"
		hash2 = "f999db9cc3a0719c19f35f0e760f4ce3377b31b756d8cd91bb8270acecd7be7d"
		id = "cc0e01ca-77f0-5665-8b1e-48c8e947d0d3"

	strings:
		$x1 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 20 00 50 00 6f 00 77 00 65 00 72 00 53 00 68 00 64 00 6c 00 6c 00 2c 00 6d 00 61 00 69 00 6e 00 20 00 2d 00 66 00 20 00 3c 00 70 00 61 00 74 00 68 00 3e 00}
		$x2 = {5c 50 6f 77 65 72 53 68 64 6c 6c 2e 64 6c 6c}
		$x3 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 20 00 50 00 6f 00 77 00 65 00 72 00 53 00 68 00 64 00 6c 00 6c 00 2c 00 6d 00 61 00 69 00 6e 00 20 00 3c 00 73 00 63 00 72 00 69 00 70 00 74 00 3e 00}

	condition:
		1 of them
}

