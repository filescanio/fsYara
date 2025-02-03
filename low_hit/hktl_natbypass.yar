rule HKTL_NATBypass_Dec22_1 : T1090 hardened
{
	meta:
		description = "Detects NatBypass tool (also used by APT41)"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/cw1997/NATBypass"
		date = "2022-12-27"
		score = 80
		hash1 = "4550635143c9997d5499d1d4a4c860126ee9299311fed0f85df9bb304dca81ff"
		id = "54af4d84-72f7-5ec4-b0bf-7ba228fdf508"

	strings:
		$x1 = {6e 62 20 2d 73 6c 61 76 65 20 31 32 37 2e 30 2e 30 2e 31 3a 33 33 38 39 20 38 2e 38 2e 38 2e 38 3a 31 39 39 37}
		$x2 = {7c 20 57 65 6c 63 6f 6d 65 20 74 6f 20 75 73 65 20 4e 41 54 42 79 70 61 73 73 20 56 65 72}
		$s1 = {6d 61 69 6e 2e 70 6f 72 74 32 68 6f 73 74 2e 66 75 6e 63 31}
		$s2 = {73 74 61 72 74 20 74 6f 20 74 72 61 6e 73 6d 69 74 20 61 64 64 72 65 73 73 3a}
		$s3 = {5e 28 5c 64 7b 31 2c 32 7d 7c 31 5c 64 5c 64 7c 32 5b 30 2d 34 5d 5c 64 7c 32 35 5b 30 2d 35 5d 29 5c 2e 28 5c 64 7b 31 2c 32 7d 7c 31 5c 64 5c 64 7c 32 5b 30 2d 34 5d 5c 64 7c 32 35 5b 30 2d 35 5d 29 5c 2e 28 5c 64 7b 31 2c 32 7d 7c 31 5c 64 5c 64 7c 32 5b 30 2d 34 5d 5c 64 7c 32 35 5b 30 2d 35 5d 29 5c 2e 28 5c 64 7b 31 2c 32 7d 7c 31 5c 64 5c 64 7c 32 5b 30 2d 34 5d 5c 64 7c 32 35 5b 30 2d 35 5d 29}

	condition:
		filesize < 8000KB and ( 1 of ( $x* ) or 2 of them ) or 3 of them
}

