rule POSHSPY_Malware : hardened
{
	meta:
		description = "Detects"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2017/03/dissecting_one_ofap.html"
		date = "2017-07-15"
		id = "7e908efc-0023-5be1-9871-8bfbf8b9e53a"
		score = 75

	strings:
		$x1 = {66 75 6e 63 74 69 6f 6e 20 73 57 50 28 24 63 4e 2c 20 24 70 4e 2c 20 24 61 4b 2c 20 24 61 49 29}
		$x2 = {24 61 65 4b 20 3d 20 5b 62 79 74 65 5b 5d 5d 20 28 30 78 36 39 2c 20 30 78 38 37 2c 20 30 78 30 62 2c 20 30 78 66 32}
		$x3 = {28 28 27 76 61 72 69 61 6e 74 27 2c 20 27 65 78 63 72 65 74 69 6f 6e 73 27 2c 20 27 61 63 63 75 6d 75 6c 61 74 6f 72 73 27 2c 20 27 77 69 6e 73 6c 6f 77 27 2c 20 27 77 68 69 73 74 6c 65 61 62 6c 65 27 2c 20 27 6c 65 6e 27 2c}
		$x4 = {24 63 50 61 69 72 4b 65 79 20 3d 20 22 42 77 49 41 41 41 43 6b 41 41 42 53 55 30 45 79 41 41 51 41 41 41 45 41 41}
		$x5 = {24 65 78 65 52 65 73 20 3d 20 65 78 65 50 6c 64 52 6f 75 74 69 6e 65}
		$x6 = {5a 67 42 31 41 47 34 41 59 77 42 30 41 47 6b 41 62 77 42 75 41 43 41 41 63 41 42 31 41 48 49 41 5a 67 42 44 41 48 49 41}

	condition:
		1 of them
}

