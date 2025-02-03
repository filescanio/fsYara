rule Invoke_OSiRis : hardened
{
	meta:
		description = "Osiris Device Guard Bypass - file Invoke-OSiRis.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-03-27"
		hash1 = "19e4a8b07f85c3d4c396d0c4e839495c9fba9405c06a631d57af588032d2416e"
		id = "b9f4e5dd-2366-5898-9f46-17584139469f"

	strings:
		$x1 = {24 6e 75 6c 6c 20 3d 20 49 77 6d 69 20 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 20 2d 45 6e 61 62 6c 65 41 20 2d 49 6d 70 65 72 73 20 33 20 2d 41 75 74 68 65 6e 50 61 63 6b 65 74 70 72 69 76 61 63 79 20 2d 4e 61 6d 65 20 43 72 65 61 74 65 20 2d 41 72 67 20 24 4f 62 66 75 73 4b 20 2d 43 6f 6d 70 75 74 65 72 20 24 54 61 72 67 65 74}
		$x2 = {49 6e 76 6f 6b 65 2d 4f 53 69 52 69 73}
		$x3 = {2d 41 72 67 40 7b 4e 61 6d 65 3d 24 56 61 72 4e 61 6d 65 3b 56 61 72 69 61 62 6c 65 56 61 6c 75 65 3d 24 4f 53 69 52 69 73 3b 55 73 65 72 4e 61 6d 65 3d 24 65 6e 76 3a 55 73 65 72 6e 61 6d 65 7d}
		$x4 = {44 65 76 69 63 65 20 47 75 61 72 64 20 42 79 70 61 73 73 20 43 6f 6d 6d 61 6e 64 20 45 78 65 63 75 74 69 6f 6e}
		$x5 = {2d 50 75 74 20 50 61 79 6c 6f 61 64 20 69 6e 20 57 69 6e 33 32 5f 4f 53 52 65 63 6f 76 65 72 79 43 6f 6e 66 69 67 75 72 61 74 69 6f 6e 20 44 65 62 75 67 46 69 6c 65 50 61 74 68}
		$x6 = {24 6e 75 6c 6c 20 3d 20 49 77 6d 69 20 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 20 2d 45 6e 61 62 6c 65 41 20 2d 49 6d 70 65 72 73 20 33 20 2d 41 75 74 68 65 6e 50 61 63 6b 65 74 70 72 69 76 61 63 79 20 2d 4e 61 6d 65 20 43 72 65 61 74 65}

	condition:
		1 of them
}

