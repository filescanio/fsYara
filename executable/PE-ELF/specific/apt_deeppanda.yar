rule DeepPanda_htran_exe : hardened
{
	meta:
		description = "Hack Deep Panda - htran-exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2015/02/08"
		hash = "38e21f0b87b3052b536408fdf59185f8b3d210b9"
		id = "2a551e82-aff1-5a77-bc5e-d06e49dca8bc"

	strings:
		$s0 = {25 73 20 2d 3c 6c 69 73 74 65 6e 7c 74 72 61 6e 7c 73 6c 61 76 65 3e 20 3c 6f 70 74 69 6f 6e 3e 20 5b 2d 6c 6f 67 20 6c 6f 67 66 69 6c 65 5d}
		$s2 = {5c 52 65 6c 65 61 73 65 5c 68 74 72 61 6e 2e 70 64 62}
		$s3 = {5b 53 45 52 56 45 52 5d 63 6f 6e 6e 65 63 74 69 6f 6e 20 74 6f 20 25 73 3a 25 64 20 65 72 72 6f 72}
		$s4 = {2d 74 72 61 6e 20 20 3c 43 6f 6e 6e 65 63 74 50 6f 72 74 3e 20 3c 54 72 61 6e 73 6d 69 74 48 6f 73 74 3e 20 3c 54 72 61 6e 73 6d 69 74 50 6f 72 74 3e}
		$s8 = {3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 20 68 74 72 61 6e 20 56 25 73 20 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d}
		$s11 = {2d 73 6c 61 76 65 20 20 3c 43 6f 6e 6e 65 63 74 48 6f 73 74 3e 20 3c 43 6f 6e 6e 65 63 74 50 6f 72 74 3e 20 3c 54 72 61 6e 73 6d 69 74 48 6f 73 74 3e 20 3c 54 72 61 6e 73 6d 69 74 50 6f 72 74 3e}
		$s15 = {5b 2b 5d 20 4f 4b 21 20 49 20 43 6c 6f 73 65 64 20 54 68 65 20 54 77 6f 20 53 6f 63 6b 65 74 2e}
		$s20 = {2d 6c 69 73 74 65 6e 20 3c 43 6f 6e 6e 65 63 74 50 6f 72 74 3e 20 3c 54 72 61 6e 73 6d 69 74 50 6f 72 74 3e}

	condition:
		2 of them
}

