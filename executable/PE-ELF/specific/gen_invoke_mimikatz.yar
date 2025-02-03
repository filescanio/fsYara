rule Invoke_Mimikatz : hardened
{
	meta:
		description = "Detects Invoke-Mimikatz String"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/clymb3r/PowerShell/tree/master/Invoke-Mimikatz"
		date = "2016-08-03"
		hash1 = "f1a499c23305684b9b1310760b19885a472374a286e2f371596ab66b77f6ab67"
		id = "37de51a6-e1bb-5ee7-9b7f-8fe17b3697b5"
		score = 100

	strings:
		$x2 = {54 56 71 51 41 41 4d 41 41 41 41 45 41 41 41 41 2f 2f 38 41 41 4c 67 41 41 41 41 41 41 41 41 41 51 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 47 41 45 41 41 41 34 66 75 67 34 41 74 41 6e 4e 49 62 67 42 54 4d 30 68 56 47 68 70 63 79 42 77 63 6d}
		$x3 = {57 72 69 74 65 2d 42 79 74 65 73 54 6f 4d 65 6d 6f 72 79 20 2d 42 79 74 65 73 20 24 53 68 65 6c 6c 63 6f 64 65 31 20 2d 4d 65 6d 6f 72 79 41 64 64 72 65 73 73 20 24 47 65 74 43 6f 6d 6d 61 6e 64 4c 69 6e 65 57 41 64 64 72 54 65 6d 70}

	condition:
		1 of them
}

