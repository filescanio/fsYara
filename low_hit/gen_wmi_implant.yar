rule WMImplant : hardened
{
	meta:
		description = "Auto-generated rule - file WMImplant.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2017/03/wmimplant_a_wmi_ba.html"
		date = "2017-03-24"
		hash1 = "860d7c237c2395b4f51b8c9bd0ee6cab06af38fff60ce3563d160d50c11d2f78"
		id = "18dadc55-e12f-5c4c-9e11-27dc2d6c8dd2"

	strings:
		$x1 = {49 6e 76 6f 6b 65 2d 50 72 6f 63 65 73 73 50 75 6e 69 73 68 65 72 20 2d 43 72 65 64 73 20 24 52 65 6d 6f 74 65 43 72 65 64 65 6e 74 69 61 6c}
		$x2 = {24 54 61 72 67 65 74 20 2d 71 75 65 72 79 20 22 53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 57 69 6e 33 32 5f 4e 54 4c 6f 67 45 76 65 6e 74 20 57 48 45 52 45 20 28 6c 6f 67 66 69 6c 65 3d 27 73 65 63 75 72 69 74 79 27 29}
		$x3 = {57 4d 49 6d 70 6c 61 6e 74 20 2d 43 72 65 64 73}
		$x4 = {2d 44 6f 77 6e 6c 6f 61 64 20 2d 52 65 6d 6f 74 65 46 69 6c 65 20 43 3a 5c 70 61 73 73 77 6f 72 64 73 2e 74 78 74}
		$x5 = {2d 43 6f 6d 6d 61 6e 64 20 27 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 63 6f 6d 6d 61 6e 64 20 22 45 6e 61 62 6c 65 2d 50 53 52 65 6d 6f 74 69 6e 67}
		$x6 = {49 6e 76 6f 6b 65 2d 57 4d 49 6d 70 6c 61 6e 74}

	condition:
		1 of them
}

