rule Rana_Android_resources : hardened loosened limited
{
	meta:
		score = 60

	strings:
		$res1 = {((72 65 73 2f 72 61 77 2f 63 6e 67 2e 63 6e) | (72 00 65 00 73 00 2f 00 72 00 61 00 77 00 2f 00 63 00 6e 00 67 00 2e 00 63 00 6e 00))}
		$res2 = {((72 65 73 2f 72 61 77 2f 61 74 74 2e 63 6e) | (72 00 65 00 73 00 2f 00 72 00 61 00 77 00 2f 00 61 00 74 00 74 00 2e 00 63 00 6e 00))}
		$res3 = {((72 65 73 2f 72 61 77 2f 6f 64 72 2e 6f 64) | (72 00 65 00 73 00 2f 00 72 00 61 00 77 00 2f 00 6f 00 64 00 72 00 2e 00 6f 00 64 00))}

	condition:
		any of them
}

