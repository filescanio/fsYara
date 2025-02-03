rule Dexter_Malware : hardened
{
	meta:
		description = "Detects the Dexter Trojan/Agent http://goo.gl/oBvy8b"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/oBvy8b"
		date = "2015/02/10"
		score = 70
		id = "8be328ec-ba29-50ba-8d35-e2c4dfcae45e"

	strings:
		$s0 = {4a 00 61 00 76 00 61 00 20 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 20 00 50 00 6c 00 75 00 67 00 69 00 6e 00}
		$s1 = {25 00 73 00 5c 00 25 00 73 00 5c 00 25 00 73 00 2e 00 65 00 78 00 65 00}
		$s2 = {53 00 75 00 6e 00 20 00 4a 00 61 00 76 00 61 00 20 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 20 00 50 00 6c 00 75 00 67 00 69 00 6e 00}
		$s3 = {5c 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5c 00 69 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 2e 00 65 00 78 00 65 00}

	condition:
		all of them
}

