rule Backdoor_WebShell_asp : ASPXSpy hardened
{
	meta:
		description = "Detect ASPXSpy"
		author = "xylitol@temari.fr"
		date = "2019-02-26"
		score = 75

	strings:
		$string1 = {((43 6d 64 53 68 65 6c 6c) | (43 00 6d 00 64 00 53 00 68 00 65 00 6c 00 6c 00))}
		$string2 = {((41 44 53 56 69 65 77 65 72) | (41 00 44 00 53 00 56 00 69 00 65 00 77 00 65 00 72 00))}
		$string3 = {((41 53 50 58 53 70 79 2e 42 69 6e) | (41 00 53 00 50 00 58 00 53 00 70 00 79 00 2e 00 42 00 69 00 6e 00))}
		$string4 = {((50 6f 72 74 53 63 61 6e) | (50 00 6f 00 72 00 74 00 53 00 63 00 61 00 6e 00))}
		$plugin = {((54 65 73 74 2e 41 73 70 78 53 70 79 50 6c 75 67 69 6e 73) | (54 00 65 00 73 00 74 00 2e 00 41 00 73 00 70 00 78 00 53 00 70 00 79 00 50 00 6c 00 75 00 67 00 69 00 6e 00 73 00))}

	condition:
		3 of ( $string* ) or $plugin
}

