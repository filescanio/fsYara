rule fromCharCode_in_unicode : hardened
{
	strings:
		$ = {5c 75 30 30 36 36 5c 75 30 30 37 32 5c 75 30 30 36 66 5c 75 30 30 36 64 5c 75 30 30 34 33 5c 75 30 30 36 38 5c 75 30 30 36 31 5c 75 30 30 37 32 5c 75 30 30 34 33 5c 75 30 30 36 66 5c 75 30 30 36 34 5c 75 30 30 36 35}

	condition:
		any of them and filesize < 500KB
}

rule function_through_object : hardened
{
	strings:
		$ = {5b 27 65 76 61 6c 27 5d}
		$ = {5b 27 75 6e 65 73 63 61 70 65 27 5d}
		$ = {5b 27 63 68 61 72 43 6f 64 65 41 74 27 5d}
		$ = {5b 27 66 72 6f 6d 43 68 61 72 43 6f 64 65 27 5d}

	condition:
		any of them and filesize < 500KB
}

rule hex_script : hardened
{
	strings:
		$ = {5c 78 37 33 5c 78 36 33 5c 78 37 32 5c 78 36 39 5c 78 37 30 5c 78 37 34 5c 78 32 32}

	condition:
		any of them and filesize < 500KB
}

rule php_malfunctions : hardened
{
	meta:
		score = 50

	strings:
		$ = {65 76 61 6c 28}
		$ = {67 7a 69 6e 66 6c 61 74 65 28}
		$ = {73 74 72 5f 72 6f 74 31 33 28}
		$ = {62 61 73 65 36 34 5f 64 65 63 6f 64 65 28}

	condition:
		3 of them and filesize < 500KB
}

rule php_obf_malfunctions : hardened
{
	strings:
		$ = {65 76 61 6c 28 62 61 73 65 36 34 5f 64 65 63 6f 64 65}
		$ = {65 76 61 6c 28 67 7a 69 6e 66 6c 61 74 65}
		$ = {73 74 72 5f 72 6f 74 31 33 28 62 61 73 65 36 34 5f 64 65 63 6f 64 65}

	condition:
		any of them and filesize < 500KB
}

rule fopo_obfuscator : hardened
{
	strings:
		$ = {77 77 77 2e 66 6f 70 6f 2e 63 6f 6d 2e 61 72}

	condition:
		any of them and filesize < 500KB
}

rule obf_base64_decode : hardened
{
	strings:
		$ = {5c 78 36 32 5c 78 36 31 5c 78 37 33 5c 31 34 35 5c 78 33 36 5c 78 33 34 5c 78 35 66 5c 78 36 34 5c 78 36 35 5c 31 34 33 5c 78 36 66 5c 31 34 34 5c 31 34 35}

	condition:
		any of them and filesize < 500KB
}

rule html_upload : hardened
{
	strings:
		$ = {3c 69 6e 70 75 74 20 74 79 70 65 3d 27 73 75 62 6d 69 74 27 20 6e 61 6d 65 3d 27 75 70 6c 6f 61 64 27 20 76 61 6c 75 65 3d 27 75 70 6c 6f 61 64 27 3e}
		$ = {69 66 28 24 5f 50 4f 53 54 5b 27 75 70 6c 6f 61 64 27 5d 29}

	condition:
		any of them and filesize < 500KB
}

rule php_uname : hardened
{
	strings:
		$ = {70 68 70 5f 75 6e 61 6d 65 28 29}

	condition:
		any of them and filesize < 500KB
}

rule scriptkiddies : hardened limited
{
	strings:
		$ = {6c 61 73 74 63 30 64 65 40 4f 75 74 6c 6f 6f 6b 2e 63 6f 6d}
		$ = {43 6f 64 65 72 73 4c 65 65 74}
		$ = {41 67 65 6e 63 79 43 61 46 63}
		$ = {49 6e 64 6f 58 70 6c 6f 69 74}
		$ = {4b 61 70 61 6c 6a 65 74 7a 36 36 36}

	condition:
		any of them and filesize < 500KB
}

rule eval_with_comments : hardened
{
	strings:
		$ = /(^|\s)eval\s*\/\*.{,128}\*\/\s*\(/

	condition:
		any of them and filesize < 500KB
}

