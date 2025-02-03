rule APT_Liudoor : hardened
{
	meta:
		author = "RSA FirstWatch"
		date = "2015-07-23"
		description = "Detects Liudoor daemon backdoor"
		hash0 = "78b56bc3edbee3a425c96738760ee406"
		hash1 = "5aa0510f6f1b0e48f0303b9a4bfc641e"
		hash2 = "531d30c8ee27d62e6fbe855299d0e7de"
		hash3 = "2be2ac65fd97ccc97027184f0310f2f3"
		hash4 = "6093505c7f7ec25b1934d3657649ef07"
		type = "Win32 DLL"
		id = "cf7e08b8-2ccd-5828-917b-11340b4a86b1"

	strings:
		$string0 = {53 75 63 63}
		$string1 = {46 61 69 6c}
		$string2 = {70 61 73 73}
		$string3 = {65 78 69 74}
		$string4 = {73 76 63 68 6f 73 74 64 6c 6c 73 65 72 76 65 72 2e 64 6c 6c}
		$string5 = {4c 24 2c 50 51 52}
		$string6 = {30 2f 30 42 30 48 30 51 30 57 30 6b 30}
		$string7 = {51 53 55 56 57 68}
		$string8 = {48 74 20 48 75 5b}

	condition:
		all of them
}

