rule HKTL_RedMimicry_Agent : hardened
{
	meta:
		date = "2020-06-22"
		modified = "2023-01-06"
		author = "mirar@chaosmail.org"
		sharing = "tlp:white"
		description = "matches the RedMimicry agent executable and payload"
		reference = "https://redmimicry.com"
		id = "a4d4ec77-4a0d-5afd-9181-85433e8b5fda"

	strings:
		$reg0 = {48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c}
		$reg1 = {48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c}
		$reg2 = {48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 43 4f 4e 46 49 47 5c}
		$reg3 = {48 4b 45 59 5f 43 4c 41 53 53 45 53 5f 52 4f 4f 54 5c}
		$cmd0 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 63 6d 64 2e 65 78 65}
		$lua0 = {63 6c 69 65 6e 74 5f 72 65 63 76}
		$lua1 = {63 6c 69 65 6e 74 5f 73 65 6e 64}
		$lua2 = {24 4c 75 61 56 65 72 73 69 6f 6e 3a 20}
		$sym0 = {56 00 69 00 72 00 74 00 75 00 61 00 6c 00 41 00 6c 00 6c 00 6f 00 63 00 45 00 78 00}
		$sym1 = {6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00}

	condition:
		all of them
}

rule HKTL_RedMimicry_WinntiLoader : hardened
{
	meta:
		date = "2020-06-22"
		modified = "2023-01-10"
		author = "mirar@chaosmail.org"
		sharing = "tlp:white"
		description = "matches the Winnti 'Cooper' loader version used for the RedMimicry breach emulation"
		reference = "https://redmimicry.com"
		id = "a8be1377-faa0-560d-a12c-0369b1f91180"

	strings:
		$s0 = {43 6f 6f 70 65 72}
		$s1 = {73 74 6f 6e 65 36 34 2e 64 6c 6c}
		$decoding_loop = { 49 63 D0 43 8D 0C 01 41 FF C0 42 32 0C 1A 0F B6 C1 C0 E9 04 C0 E0 04 02 C1 42 88 04 1A 44 3B 03 72 DE }

	condition:
		all of them
}

