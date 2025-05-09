rule skeleton_key_patcher : hardened
{
	meta:
		description = "Skeleton Key Patcher from Dell SecureWorks Report http://goo.gl/aAk3lN"
		author = "Dell SecureWorks Counter Threat Unit"
		reference = "http://goo.gl/aAk3lN"
		date = "2015/01/13"
		score = 70
		id = "a2805cce-7605-58a4-85ce-9dff5586858e"

	strings:
		$target_process = {6c 00 73 00 61 00 73 00 73 00 2e 00 65 00 78 00 65 00}
		$dll1 = {63 72 79 70 74 64 6c 6c 2e 64 6c 6c}
		$dll2 = {73 61 6d 73 72 76 2e 64 6c 6c}
		$name = {48 6f 6f 6b 44 43 2e 64 6c 6c}
		$patched1 = {43 44 4c 6f 63 61 74 65 43 53 79 73 74 65 6d}
		$patched2 = {53 61 6d 49 52 65 74 72 69 65 76 65 50 72 69 6d 61 72 79 43 72 65 64 65 6e 74 69 61 6c 73}
		$patched3 = {53 61 6d 49 52 65 74 72 69 65 76 65 4d 75 6c 74 69 70 6c 65 50 72 69 6d 61 72 79 43 72 65 64 65 6e 74 69 61 6c 73}

	condition:
		all of them
}

rule skeleton_key_injected_code : hardened
{
	meta:
		description = "Skeleton Key injected Code http://goo.gl/aAk3lN"
		author = "Dell SecureWorks Counter Threat Unit"
		reference = "http://goo.gl/aAk3lN"
		date = "2015/01/13"
		score = 70
		id = "29daaffa-cd9d-55d3-b79d-cde1c76e9e45"

	strings:
		$injected = { 33 C0 85 C9 0F 95 C0 48 8B 8C 24 40 01 00 00 48 33 CC E8 4D 02 00 00 48 81 C4 58 01 00 00 C3 }
		$patch_CDLocateCSystem = { 48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B FA 8B F1 E8 ?? ?? ?? ?? 48 8B D7 8B CE 48 8B D8 FF 50 10 44 8B D8 85 C0 0F 88 A5 00 00 00 48 85 FF 0F 84 9C 00 00 00 83 FE 17 0F 85 93 00 00 00 48 8B 07 48 85 C0 0F 84 84 00 00 00 48 83 BB 48 01 00 00 00 75 73 48 89 83 48 01 00 00 33 D2 }
		$patch_SamIRetrievePrimaryCredential = { 48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 20 49 8B F9 49 8B F0 48 8B DA 48 8B E9 48 85 D2 74 2A 48 8B 42 08 48 85 C0 74 21 66 83 3A 26 75 1B 66 83 38 4B 75 15 66 83 78 0E 73 75 0E 66 83 78 1E 4B 75 07 B8 A1 02 00 C0 EB 14 E8 ?? ?? ?? ?? 4C 8B CF 4C 8B C6 48 8B D3 48 8B CD FF 50 18 48 8B 5C 24 30 48 8B 6C 24 38 48 8B 74 24 40 48 83 C4 20 5F C3 }
		$patch_SamIRetrieveMultiplePrimaryCredential = { 48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 20 41 8B F9 49 8B D8 8B F2 8B E9 4D 85 C0 74 2B 49 8B 40 08 48 85 C0 74 22 66 41 83 38 26 75 1B 66 83 38 4B 75 15 66 83 78 0E 73 75 0E 66 83 78 1E 4B 75 07 B8 A1 02 00 C0 EB 12 E8 ?? ?? ?? ?? 44 8B CF 4C 8B C3 8B D6 8B CD FF 50 20 48 8B 5C 24 30 48 8B 6C 24 38 48 8B 74 24 40 48 83 C4 20 5F C3 }

	condition:
		any of them
}

