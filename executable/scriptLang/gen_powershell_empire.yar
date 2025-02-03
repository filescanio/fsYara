rule Empire_Invoke_BypassUAC : hardened
{
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file Invoke-BypassUAC.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/PowerShellEmpire/Empire"
		date = "2015-08-06"
		score = 70
		hash = "ab0f900a6915b7497313977871a64c3658f3e6f73f11b03d2d33ca61305dc6a8"
		id = "8454d929-e184-5be1-b61f-4dfa8f44bdda"

	strings:
		$s1 = {24 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 41 64 64 72 20 3d 20 47 65 74 2d 50 72 6f 63 41 64 64 72 65 73 73 20 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 20 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79}
		$s2 = {24 70 72 6f 63 20 3d 20 53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 6e 6f 74 65 70 61 64 2e 65 78 65 20 2d 50 61 73 73 54 68 72 75}
		$s3 = {24 50 61 79 6c 6f 61 64 20 3d 20 49 6e 76 6f 6b 65 2d 50 61 74 63 68 44 6c 6c 20 2d 44 6c 6c 42 79 74 65 73 20 24 50 61 79 6c 6f 61 64 20 2d 46 69 6e 64 53 74 72 69 6e 67 20 22 45 78 69 74 54 68 72 65 61 64 22 20 2d 52 65 70 6c 61 63 65 53 74 72 69 6e 67 20 22 45 78 69 74 50 72 6f 63 65 73 73 22}
		$s4 = {24 74 65 6d 70 20 3d 20 5b 53 79 73 74 65 6d 2e 54 65 78 74 2e 45 6e 63 6f 64 69 6e 67 5d 3a 3a 55 4e 49 43 4f 44 45 2e 47 65 74 42 79 74 65 73 28 24 73 7a 54 65 6d 70 44 6c 6c 50 61 74 68 29}

	condition:
		filesize < 1200KB and 3 of them
}

rule Empire_lib_modules_trollsploit_message : hardened
{
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file message.py"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/PowerShellEmpire/Empire"
		date = "2015-08-06"
		score = 70
		hash = "71f2258177eb16eafabb110a9333faab30edacf67cb019d5eab3c12d095655d5"
		id = "cb0eee5a-c236-512e-8256-7411a7fb1fd5"

	strings:
		$s1 = {73 63 72 69 70 74 20 2b 3d 20 22 20 2d 22 20 2b 20 73 74 72 28 6f 70 74 69 6f 6e 29 20 2b 20 22 20 5c 5c 22 22 20 2b 20 73 74 72 28 76 61 6c 75 65 73 5b 27 56 61 6c 75 65 27 5d 2e 73 74 72 69 70 28 22 5c 5c 22 22 29 29 20 2b 20 22 5c 5c 22 22}
		$s2 = {69 66 20 6f 70 74 69 6f 6e 2e 6c 6f 77 65 72 28 29 20 21 3d 20 22 61 67 65 6e 74 22 20 61 6e 64 20 6f 70 74 69 6f 6e 2e 6c 6f 77 65 72 28 29 20 21 3d 20 22 63 6f 6d 70 75 74 65 72 6e 61 6d 65 22 3a}
		$s3 = {5b 53 74 72 69 6e 67 5d 20 24 54 69 74 6c 65 20 3d 20 27 45 52 52 4f 52 20 2d 20 30 78 41 38 30 31 42 37 32 30 27}
		$s4 = {27 56 61 6c 75 65 27 20 20 20 20 20 20 20 20 20 3a 20 20 20 27 4c 6f 73 74 20 63 6f 6e 74 61 63 74 20 77 69 74 68 20 74 68 65 20 44 6f 6d 61 69 6e 20 43 6f 6e 74 72 6f 6c 6c 65 72 2e 27}

	condition:
		filesize < 10KB and 3 of them
}

rule Empire_Persistence : hardened
{
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file Persistence.psm1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/PowerShellEmpire/Empire"
		date = "2015-08-06"
		score = 70
		hash = "ae8875f7fcb8b4de5cf9721a9f5a9f7782f7c436c86422060ecdc5181e31092f"
		id = "0f63b5f4-f933-5821-b0b0-50717e75f6d9"

	strings:
		$s1 = {43 3a 5c 50 53 3e 41 64 64 2d 50 65 72 73 69 73 74 65 6e 63 65 20 2d 53 63 72 69 70 74 42 6c 6f 63 6b 20 24 52 69 63 6b 52 6f 6c 6c 20 2d 45 6c 65 76 61 74 65 64 50 65 72 73 69 73 74 65 6e 63 65 4f 70 74 69 6f 6e 20 24 45 6c 65 76 61 74 65 64 4f 70 74 69 6f 6e 73 20 2d 55 73 65 72 50 65 72 73 69 73 74 65 6e 63 65 4f 70 74 69 6f 6e 20 24 55 73 65 72 4f 70 74 69 6f 6e 73 20 2d 56}
		$s2 = {23 20 45 78 65 63 75 74 65 20 74 68 65 20 66 6f 6c 6c 6f 77 69 6e 67 20 74 6f 20 72 65 6d 6f 76 65 20 74 68 65 20 75 73 65 72 2d 6c 65 76 65 6c 20 70 65 72 73 69 73 74 65 6e 74 20 70 61 79 6c 6f 61 64}
		$s3 = {24 50 65 72 73 69 73 74 61 6e 74 53 63 72 69 70 74 20 3d 20 24 50 65 72 73 69 73 74 61 6e 74 53 63 72 69 70 74 2e 54 6f 53 74 72 69 6e 67 28 29 2e 52 65 70 6c 61 63 65 28 27 45 58 45 43 55 54 45 46 55 4e 43 54 49 4f 4e 27 2c 20 22 24 50 65 72 73 69 73 74 65 6e 63 65 53 63 72 69 70 74 4e 61 6d 65 20 2d 50 65 72 73 69 73 74 22 29}

	condition:
		filesize < 108KB and 1 of them
}

rule Empire_portscan : hardened
{
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file portscan.py"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/PowerShellEmpire/Empire"
		date = "2015-08-06"
		score = 70
		hash = "b355efa1e7b3681b1402e22c58ce968795ef245fd08a0afb948d45c173e60b97"
		id = "23a0f769-9155-5aa0-9200-2baf827bdda4"

	strings:
		$s1 = {73 63 72 69 70 74 20 2b 3d 20 22 49 6e 76 6f 6b 65 2d 50 6f 72 74 53 63 61 6e 20 2d 6e 6f 50 72 6f 67 72 65 73 73 4d 65 74 65 72 20 2d 66 22}
		$s2 = {73 63 72 69 70 74 20 2b 3d 20 22 20 7c 20 3f 20 7b 24 5f 2e 61 6c 69 76 65 7d 7c 20 53 65 6c 65 63 74 2d 4f 62 6a 65 63 74 20 48 6f 73 74 4e 61 6d 65 2c 40 7b 6e 61 6d 65 3d 27 4f 70 65 6e 50 6f 72 74 73 27 3b 65 78 70 72 65 73 73 69 6f 6e 3d 7b 24 5f 2e 6f 70 65 6e 50 6f 72 74 73 20 2d 6a 6f 69 6e 20 27 2c 27 7d 7d 20 7c 20 66 74 20 2d 77 72 61 70 20 7c 20 4f 75 74 2d 53 74 72}

	condition:
		filesize < 14KB and all of them
}

rule Empire_Invoke_Shellcode : hardened
{
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file Invoke-Shellcode.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/PowerShellEmpire/Empire"
		date = "2015-08-06"
		score = 70
		hash = "fa75cfd57269fbe3ad6bdc545ee57eb19335b0048629c93f1dc1fe1059f60438"
		id = "41788f71-cc99-50b3-bdc7-17b132ab2767"

	strings:
		$s1 = {43 3a 5c 50 53 3e 20 49 6e 76 6f 6b 65 2d 53 68 65 6c 6c 63 6f 64 65 20 2d 50 72 6f 63 65 73 73 49 64 20 24 50 72 6f 63 2e 49 64 20 2d 50 61 79 6c 6f 61 64 20 77 69 6e 64 6f 77 73 2f 6d 65 74 65 72 70 72 65 74 65 72 2f 72 65 76 65 72 73 65 5f 68 74 74 70 73 20 2d 4c 68 6f 73 74 20 31 39 32 2e 31 36 38 2e 33 30 2e 31 32 39 20 2d 4c 70 6f 72 74 20 34 34 33 20 2d 56 65 72 62 6f 73}
		$s2 = {22 49 6e 6a 65 63 74 69 6e 67 20 73 68 65 6c 6c 63 6f 64 65 20 69 6e 6a 65 63 74 69 6e 67 20 69 6e 74 6f 20 24 28 28 47 65 74 2d 50 72 6f 63 65 73 73 20 2d 49 64 20 24 50 72 6f 63 65 73 73 49 64 29 2e 50 72 6f 63 65 73 73 4e 61 6d 65 29 20 28 24 50 72 6f 63 65 73 73 49 64 29 21 22 20 29 20 29}
		$s3 = {24 52 65 6d 6f 74 65 4d 65 6d 41 64 64 72 20 3d 20 24 56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 2e 49 6e 76 6f 6b 65 28 24 68 50 72 6f 63 65 73 73 2c 20 5b 49 6e 74 50 74 72 5d 3a 3a 5a 65 72 6f 2c 20 24 53 68 65 6c 6c 63 6f 64 65 2e 4c 65 6e 67 74 68 20 2b 20 31 2c 20 30 78 33 30 30 30 2c 20 30 78 34 30 29 20 23 20 28 52 65 73 65 72 76 65 7c 43 6f 6d 6d 69 74 2c 20 52 57 58 29}

	condition:
		filesize < 100KB and 1 of them
}

rule Empire_Invoke_Mimikatz : hardened
{
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file Invoke-Mimikatz.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/PowerShellEmpire/Empire"
		date = "2015-08-06"
		score = 70
		hash = "c5481864b757837ecbc75997fa24978ffde3672b8a144a55478ba9a864a19466"
		id = "f7d6c1c4-2a24-54fd-b745-32d7894affc8"

	strings:
		$s1 = {24 50 45 42 79 74 65 73 36 34 20 3d 20 22 54 56 71 51 41 41 4d 41 41 41 41 45 41 41 41 41 2f 2f 38 41 41 4c 67 41 41 41 41 41 41 41 41 41 51 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 2b 41 41 41 41 41 34 66 75 67 34 41 74 41 6e 4e 49 62 67 42 54 4d 30 68 56 47 68 70 63 79 42 77 63}
		$s2 = {5b 53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 49 6e 74 65 72 6f 70 53 65 72 76 69 63 65 73 2e 4d 61 72 73 68 61 6c 5d 3a 3a 53 74 72 75 63 74 75 72 65 54 6f 50 74 72 28 24 43 6d 64 4c 69 6e 65 41 41 72 67 73 50 74 72 2c 20 24 47 65 74 43 6f 6d 6d 61 6e 64 4c 69 6e 65 41 41 64 64 72 54 65 6d 70 2c 20 24 66 61 6c 73 65 29}
		$s3 = {57 72 69 74 65 2d 42 79 74 65 73 54 6f 4d 65 6d 6f 72 79 20 2d 42 79 74 65 73 20 24 53 68 65 6c 6c 63 6f 64 65 32 20 2d 4d 65 6d 6f 72 79 41 64 64 72 65 73 73 20 24 47 65 74 43 6f 6d 6d 61 6e 64 4c 69 6e 65 57 41 64 64 72 54 65 6d 70}

	condition:
		filesize < 2500KB and 2 of them
}

rule Empire_lib_modules_credentials_mimikatz_pth : hardened
{
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file pth.py"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/PowerShellEmpire/Empire"
		date = "2015-08-06"
		score = 70
		hash = "6dee1cf931e02c5f3dc6889e879cc193325b39e18409dcdaf987b8bf7c459211"
		id = "f954b7e8-e820-5111-ba8d-a9b9779381b0"

	strings:
		$s0 = {28 63 72 65 64 49 44 2c 20 63 72 65 64 54 79 70 65 2c 20 64 6f 6d 61 69 6e 4e 61 6d 65 2c 20 75 73 65 72 4e 61 6d 65 2c 20 70 61 73 73 77 6f 72 64 2c 20 68 6f 73 74 2c 20 73 69 64 2c 20 6e 6f 74 65 73 29 20 3d 20 73 65 6c 66 2e 6d 61 69 6e 4d 65 6e 75 2e 63 72 65 64 65 6e 74 69 61 6c 73 2e 67 65 74 5f 63 72 65 64 65 6e 74 69 61 6c 73 28 63 72 65 64 49 44 29 5b 30 5d}
		$s1 = {63 6f 6d 6d 61 6e 64 20 3d 20 22 73 65 6b 75 72 6c 73 61 3a 3a 70 74 68 20 2f 75 73 65 72 3a 22 2b 73 65 6c 66 2e 6f 70 74 69 6f 6e 73 5b 22 75 73 65 72 22 5d 5b 27 56 61 6c 75 65 27 5d}

	condition:
		filesize < 12KB and all of them
}

rule Empire_Write_HijackDll : hardened
{
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file Write-HijackDll.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/PowerShellEmpire/Empire"
		date = "2015-08-06"
		score = 70
		hash = "155fa7168e28f15bb34f67344f47234a866e2c63b3303422ff977540623c70bf"
		id = "6a80af21-fb01-5996-b14d-44ff55b7fb3e"

	strings:
		$s1 = {24 44 6c 6c 42 79 74 65 73 20 3d 20 49 6e 76 6f 6b 65 2d 50 61 74 63 68 44 6c 6c 20 2d 44 6c 6c 42 79 74 65 73 20 24 44 6c 6c 42 79 74 65 73 20 2d 46 69 6e 64 53 74 72 69 6e 67 20 22 64 65 62 75 67 2e 62 61 74 22 20 2d 52 65 70 6c 61 63 65 53 74 72 69 6e 67 20 24 42 61 74 63 68 50 61 74 68}
		$s2 = {24 44 6c 6c 42 79 74 65 73 33 32 20 3d 20 22 54 56 71 51 41 41 4d 41 41 41 41 45 41 41 41 41 2f 2f 38 41 41 4c 67 41 41 41 41 41 41 41 41 41 51 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 34 41 41 41 41 41 34 66 75 67 34 41 74 41 6e 4e 49 62 67 42 54 4d 30 68 56 47 68 70 63 79 42 77}
		$s3 = {5b 42 79 74 65 5b 5d 5d 24 44 6c 6c 42 79 74 65 73 20 3d 20 5b 42 79 74 65 5b 5d 5d 5b 43 6f 6e 76 65 72 74 5d 3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 24 44 6c 6c 42 79 74 65 73 33 32 29}

	condition:
		filesize < 500KB and 2 of them
}

rule Empire_skeleton_key : hardened
{
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file skeleton_key.py"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/PowerShellEmpire/Empire"
		date = "2015-08-06"
		score = 70
		hash = "3d02f16dcc38faaf5e97e4c5dbddf761f2816004775e6af8826cde9e29bb750f"
		id = "d508e09e-13e8-5866-bb5b-0d886f960bb5"

	strings:
		$s1 = {73 63 72 69 70 74 20 2b 3d 20 22 49 6e 76 6f 6b 65 2d 4d 69 6d 69 6b 61 74 7a 20 2d 43 6f 6d 6d 61 6e 64 20 27 5c 5c 22 22 20 2b 20 63 6f 6d 6d 61 6e 64 20 2b 20 22 5c 5c 22 27 3b 22}
		$s2 = {73 63 72 69 70 74 20 2b 3d 20 27 22 53 6b 65 6c 65 74 6f 6e 20 6b 65 79 20 69 6d 70 6c 61 6e 74 65 64 2e 20 55 73 65 20 70 61 73 73 77 6f 72 64 20 5c 27 6d 69 6d 69 6b 61 74 7a 5c 27 20 66 6f 72 20 61 63 63 65 73 73 2e 22 27}
		$s3 = {63 6f 6d 6d 61 6e 64 20 3d 20 22 6d 69 73 63 3a 3a 73 6b 65 6c 65 74 6f 6e 22}
		$s4 = {22 4f 4e 4c 59 20 41 50 50 4c 49 43 41 42 4c 45 20 4f 4e 20 44 4f 4d 41 49 4e 20 43 4f 4e 54 52 4f 4c 4c 45 52 53 21 22 29 2c}

	condition:
		filesize < 6KB and 2 of them
}

rule Empire_invoke_wmi : hardened
{
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file invoke_wmi.py"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/PowerShellEmpire/Empire"
		date = "2015-08-06"
		score = 70
		hash = "a914cb227f652734a91d3d39745ceeacaef7a8b5e89c1beedfd6d5f9b4615a1d"
		id = "1e1d1e71-6ea9-500a-b8b8-c48a64bc2b54"

	strings:
		$s1 = {28 63 72 65 64 49 44 2c 20 63 72 65 64 54 79 70 65 2c 20 64 6f 6d 61 69 6e 4e 61 6d 65 2c 20 75 73 65 72 4e 61 6d 65 2c 20 70 61 73 73 77 6f 72 64 2c 20 68 6f 73 74 2c 20 73 69 64 2c 20 6e 6f 74 65 73 29 20 3d 20 73 65 6c 66 2e 6d 61 69 6e 4d 65 6e 75 2e 63 72 65 64 65 6e 74 69 61 6c 73 2e 67 65 74 5f 63 72 65 64 65 6e 74 69 61 6c 73 28 63 72 65 64 49 44 29 5b 30 5d}
		$s2 = {73 63 72 69 70 74 20 2b 3d 20 22 3b 27 49 6e 76 6f 6b 65 2d 57 6d 69 20 65 78 65 63 75 74 65 64 20 6f 6e 20 22 20 2b 63 6f 6d 70 75 74 65 72 4e 61 6d 65 73 20 2b 22 27 22}
		$s3 = {73 63 72 69 70 74 20 3d 20 22 24 50 53 50 61 73 73 77 6f 72 64 20 3d 20 5c 5c 22 22 2b 70 61 73 73 77 6f 72 64 2b 22 5c 5c 22 20 7c 20 43 6f 6e 76 65 72 74 54 6f 2d 53 65 63 75 72 65 53 74 72 69 6e 67 20 2d 61 73 50 6c 61 69 6e 54 65 78 74 20 2d 46 6f 72 63 65 3b 24 43 72 65 64 65 6e 74 69 61 6c 20 3d 20 4e 65 77 2d 4f 62 6a 65 63 74 20 53 79 73 74 65 6d 2e 4d 61 6e}

	condition:
		filesize < 20KB and 2 of them
}

