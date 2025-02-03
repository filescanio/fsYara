rule p0wnedPowerCat : hardened
{
	meta:
		description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedPowerCat.cs"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/Cn33liz/p0wnedShell"
		date = "2017-01-14"
		hash1 = "6a3ba991d3b5d127c4325bc194b3241dde5b3a5853b78b4df1bce7cbe87c0fdf"
		id = "059a8e58-7b7e-582e-ba4a-80e4dffe9b5e"

	strings:
		$x1 = {4e 6f 77 20 69 66 20 77 65 20 70 6f 69 6e 74 20 46 69 72 65 66 6f 78 20 74 6f 20 68 74 74 70 3a 2f 2f 31 32 37 2e 30 2e 30 2e 31}
		$x2 = {70 6f 77 65 72 63 61 74 20 2d 6c 20 2d 76 20 2d 70}
		$x3 = {50 30 77 6e 65 64 4c 69 73 74 65 6e 65 72}
		$x4 = {45 6e 63 6f 64 65 64 50 61 79 6c 6f 61 64 2e 62 61 74}
		$x5 = {70 6f 77 65 72 63 61 74 20 2d 63 20}
		$x6 = {50 72 6f 67 72 61 6d 2e 50 30 77 6e 65 64 50 61 74 68 28 29}
		$x7 = {49 6e 76 6f 6b 65 2d 50 6f 77 65 72 53 68 65 6c 6c 54 63 70 4f 6e 65 4c 69 6e 65}

	condition:
		( uint16( 0 ) == 0x7375 and filesize < 150KB and 1 of them ) or ( 2 of them )
}

rule Hacktool_Strings_p0wnedShell : FILE hardened
{
	meta:
		description = "Detects strings found in Runspace Post Exploitation Toolkit"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth"
		reference = "https://github.com/Cn33liz/p0wnedShell"
		date = "2017-01-14"
		modified = "2023-02-10"
		hash1 = "e1f35310192416cd79e60dba0521fc6eb107f3e65741c344832c46e9b4085e60"
		nodeepdive = 1
		id = "0846039d-1e00-5224-9560-55ab18034d54"
		score = 60

	strings:
		$x1 = {49 6e 76 6f 6b 65 2d 54 6f 6b 65 6e 4d 61 6e 69 70 75 6c 61 74 69 6f 6e}
		$x2 = {77 69 6e 64 6f 77 73 2f 6d 65 74 65 72 70 72 65 74 65 72}
		$x3 = {6c 73 61 64 75 6d 70 3a 3a 64 63 73 79 6e 63}
		$x4 = {70 30 77 6e 65 64 53 68 65 6c 6c 78 38 36}
		$x5 = {70 30 77 6e 65 64 53 68 65 6c 6c 78 36 34}
		$x6 = {49 6e 76 6f 6b 65 5f 50 73 45 78 65 63 28 29}
		$x7 = {49 6e 76 6f 6b 65 2d 4d 69 6d 69 6b 61 74 7a}
		$x8 = {49 6e 76 6f 6b 65 5f 53 68 65 6c 6c 63 6f 64 65 28 29}
		$x9 = {49 6e 76 6f 6b 65 2d 52 65 66 6c 65 63 74 69 76 65 50 45 49 6e 6a 65 63 74 69 6f 6e}
		$fp1 = {53 00 65 00 6e 00 74 00 69 00 6e 00 65 00 6c 00 20 00 4c 00 61 00 62 00 73 00 2c 00 20 00 49 00 6e 00 63 00 2e 00}
		$fp2 = {((43 6f 70 79 72 69 67 68 74 20 45 6c 61 73 74 69 63 73 65 61 72 63 68 20 42 2e 56 2e) | (43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 45 00 6c 00 61 00 73 00 74 00 69 00 63 00 73 00 65 00 61 00 72 00 63 00 68 00 20 00 42 00 2e 00 56 00 2e 00))}
		$fp3 = {41 74 74 61 63 6b 20 49 6e 66 6f 72 6d 61 74 69 6f 6e 3a 20 49 6e 76 6f 6b 65 2d 4d 69 6d 69 6b 61 74 7a}
		$fp4 = {61 33 30 32 32 36 20 7c 7c 20 49 4e 44 49 43 41 54 4f 52 2d 53 48 45 4c 4c 43 4f 44 45 20 4d 65 74 61 73 70 6c 6f 69 74 20 77 69 6e 64 6f 77 73 2f 6d 65 74 65 72 70 72 65 74 65 72 20 73 74 61 67 65 20 74 72 61 6e 73 66 65 72 20 61 74 74 65 6d 70 74}
		$fp5 = {75 73 65 20 73 74 72 69 63 74}

	condition:
		filesize < 20MB and 1 of ( $x* ) and not 1 of ( $fp* )
}

rule p0wnedPotato : hardened
{
	meta:
		description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedPotato.cs"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/Cn33liz/p0wnedShell"
		date = "2017-01-14"
		hash1 = "aff2b694a01b48ef96c82daf387b25845abbe01073b76316f1aab3142fdb235b"
		id = "2c2378e3-b948-5325-9afd-76424a7130b1"

	strings:
		$x1 = {49 6e 76 6f 6b 65 2d 54 61 74 65 72}
		$x2 = {50 30 77 6e 65 64 4c 69 73 74 65 6e 65 72 2e 45 78 65 63 75 74 65 28 57 50 41 44 5f 50 72 6f 78 79 29 3b}
		$x3 = {20 2d 53 70 6f 6f 66 65 72 49 50 20}
		$x4 = {54 61 74 65 72 43 6f 6d 6d 61 6e 64 28 29}
		$x5 = {46 69 6c 65 4e 61 6d 65 20 3d 20 22 63 6d 64 2e 65 78 65 22 2c}

	condition:
		1 of them
}

rule p0wnedExploits : hardened
{
	meta:
		description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedExploits.cs"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/Cn33liz/p0wnedShell"
		date = "2017-01-14"
		hash1 = "54548e7848e742566f5596d8f02eca1fd2cbfeae88648b01efb7bab014b9301b"
		id = "9f754f5f-85e8-5b6f-bde2-566da4d39586"

	strings:
		$x1 = {50 73 68 65 6c 6c 2e 52 75 6e 50 53 43 6f 6d 6d 61 6e 64 28 57 68 6f 61 6d 69 29 3b}
		$x2 = {49 66 20 73 75 63 63 65 65 64 65 64 20 74 68 69 73 20 65 78 70 6c 6f 69 74 20 73 68 6f 75 6c 64 20 70 6f 70 75 70 20 61 20 53 79 73 74 65 6d 20 43 4d 44 20 53 68 65 6c 6c}

	condition:
		all of them
}

rule p0wnedShellx64 : hardened
{
	meta:
		description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedShellx64.exe"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/Cn33liz/p0wnedShell"
		date = "2017-01-14"
		modified = "2021-09-15"
		hash1 = "d8b4f5440627cf70fa0e0e19e0359b59e671885f8c1855517211ba331f48c449"
		id = "c9791804-4f08-5b7e-8d9d-37e2dfccec47"

	strings:
		$x1 = {4f 00 71 00 30 00 32 00 41 00 42 00 2b 00 4c 00 43 00 41 00 41 00 41 00 41 00 41 00 41 00 41 00 42 00 41 00 44 00 73 00 2f 00 51 00 6b 00 57 00 33 00 4c 00 69 00 4f 00 4c 00 51 00 42 00 75 00 52 00 55 00 73 00 51 00 52 00 31 00 48 00 37 00 33 00 31 00 67 00 48 00 4d 00 51 00 4f 00 6b 00 46 00 47 00 46 00 6e 00 76 00 76 00 72 00 64 00 70 00 2f 00 4f 00 34 00 73 00 70 00 36 00 74 00 6b 00 44 00 69 00 41 00 49 00 49 00 6a 00 68 00 41 00 72 00 79 00 75 00 34 00 7a 00 36 00 50 00 56 00 4f 00 74 00 78 00 48 00 75 00 58 00 7a 00 33 00 2f 00 78 00 54 00 36 00 58 00 39 00 7a 00 61 00 2f 00 44 00 66 00 2f 00 48 00 73 00 61 00 2f 00 4a 00 54 00 2f 00 39 00 50 00 6a 00 67 00 62 00 2f 00 2b 00 6b 00 50 00 50 00 68 00 76 00 39 00 53 00 6a 00 70 00 30 00 31 00 57 00 66 00}
		$x2 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 54 00 6f 00 6b 00 65 00 6e 00 4d 00 61 00 6e 00 69 00 70 00 75 00 6c 00 61 00 74 00 69 00 6f 00 6e 00}
		$x3 = {2d 00 43 00 72 00 65 00 61 00 74 00 65 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 22 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 22 00 20 00 2d 00 55 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 20 00 22 00 6e 00 74 00 20 00 61 00 75 00 74 00 68 00 6f 00 72 00 69 00 74 00 79 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 22 00}
		$x4 = {43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 53 00 68 00 65 00 6c 00 6c 00 20 00 77 00 69 00 74 00 68 00 20 00 4c 00 6f 00 63 00 61 00 6c 00 20 00 41 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00 20 00 70 00 72 00 69 00 76 00 69 00 6c 00 65 00 67 00 65 00 73 00 20 00 3a 00 29 00}
		$x5 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 73 00 68 00 65 00 6c 00 6c 00 63 00 6f 00 64 00 65 00 20 00 2d 00 50 00 61 00 79 00 6c 00 6f 00 61 00 64 00 20 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 2f 00 6d 00 65 00 74 00 65 00 72 00 70 00 72 00 65 00 74 00 65 00 72 00 2f 00 72 00 65 00 76 00 65 00 72 00 73 00 65 00 5f 00 68 00 74 00 74 00 70 00 73 00 20 00 2d 00 4c 00 68 00 6f 00 73 00 74 00 20 00}
		$fp1 = {((41 56 53 69 67 6e 61 74 75 72 65) | (41 00 56 00 53 00 69 00 67 00 6e 00 61 00 74 00 75 00 72 00 65 00))}

	condition:
		1 of ( $x* ) and not 1 of them
}

rule p0wnedListenerConsole : hardened
{
	meta:
		description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedListenerConsole.cs"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/Cn33liz/p0wnedShell"
		date = "2017-01-14"
		hash1 = "d2d84e65fad966a8556696fdaab5dc8110fc058c9e9caa7ea78aa00921ae3169"
		id = "77d13c34-3e15-5bc1-a100-f04be38cfb44"

	strings:
		$x1 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 5f 00 52 00 65 00 66 00 6c 00 65 00 63 00 74 00 69 00 76 00 65 00 50 00 45 00 49 00 6e 00 6a 00 65 00 63 00 74 00 69 00 6f 00 6e 00}
		$x5 = {70 00 30 00 77 00 6e 00 65 00 64 00 53 00 68 00 65 00 6c 00 6c 00 3e 00 20 00}
		$x6 = {52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 2e 00 47 00 65 00 74 00 5f 00 50 00 61 00 73 00 73 00 48 00 61 00 73 00 68 00 65 00 73 00}
		$s7 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 5f 00 43 00 72 00 65 00 64 00 65 00 6e 00 74 00 69 00 61 00 6c 00 73 00 50 00 68 00 69 00 73 00 68 00}
		$s8 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 5f 00 53 00 68 00 65 00 6c 00 6c 00 63 00 6f 00 64 00 65 00}
		$s9 = {52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 2e 00 49 00 6e 00 76 00 6f 00 6b 00 65 00 5f 00 54 00 6f 00 6b 00 65 00 6e 00 4d 00 61 00 6e 00 69 00 70 00 75 00 6c 00 61 00 74 00 69 00 6f 00 6e 00}
		$s10 = {52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 2e 00 50 00 6f 00 72 00 74 00 5f 00 53 00 63 00 61 00 6e 00}
		$s20 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 5f 00 50 00 6f 00 77 00 65 00 72 00 55 00 70 00}

	condition:
		1 of them
}

rule p0wnedBinaries : hardened
{
	meta:
		description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedBinaries.cs"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/Cn33liz/p0wnedShell"
		date = "2017-01-14"
		hash1 = "fd7014625b58d00c6e54ad0e587c6dba5d50f8ca4b0f162d5af3357c2183c7a7"
		id = "0c62dd3a-195c-5890-b262-2eb00c58f8c1"

	strings:
		$x1 = {4f 71 30 32 41 42 2b 4c 43 41 41 41 41 41 41 41 42 41 44 73 2f 51 6b 57 33 4c 69 4f 4c 51 42 75 52 55 73 51 52 31 48 37 33 31 67 48 4d 51 4f 6b 46 47 46 6e 76 76 72 64 70 2f 4f 34 73 70 36 74 6b 44 69 41 49 49 6a 68 41 72 79 75 34 7a 36 50 56 4f 74 78 48 75 58 7a 33 2f 78 54 36 58 39 7a 61 2f 44 66 2f 48 73 61 2f 4a 54 2f 39}
		$x2 = {77 70 6f 57 41 42 2b 4c 43 41 41 41 41 41 41 41 42 41 44 73 2f 51 65 79 4b 37 75 4f 42 59 68 4f 52 55 4e 49 65 6e 4c 2b 45 32 76 42 41 30 79 6d 70 48 33 65 72 59 34 66 38 54 74 65 33 54 70 62 55 69 59 39 59 52 62 63 47 4b 39 31 76 56 4b 74 72 2b 74 56 33 76 2f 42 2f 79 72 2f 6d 31 76 44 2f 2b 44 76 4e 4f 56 62 2b 56 2f 66}
		$x3 = {6d 6f 30 4d 41 42 2b 4c 43 41 41 41 41 41 41 41 42 41 44 73 58 51 6c 32 34 7a 71 75 33 59 71 58 49 49 36 69 39 72 2b 78 4a 34 41 41 43 55 34 53 5a 63 75 4a 6e 56 65 6e 66 2f 39 4f 78 62 48 45 41 63 52 77 63 51 47 75 36 32 4e 62 48 73 72 61 78 2f 49 77 2b 33 2f 68 50 35 62 2b 56 7a 75 48 2f 34 57 66 56 65 44 66 38 6e 39 38}
		$x4 = {4c 45 34 43 41 42 2b 4c 43 41 41 41 41 41 41 41 42 41 44 73 66 51 6d 57 32 7a 71 75 36 46 61 38 42 4d 37 44 2f 6a 66 32 68 52 6d 6b 4b 4e 75 56 6d 2f 54 74 39 7a 75 6e 6b 69 70 62 34 67 69 43 49 47 62 32 2f 70 72 68 46 55 74 35 68 56 65 2b 2f 73 4e 50 34 62 2b 70 56 76 77 50 6e 2b 4f 51 70 2f 4c 54 39 67 65 2f 2b}
		$x5 = {58 70 4d 43 41 42 2b 4c 43 41 41 41 41 41 41 41 42 41 44 73 66 51 65 57 49 7a 6d 4f 36 46 56 30 68 4b 41 6e 37 33 2b 78 4c 33 69 41 77 56 41 71 71 32 74 33 35 72 2f 74 6c 35 33 56 79 68 43 44 46 6f 51 33 59 37 7a 57 39 55 71 31 76 71 35 58 65 66 2f 43 54 2b 58 2f 35 39 62 77 46 7a 36 6e 4b 55 2f 6c 70 2b 38 50 2f}
		$x6 = {53 54 77 41 41 42 2b 4c 43 41 41 41 41 41 41 41 42 41 44 74 57 77 6d 79 36 79 6f 4f 33 59 71 58 67 4a 6a 5a 2f 38 5a 61 52 77 4e 67 78 2f 48 4e 66 58 2f 6f 37 71 71 55 6b 78 67 7a 43 4d 30 53 6d 4c 52 32 6a 48 42 51 7a 6b 63 34 45 6e 39 78 5a 62 76 48 55 75 53 4c 4d 6e 57 76 39 61 74 65 4b 2f 37 30 69 6c 53 74 52}
		$x7 = {6e 61 6d 65 73 70 61 63 65 20 70 30 77 6e 65 64 53 68 65 6c 6c}

	condition:
		1 of them
}

rule p0wnedAmsiBypass : hardened
{
	meta:
		description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedAmsiBypass.cs"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/Cn33liz/p0wnedShell"
		date = "2017-01-14"
		hash1 = "345e8e6f38b2914f4533c4c16421d372d61564a4275537e674a2ac3360b19284"
		id = "168af265-d3e9-59a2-b754-20d6c9a298b1"

	strings:
		$x1 = {50 72 6f 67 72 61 6d 2e 50 30 77 6e 65 64 50 61 74 68 28 29}
		$x2 = {6e 61 6d 65 73 70 61 63 65 20 70 30 77 6e 65 64 53 68 65 6c 6c}
		$x3 = {48 34 73 49 41 41 41 41 41 41 41 45 41 4f 31 59 66 58 52 55 78 33 57 66 6c 58 61 6c 46 61 7a 51 67 69 56 62 35 6e 4d 56 72 79 7a 78 49 62 47 72 74 2f 72 63 46 52 5a 49 61 31 43 51 59 45 46 43 51 6e 78 6f 74 55 68 50 32 70 58 33 51 33 33 37 48 70 59 6f 74 43 4b 72 50 64 62 6d 6f 51 51 6e 6b 4f 59 30 2b 42 51 43 4e 4b 52 70 65}

	condition:
		1 of them
}

rule p0wnedShell_outputs : hardened
{
	meta:
		description = "p0wnedShell Runspace Post Exploitation Toolkit - from files p0wnedShell.cs, p0wnedShell.cs"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/Cn33liz/p0wnedShell"
		date = "2017-01-14"
		super_rule = 1
		hash1 = "e1f35310192416cd79e60dba0521fc6eb107f3e65741c344832c46e9b4085e60"
		id = "c19fc14b-0c42-5dd1-bff2-ba75f4168d9c"

	strings:
		$s1 = {5b 2b 5d 20 46 6f 72 20 74 68 69 73 20 61 74 74 61 63 6b 20 74 6f 20 73 75 63 63 65 65 64 2c 20 79 6f 75 20 6e 65 65 64 20 74 6f 20 68 61 76 65 20 41 64 6d 69 6e 20 70 72 69 76 69 6c 65 67 65 73 2e}
		$s2 = {5b 2b 5d 20 54 68 69 73 20 69 73 20 6e 6f 74 20 61 20 76 61 6c 69 64 20 68 6f 73 74 6e 61 6d 65 2c 20 70 6c 65 61 73 65 20 74 72 79 20 61 67 61 69 6e}
		$s3 = {5b 2b 5d 20 46 69 72 73 74 20 72 65 74 75 72 6e 20 74 68 65 20 6e 61 6d 65 20 6f 66 20 6f 75 72 20 63 75 72 72 65 6e 74 20 64 6f 6d 61 69 6e 2e}

	condition:
		1 of them
}

