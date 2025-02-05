rule SUSP_Base64_Encoded_Hex_Encoded_Code : hardened
{
	meta:
		author = "Florian Roth (Nextron Systems)"
		description = "Detects hex encoded code that has been base64 encoded"
		date = "2019-04-29"
		score = 65
		reference = "https://www.nextron-systems.com/2019/04/29/spotlight-threat-hunting-yara-rule-example/"
		id = "2cfd278f-ff45-5e23-b552-dad688ab303b"

	strings:
		$x1 = { 78 34 4e ?? ?? 63 65 44 ?? ?? 58 48 67 }
		$x2 = { 63 45 44 ?? ?? 58 48 67 ?? ?? ?? 78 34 4e }
		$fp1 = {4d 69 63 72 6f 73 6f 66 74 20 41 7a 75 72 65 20 43 6f 64 65 20 53 69 67 6e 70 24}

	condition:
		1 of ( $x* ) and not 1 of ( $fp* )
}

rule SUSP_Double_Base64_Encoded_Executable : hardened
{
	meta:
		description = "Detects an executable that has been encoded with base64 twice"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/TweeterCyber/status/1189073238803877889"
		date = "2019-10-29"
		hash1 = "1a172d92638e6fdb2858dcca7a78d4b03c424b7f14be75c2fd479f59049bc5f9"
		id = "6fb40ed3-1afc-5d5b-9373-4a8490177b20"
		score = 75

	strings:
		$ = {((56 46 5a 77 56 45 46 52 52) | (56 00 46 00 5a 00 77 00 56 00 45 00 46 00 52 00 52 00))}
		$ = {((52 57 63 46 52 42 55 55) | (52 00 57 00 63 00 46 00 52 00 42 00 55 00 55 00))}
		$ = {((55 56 6e 42 55 51 56 46 46) | (55 00 56 00 6e 00 42 00 55 00 51 00 56 00 46 00 46 00))}
		$ = {((56 46 5a 76 51 55 46 42 51) | (56 00 46 00 5a 00 76 00 51 00 55 00 46 00 42 00 51 00))}
		$ = {((52 57 62 30 46 42 51 55) | (52 00 57 00 62 00 30 00 46 00 42 00 51 00 55 00))}
		$ = {((55 56 6d 39 42 51 55 46 42) | (55 00 56 00 6d 00 39 00 42 00 51 00 55 00 46 00 42 00))}
		$ = {((56 46 5a 78 51 55 46 42 52) | (56 00 46 00 5a 00 78 00 51 00 55 00 46 00 42 00 52 00))}
		$ = {((52 57 63 55 46 42 51 55) | (52 00 57 00 63 00 55 00 46 00 42 00 51 00 55 00))}
		$ = {((55 56 6e 46 42 51 55 46 46) | (55 00 56 00 6e 00 46 00 42 00 51 00 55 00 46 00 46 00))}
		$ = {((56 46 5a 77 55 55 46 42 53) | (56 00 46 00 5a 00 77 00 55 00 55 00 46 00 42 00 53 00))}
		$ = {((52 57 63 46 46 42 51 55) | (52 00 57 00 63 00 46 00 46 00 42 00 51 00 55 00))}
		$ = {((55 56 6e 42 52 51 55 46 4a) | (55 00 56 00 6e 00 42 00 52 00 51 00 55 00 46 00 4a 00))}
		$ = {((56 46 5a 78 55 55 46 42 54) | (56 00 46 00 5a 00 78 00 55 00 55 00 46 00 42 00 54 00))}
		$ = {((52 57 63 56 46 42 51 55) | (52 00 57 00 63 00 56 00 46 00 42 00 51 00 55 00))}
		$ = {((55 56 6e 46 52 51 55 46 4e) | (55 00 56 00 6e 00 46 00 52 00 51 00 55 00 46 00 4e 00))}

	condition:
		1 of them
}

rule SUSP_Reversed_Base64_Encoded_EXE : FILE hardened
{
	meta:
		description = "Detects an base64 encoded executable with reversed characters"
		author = "Florian Roth (Nextron Systems)"
		date = "2020-04-06"
		reference = "Internal Research"
		score = 80
		hash1 = "7e6d9a5d3b26fd1af7d58be68f524c4c55285b78304a65ec43073b139c9407a8"
		id = "3b52e59e-7c0a-560f-8123-1099c52e7e3d"

	strings:
		$s1 = {41 45 41 41 41 41 45 51 41 54 70 56 54}
		$s2 = {41 41 41 41 41 41 41 41 41 41 6f 56 54}
		$s3 = {41 45 41 41 41 41 45 41 41 41 71 56 54}
		$s4 = {41 45 41 41 41 41 49 41 41 51 70 56 54}
		$s5 = {41 45 41 41 41 41 4d 41 41 51 71 56 54}
		$sh1 = {53 5a 6b 39 57 62 67 4d 31 54 45 42 69 62 70 42 69 62 31 4a 48 49 6c 4a 47 49 30 39 6d 62 75 46 32 59 67 30 57 59 79 64 32 62 79 42 48 49 7a 6c 47 61 55}
		$sh2 = {4c 6c 52 32 62 74 42 79 55 50 52 45 49 75 6c 47 49 75 56 6e 63 67 55 6d 59 67 51 33 62 75 35 57 59 6a 42 53 62 68 4a 33 5a 76 4a 48 63 67 4d 58 61 6f 52}
		$sh3 = {75 55 47 5a 76 31 47 49 54 39 45 52 67 34 57 61 67 34 57 64 79 42 53 5a 69 42 43 64 76 35 6d 62 68 4e 47 49 74 46 6d 63 6e 39 6d 63 77 42 79 63 70 68 47 56}

	condition:
		filesize < 10000KB and 1 of them
}

rule SUSP_Script_Base64_Blocks_Jun20_1 : hardened
{
	meta:
		description = "Detects suspicious file with base64 encoded payload in blocks"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://posts.specterops.io/covenant-v0-5-eee0507b85ba"
		date = "2020-06-05"
		score = 70
		id = "cef759a5-b02a-53e7-bf27-184eee6bc3fa"

	strings:
		$sa1 = {3c 73 63 72 69 70 74 20 6c 61 6e 67 75 61 67 65 3d}
		$sb2 = { 41 41 41 22 2B 0D 0A 22 41 41 41 }

	condition:
		all of them
}

rule SUSP_Reversed_Hacktool_Author : FILE hardened
{
	meta:
		description = "Detects a suspicious path traversal into a Windows folder"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://hackingiscool.pl/cmdhijack-command-argument-confusion-with-path-traversal-in-cmd-exe/"
		date = "2020-06-10"
		score = 65
		id = "33e20d75-af07-5df2-82c3-c48aec37a947"

	strings:
		$x1 = {((69 77 69 6b 6c 69 74 6e 65 67) | (69 00 77 00 69 00 6b 00 6c 00 69 00 74 00 6e 00 65 00 67 00))}
		$x2 = {((20 65 65 74 62 75 73 40 20) | (20 00 65 00 65 00 74 00 62 00 75 00 73 00 40 00 20 00))}

	condition:
		filesize < 4000KB and 1 of them
}

rule SUSP_Base64_Encoded_Hacktool_Dev : hardened
{
	meta:
		description = "Detects a suspicious base64 encoded keyword"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/cyb3rops/status/1270626274826911744"
		date = "2020-06-10"
		score = 65
		id = "6dc7db4b-a614-51e4-a9a5-f869154dbbb1"

	strings:
		$ = {((51 47 64 6c 62 6e 52 70 62 47 74 70 64 32) | (51 00 47 00 64 00 6c 00 62 00 6e 00 52 00 70 00 62 00 47 00 74 00 70 00 64 00 32 00))}
		$ = {((42 6e 5a 57 35 30 61 57 78 72 61 58 64 70) | (42 00 6e 00 5a 00 57 00 35 00 30 00 61 00 57 00 78 00 72 00 61 00 58 00 64 00 70 00))}
		$ = {((41 5a 32 56 75 64 47 6c 73 61 32 6c 33 61) | (41 00 5a 00 32 00 56 00 75 00 64 00 47 00 6c 00 73 00 61 00 32 00 6c 00 33 00 61 00))}
		$ = {((51 47 68 68 63 6d 31 71 4d 48) | (51 00 47 00 68 00 68 00 63 00 6d 00 31 00 71 00 4d 00 48 00))}
		$ = {((42 6f 59 58 4a 74 61 6a 42 35) | (42 00 6f 00 59 00 58 00 4a 00 74 00 61 00 6a 00 42 00 35 00))}
		$ = {((41 61 47 46 79 62 57 6f 77 65) | (41 00 61 00 47 00 46 00 79 00 62 00 57 00 6f 00 77 00 65 00))}
		$ = {((49 45 42 7a 64 57 4a 30 5a 57) | (49 00 45 00 42 00 7a 00 64 00 57 00 4a 00 30 00 5a 00 57 00))}
		$ = {((42 41 63 33 56 69 64 47 56 6c) | (42 00 41 00 63 00 33 00 56 00 69 00 64 00 47 00 56 00 6c 00))}
		$ = {((67 51 48 4e 31 59 6e 52 6c 5a) | (67 00 51 00 48 00 4e 00 31 00 59 00 6e 00 52 00 6c 00 5a 00))}

	condition:
		filesize < 6000KB and 1 of them
}

