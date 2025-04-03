rule Invoke_SMBExec : hardened limited
{
	meta:
		description = "Detects Invoke-WmiExec or Invoke-SmbExec"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/Kevin-Robertson/Invoke-TheHash"
		date = "2017-06-14"
		hash1 = "674fc045dc198874f323ebdfb9e9ff2f591076fa6fac8d1048b5b8d9527c64cd"
		id = "07c742f4-3039-5c84-81d4-73ad25b98681"

	strings:
		$x1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 49 6e 76 6f 6b 65 2d 53 4d 42 45 78 65 63 20 2d 54 61 72 67 65 74 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$x2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 24 70 61 63 6b 65 74 5f 53 4d 42 5f 68 65 61 64 65 72 20 3d 20 47 65 74 2d 50 61 63 6b 65 74 53 4d 42 48 65 61 64 65 72 20 30 78 37 31 20 30 78 31 38 20 30 78 30 37 2c 30 78 63 38 20 24 53 4d 42 5f 74 72 65 65 5f 49 44 20 24 70 72 6f 63 65 73 73 5f 49 44 5f 62 79 74 65 73 20 24 53 4d 42 5f 75 73 65 72 5f 49 44 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 57 72 69 74 65 2d 4f 75 74 70 75 74 20 22 43 6f 6d 6d 61 6e 64 20 65 78 65 63 75 74 65 64 20 77 69 74 68 20 73 65 72 76 69 63 65 20 24 53 4d 42 5f 73 65 72 76 69 63 65 20 6f 6e 20 24 54 61 72 67 65 74 22 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 24 70 61 63 6b 65 74 5f 52 50 43 5f 64 61 74 61 20 3d 20 47 65 74 2d 50 61 63 6b 65 74 52 50 43 42 69 6e 64 20 31 20 30 78 62 38 2c 30 78 31 30 20 30 78 30 31 20 30 78 30 30 2c 30 78 30 30 20 24 53 4d 42 5f 6e 61 6d 65 64 5f 70 69 70 65 5f 55 55 49 44 20 30 78 30 32 2c 30 78 30 30 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 24 53 4d 42 5f 6e 61 6d 65 64 5f 70 69 70 65 5f 62 79 74 65 73 20 3d 20 30 78 37 33 2c 30 78 30 30 2c 30 78 37 36 2c 30 78 30 30 2c 30 78 36 33 2c 30 78 30 30 2c 30 78 36 33 2c 30 78 30 30 2c 30 78 37 34 2c 30 78 30 30 2c 30 78 36 63 2c 30 78 30 30 20 23 20 5c 73 76 63 63 74 6c (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		( filesize < 400KB and 1 of them )
}

rule Invoke_WMIExec_Gen_1 : hardened limited
{
	meta:
		description = "Detects Invoke-WmiExec or Invoke-SmbExec"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/Kevin-Robertson/Invoke-TheHash"
		date = "2017-06-14"
		hash1 = "140c23514dbf8043b4f293c501c2f9046efcc1c08630621f651cfedb6eed8b97"
		hash2 = "7565d376665e3cd07d859a5cf37c2332a14c08eb808cc5d187a7f0533dc69e07"
		id = "08b79c7d-c383-5891-af0f-31a92f1ed07d"
		score = 60

	strings:
		$x1 = {49 6e 76 6f 6b 65 2d 57 4d 49 45 78 65 63 20}
		$x2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 24 74 61 72 67 65 74 5f 63 6f 75 6e 74 20 3d 20 5b 53 79 73 74 65 6d 2e 6d 61 74 68 5d 3a 3a 50 6f 77 28 32 2c 28 28 24 74 61 72 67 65 74 5f 61 64 64 72 65 73 73 2e 47 65 74 41 64 64 72 65 73 73 42 79 74 65 73 28 29 2e 4c 65 6e 67 74 68 20 2a 20 38 29 20 2d 20 24 73 75 62 6e 65 74 5f 6d 61 73 6b 5f 73 70 6c 69 74 29 29 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 49 6d 70 6f 72 74 2d 4d 6f 64 75 6c 65 20 24 50 57 44 5c 49 6e 76 6f 6b 65 2d 54 68 65 48 61 73 68 2e 70 73 31 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 49 6d 70 6f 72 74 2d 4d 6f 64 75 6c 65 20 24 50 57 44 5c 49 6e 76 6f 6b 65 2d 53 4d 42 43 6c 69 65 6e 74 2e 70 73 31 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 24 74 61 72 67 65 74 5f 61 64 64 72 65 73 73 5f 6c 69 73 74 20 3d 20 5b 53 79 73 74 65 6d 2e 4e 65 74 2e 44 6e 73 5d 3a 3a 47 65 74 48 6f 73 74 45 6e 74 72 79 28 24 74 61 72 67 65 74 5f 6c 6f 6e 67 29 2e 41 64 64 72 65 73 73 4c 69 73 74 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$x4 = {49 6e 76 6f 6b 65 2d 53 4d 42 43 6c 69 65 6e 74 20 2d 44 6f 6d 61 69 6e 20 54 45 53 54 44 4f 4d 41 49 4e 20 2d 55 73 65 72 6e 61 6d 65 20 54 45 53 54 20 2d 48 61 73 68 20 46 36 46 33 38 42 37 39 33 44 42 36 41 39 34 42 41 30 34 41 35 32 46 31 44 33 45 45 39 32 46 30}

	condition:
		1 of them
}

rule Invoke_SMBExec_Invoke_WMIExec_1 : hardened limited
{
	meta:
		description = "Auto-generated rule - from files Invoke-SMBExec.ps1, Invoke-WMIExec.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/Kevin-Robertson/Invoke-TheHash"
		date = "2017-06-14"
		super_rule = 1
		hash1 = "674fc045dc198874f323ebdfb9e9ff2f591076fa6fac8d1048b5b8d9527c64cd"
		hash2 = "b41bd54bbf119d153e0878696cd5a944cbd4316c781dd8e390507b2ec2d949e7"
		id = "fd1c6599-028d-5535-beb8-5b2658481b97"

	strings:
		$s1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 24 70 72 6f 63 65 73 73 5f 49 44 20 3d 20 24 70 72 6f 63 65 73 73 5f 49 44 20 2d 72 65 70 6c 61 63 65 20 22 2d 30 30 2d 30 30 22 2c 22 22 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 57 72 69 74 65 2d 4f 75 74 70 75 74 20 22 24 54 61 72 67 65 74 20 64 69 64 20 6e 6f 74 20 72 65 73 70 6f 6e 64 22 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 5b 42 79 74 65 5b 5d 5d 24 70 61 63 6b 65 74 5f 63 61 6c 6c 5f 49 44 5f 62 79 74 65 73 20 3d 20 5b 53 79 73 74 65 6d 2e 42 69 74 43 6f 6e 76 65 72 74 65 72 5d 3a 3a 47 65 74 42 79 74 65 73 28 24 70 61 63 6b 65 74 5f 63 61 6c 6c 5f 49 44 29 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		all of them
}

rule Invoke_WMIExec_Gen : hardened limited
{
	meta:
		description = "Auto-generated rule - from files Invoke-SMBClient.ps1, Invoke-SMBExec.ps1, Invoke-WMIExec.ps1, Invoke-WMIExec.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/Kevin-Robertson/Invoke-TheHash"
		date = "2017-06-14"
		super_rule = 1
		hash1 = "56c6012c36aa863663fe5536d8b7fe4c460565d456ce2277a883f10d78893c01"
		hash2 = "674fc045dc198874f323ebdfb9e9ff2f591076fa6fac8d1048b5b8d9527c64cd"
		hash3 = "b41bd54bbf119d153e0878696cd5a944cbd4316c781dd8e390507b2ec2d949e7"
		id = "08b79c7d-c383-5891-af0f-31a92f1ed07d"

	strings:
		$s1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 24 4e 54 4c 4d 76 32 5f 68 61 73 68 20 3d 20 24 48 4d 41 43 5f 4d 44 35 2e 43 6f 6d 70 75 74 65 48 61 73 68 28 24 75 73 65 72 6e 61 6d 65 5f 61 6e 64 5f 74 61 72 67 65 74 5f 62 79 74 65 73 29 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 24 63 6c 69 65 6e 74 5f 63 68 61 6c 6c 65 6e 67 65 20 3d 20 5b 53 74 72 69 6e 67 5d 28 31 2e 2e 38 20 7c 20 46 6f 72 45 61 63 68 2d 4f 62 6a 65 63 74 20 7b 22 7b 30 3a 58 32 7d 22 20 2d 66 20 28 47 65 74 2d 52 61 6e 64 6f 6d 20 2d 4d 69 6e 69 6d 75 6d 20 31 20 2d 4d 61 78 69 6d 75 6d 20 32 35 35 29 7d 29 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 24 4e 54 4c 4d 5f 68 61 73 68 5f 62 79 74 65 73 20 3d 20 24 4e 54 4c 4d 5f 68 61 73 68 5f 62 79 74 65 73 2e 53 70 6c 69 74 28 22 2d 22 29 20 7c 20 46 6f 72 45 61 63 68 2d 4f 62 6a 65 63 74 7b 5b 43 68 61 72 5d 5b 53 79 73 74 65 6d 2e 43 6f 6e 76 65 72 74 5d 3a 3a 54 6f 49 6e 74 31 36 28 24 5f 2c 31 36 29 7d (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		all of them
}

