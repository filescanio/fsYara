rule WinPayloads_PowerShell : hardened limited
{
	meta:
		description = "Detects WinPayloads PowerShell Payload"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/nccgroup/Winpayloads"
		date = "2017-07-11"
		hash1 = "011eba8f18b66634f6eb47527b4ceddac2ae615d6861f89a35dbb9fc591cae8e"
		id = "8b6b8823-4656-5b0d-9a1e-84045287f5bf"

	strings:
		$x1 = {24 42 61 73 65 36 34 43 65 72 74 20 3d 20 27 4d 49 49 4a 65 51 49 42 41 7a 43 43 43 54 38 47 43 53 71 47 53 49 62 33 44 51 45 48 41 61 43 43 43 54 41 45 67 67 6b 73 4d 49 49 4a 4b 44 43 43 41 39 38 47 43 53 71 47 53 49 62 33 44 51 45 48 42 71 43 43 41 39 41 77 67 67 50 4d 41 67 45 41 4d 49 49 44 78 51 59 4a 4b 6f 5a 49 68 76 63 4e 41 51 63 42 4d 42 77 47 43 69 71 47 53 49 62 33 44}
		$x2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 70 6f 77 65 72 73 68 65 6c 6c 20 2d 77 20 68 69 64 64 65 6e 20 2d 6e 6f 6e 69 20 2d 65 6e 63 20 53 51 42 46 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$x3 = {53 51 42 46 41 46 67 41 49 41 41 6f 41 45 34 41 5a 51 42 33 41 43 30 41 54 77 42 69 41 47 6f 41 5a 51 42 6a 41 48 51 41 49 41 42 4f 41 47 55 41 64 41 41 75 41 46 63 41 5a 51 42 69 41 47 4d 41 62 41 42 70 41 47 55 41 62 67 42 30 41 43 6b 41 4c 67 42 45 41 47 38 41 64 77 42 75 41 47 77 41}
		$x4 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 65 6e 63 20 4a 41 42 6a 41 47 77 41 61 51 42 6c 41 47 34 41 64 41 41}

	condition:
		filesize < 10KB and 1 of them
}

rule WinPayloads_Payload : hardened limited
{
	meta:
		description = "Detects WinPayloads Payload"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/nccgroup/Winpayloads"
		date = "2017-07-11"
		super_rule = 1
		hash1 = "23a24f99c3c6c00cd4bf6cb968f813ba2ceadfa846c7f169f412bcbb71ba6573"
		hash2 = "35069905d9b7ba1fd57c8df03614f563504194e4684f47aafa08ebb8d9409d0b"
		hash3 = "a28d107f168d85c38fc76229b14561b472e60e60973eb10b6b554c1f57469322"
		hash4 = "ed93e28ca18f749a78678b1e8e8ac31f4c6c0bab2376d398b413dbdfd5af9c7f"
		hash5 = "26f5aee1ce65158e8375deb63c27edabfc9f5de3c1c88a4ce26a7e50b315b6d8"
		hash6 = "b25a515706085dbde0b98deaf647ef9a8700604652c60c6b706a2ff83fdcbf45"
		id = "44fae324-1fc8-5417-950a-8a3783b6d2ae"

	strings:
		$s1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 62 70 61 79 6c 6f 61 64 2e 65 78 65 2e 6d 61 6e 69 66 65 73 74 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 73 70 61 79 6c 6f 61 64 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 10000KB and all of them )
}

