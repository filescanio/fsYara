rule kraken_cryptor_ransomware_loader : hardened limited
{
	meta:
		description = "Rule to detect the Kraken Cryptor Ransomware loader"
		author = "Marc Rivero | McAfee ATR Team"
		date = "2018-09-30"
		rule_version = "v1"
		malware_type = "ransomware"
		malware_family = "Ransom:W32/Kraken"
		actor_type = "Cybercrime"
		actor_group = "Unknown"
		reference = "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/fallout-exploit-kit-releases-the-kraken-ransomware-on-its-victims/"
		hash = "564154a2e3647318ca40a5ffa68d06b1bd40b606cae1d15985e3d15097b512cd"
		score = 90

	strings:
		$pdb = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 43 3a 5c 55 73 65 72 73 5c 4b 72 79 70 74 6f 6e 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 55 41 43 5c 55 41 43 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 55 41 43 2e 70 64 62 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s2 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 43 00 6c 00 61 00 73 00 73 00 65 00 73 00 5c 00 6d 00 73 00 63 00 66 00 69 00 6c 00 65 00 5c 00 73 00 68 00 65 00 6c 00 6c 00 5c 00 6f 00 70 00 65 00 6e 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 70 75 62 6c 69 63 5f 6b 65 79 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s4 = {4b 52 41 4b 45 4e 20 44 45 43 52 59 50 54 4f 52}
		$s5 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 55 4e 49 51 55 45 20 4b 45 59 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 600KB and $pdb or all of ( $s* )
}

rule kraken_cryptor_ransomware : hardened limited
{
	meta:
		description = "Rule to detect the Kraken Cryptor Ransomware"
		author = "Marc Rivero | McAfee ATR Team"
		date = "2018-09-30"
		rule_version = "v1"
		malware_type = "ransomware"
		malware_family = "Ransom:W32/Kraken"
		actor_type = "Cybercrime"
		actor_group = "Unknown"
		reference = "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/fallout-exploit-kit-releases-the-kraken-ransomware-on-its-victims/"
		hash = "564154a2e3647318ca40a5ffa68d06b1bd40b606cae1d15985e3d15097b512cd"

	strings:
		$s1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 4b 72 61 6b 65 6e 20 43 72 79 70 74 6f 72 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 73 75 70 70 6f 72 74 5f 65 6d 61 69 6c (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$fw1 = {4c 30 4d 67 62 6d 56 30 63 32 67 67 59 57 52 32 5a 6d 6c 79 5a 58 64 68 62 47 77 67 5a 6d 6c 79 5a 58 64 68 62 47 77 67 59 57 52 6b 49 48 4a 31 62 47 55 67 62 6d 46 74 5a 54 30 69 55 30 31 43 49 46 42 79 62 33 52 76 59 32 39 73 49 45 4a 73 62 32 4e 72 49 69 42 77 63 6d 39 30 62 32 4e 76 62 44 31 55 51 31 41 67 5a 47 6c 79 50 57 6c 75 49 47 78 76 59 32 46 73 63 47 39 79 64 44 30 30}
		$fw2 = {4c 30 4d 67 62 6d 56 30 63 32 67 67 59 57 52 32 5a 6d 6c 79 5a 58 64 68 62 47 77 67 5a 6d 6c 79 5a 58 64 68 62 47 77 67 59 57 52 6b 49 48 4a 31 62 47 55 67 62 6d 46 74 5a 54 30 69 55 6b 52 51 49 46 42 79 62 33 52 76 59 32 39 73 49 45 4a 73 62 32 4e 72 49 69 42 77 63 6d 39 30 62 32 4e 76 62 44 31 55 51 31 41 67 5a 47 6c 79 50 57 6c 75 49 47 78 76 59 32 46 73 63 47 39 79 64 44 30 7a}
		$fw3 = {4c 30 4d 67 62 6d 56 30 63 32 67 67 59 57 52 32 5a 6d 6c 79 5a 58 64 68 62 47 77 67 5a 6d 6c 79 5a 58 64 68 62 47 77 67 59 57 52 6b 49 48 4a 31 62 47 55 67 62 6d 46 74 5a 54 30 69 55 6b 52 51 49 46 42 79 62 33 52 76 59 32 39 73 49 45 4a 73 62 32 4e 72 49 69 42 77 63 6d 39 30 62 32 4e 76 62 44 31 55 51 31 41 67 5a 47 6c 79 50 57 6c 75 49 47 78 76 59 32 46 73 63 47 39 79 64 44 30 7a}
		$fw4 = {4c 30 4d 67 62 6d 56 30 63 32 67 67 59 57 52 32 5a 6d 6c 79 5a 58 64 68 62 47 77 67 5a 6d 6c 79 5a 58 64 68 62 47 77 67 59 57 52 6b 49 48 4a 31 62 47 55 67 62 6d 46 74 5a 54 30 69 55 30 31 43 49 46 42 79 62 33 52 76 59 32 39 73 49 45 4a 73 62 32 4e 72 49 69 42 77 63 6d 39 30 62 32 4e 76 62 44 31 55 51 31 41 67 5a 47 6c 79 50 57 6c 75 49 47 78 76 59 32 46 73 63 47 39 79 64 44 30 30}
		$uac = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 3c 21 2d 2d 3c 72 65 71 75 65 73 74 65 64 45 78 65 63 75 74 69 6f 6e 4c 65 76 65 6c 20 6c 65 76 65 6c 3d 22 61 73 49 6e 76 6f 6b 65 72 22 20 75 69 41 63 63 65 73 73 3d 22 66 61 6c 73 65 22 20 2f 3e 2d 2d 3e 20 20 20 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 600KB and ( all of ( $fw* ) or all of ( $s* ) or $uac )
}

rule ransom_note_kraken_cryptor_ransomware : hardened limited
{
	meta:
		description = "Rule to detect the ransom note delivered by Kraken Cryptor Ransomware"
		author = "Marc Rivero | McAfee ATR Team"
		date = "2018-09-30"
		rule_version = "v1"
		malware_type = "ransomware"
		malware_family = "Ransom:W32/Kraken"
		actor_type = "Cybercrime"
		actor_group = "Unknown"
		reference = "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/fallout-exploit-kit-releases-the-kraken-ransomware-on-its-victims/"

	strings:
		$s1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 4e 6f 20 77 61 79 20 74 6f 20 72 65 63 6f 76 65 72 79 20 79 6f 75 72 20 66 69 6c 65 73 20 77 69 74 68 6f 75 74 20 22 4b 52 41 4b 45 4e 20 44 45 43 52 59 50 54 4f 52 22 20 73 6f 66 74 77 61 72 65 20 61 6e 64 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 22 55 4e 49 51 55 45 20 4b 45 59 22 21 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 41 72 65 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 64 65 63 72 79 70 74 20 61 6c 6c 20 6f 66 20 79 6f 75 72 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 3f 20 49 66 20 79 65 73 21 20 59 6f 75 20 6e 65 65 64 20 74 6f 20 70 61 79 20 66 6f 72 20 64 65 63 72 79 70 74 69 6f 6e 20 73 65 72 76 69 63 65 20 74 6f 20 75 73 21 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 54 68 65 20 73 70 65 65 64 2c 20 70 6f 77 65 72 20 61 6e 64 20 63 6f 6d 70 6c 65 78 69 74 79 20 6f 66 20 74 68 69 73 20 65 6e 63 72 79 70 74 69 6f 6e 20 68 61 76 65 20 62 65 65 6e 20 68 69 67 68 20 61 6e 64 20 69 66 20 79 6f 75 20 61 72 65 20 6e 6f 77 20 76 69 65 77 69 6e 67 20 74 68 69 73 20 67 75 69 64 65 2e (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s4 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 50 72 6f 6a 65 63 74 20 22 4b 52 41 4b 45 4e 20 43 52 59 50 54 4f 52 22 20 64 6f 65 73 6e 27 74 20 64 61 6d 61 67 65 20 61 6e 79 20 6f 66 20 79 6f 75 72 20 66 69 6c 65 73 2c 20 74 68 69 73 20 61 63 74 69 6f 6e 20 69 73 20 72 65 76 65 72 73 69 62 6c 65 20 69 66 20 79 6f 75 20 66 6f 6c 6c 6f 77 20 74 68 65 20 69 6e 73 74 72 75 63 74 69 6f 6e 73 20 61 62 6f 76 65 2e (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s5 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 68 74 74 70 73 3a 2f 2f 6c 6f 63 61 6c 42 69 74 63 6f 69 6e 73 2e 63 6f 6d (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s6 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 46 6f 72 20 74 68 65 20 64 65 63 72 79 70 74 69 6f 6e 20 73 65 72 76 69 63 65 2c 20 77 65 20 61 6c 73 6f 20 6e 65 65 64 20 79 6f 75 72 20 22 4b 52 41 4b 45 4e 20 45 4e 43 52 59 50 54 45 44 20 55 4e 49 51 55 45 20 4b 45 59 22 20 79 6f 75 20 63 61 6e 20 73 65 65 20 74 68 69 73 20 69 6e 20 74 68 65 20 74 6f 70 21 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s7 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 2d 2d 2d 2d 2d 42 45 47 49 4e 20 4b 52 41 4b 45 4e 20 45 4e 43 52 59 50 54 45 44 20 55 4e 49 51 55 45 20 4b 45 59 2d 2d 2d 2d 2d 20 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s8 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 22 4b 52 41 4b 45 4e 20 43 52 59 50 54 4f 52 22 2e (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s9 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 49 74 20 6d 65 61 6e 73 20 74 68 61 74 20 22 4b 52 41 4b 45 4e 20 43 52 59 50 54 4f 52 22 20 69 6d 6d 65 64 69 61 74 65 6c 79 20 72 65 6d 6f 76 65 64 20 66 6f 72 6d 20 79 6f 75 72 20 73 79 73 74 65 6d 21 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s10 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 41 66 74 65 72 20 79 6f 75 72 20 70 61 79 6d 65 6e 74 20 6d 61 64 65 2c 20 61 6c 6c 20 6f 66 20 79 6f 75 72 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 20 68 61 73 20 62 65 65 6e 20 64 65 63 72 79 70 74 65 64 2e (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s11 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 44 6f 6e 27 74 20 64 65 6c 65 74 65 20 2e 58 4b 48 56 45 20 66 69 6c 65 73 21 20 74 68 65 72 65 20 61 72 65 20 6e 6f 74 20 76 69 72 75 73 20 61 6e 64 20 61 72 65 20 79 6f 75 72 20 66 69 6c 65 73 2c 20 62 75 74 20 65 6e 63 72 79 70 74 65 64 21 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s12 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 59 6f 75 20 63 61 6e 20 64 65 63 72 79 70 74 20 6f 6e 65 20 6f 66 20 79 6f 75 72 20 65 6e 63 72 79 70 74 65 64 20 73 6d 61 6c 6c 65 72 20 66 69 6c 65 20 66 6f 72 20 66 72 65 65 20 69 6e 20 74 68 65 20 66 69 72 73 74 20 63 6f 6e 74 61 63 74 20 77 69 74 68 20 75 73 2e (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s13 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 59 6f 75 20 6d 75 73 74 20 72 65 67 69 73 74 65 72 20 6f 6e 20 74 68 69 73 20 73 69 74 65 20 61 6e 64 20 63 6c 69 63 6b 20 22 42 55 59 20 42 69 74 63 6f 69 6e 73 22 20 74 68 65 6e 20 63 68 6f 6f 73 65 20 79 6f 75 72 20 63 6f 75 6e 74 72 79 20 74 6f 20 66 69 6e 64 20 73 65 6c 6c 65 72 73 20 61 6e 64 20 74 68 65 69 72 20 70 72 69 63 65 73 2e (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s14 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 2d 2d 2d 2d 2d 45 4e 44 20 4b 52 41 4b 45 4e 20 45 4e 43 52 59 50 54 45 44 20 55 4e 49 51 55 45 20 4b 45 59 2d 2d 2d 2d 2d (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s15 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 44 4f 4e 27 54 20 4d 4f 44 49 46 59 20 22 4b 52 41 4b 45 4e 20 45 4e 43 52 59 50 54 20 55 4e 49 51 55 45 20 4b 45 59 22 2e (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s16 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 23 20 52 65 61 64 20 74 68 65 20 66 6f 6c 6c 6f 77 69 6e 67 20 69 6e 73 74 72 75 63 74 69 6f 6e 73 20 63 61 72 65 66 75 6c 6c 79 20 74 6f 20 64 65 63 72 79 70 74 20 79 6f 75 72 20 66 69 6c 65 73 2e (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s17 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 57 65 20 75 73 65 20 62 65 73 74 20 61 6e 64 20 65 61 73 79 20 77 61 79 20 74 6f 20 63 6f 6d 6d 75 6e 69 63 61 74 69 6f 6e 73 2e 20 49 74 27 73 20 65 6d 61 69 6c 20 73 75 70 70 6f 72 74 2c 20 79 6f 75 20 63 61 6e 20 73 65 65 20 6f 75 72 20 65 6d 61 69 6c 73 20 62 65 6c 6f 77 2e (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s18 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 44 4f 4e 27 54 20 55 53 45 20 54 48 49 52 44 20 50 41 52 54 59 2c 20 50 55 42 4c 49 43 20 54 4f 4f 4c 53 2f 53 4f 46 54 57 41 52 45 20 54 4f 20 44 45 43 52 59 50 54 20 59 4f 55 52 20 46 49 4c 45 53 2c 20 54 48 49 53 20 43 41 55 53 45 20 44 41 4d 41 47 45 20 59 4f 55 52 20 46 49 4c 45 53 20 50 45 52 4d 41 4e 45 4e 54 4c 59 2e (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s19 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 68 74 74 70 73 3a 2f 2f 65 6e 2e 77 69 6b 69 70 65 64 69 61 2e 6f 72 67 2f 77 69 6b 69 2f 42 69 74 63 6f 69 6e (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s20 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 50 6c 65 61 73 65 20 73 65 6e 64 20 79 6f 75 72 20 6d 65 73 73 61 67 65 20 77 69 74 68 20 73 61 6d 65 20 73 75 62 6a 65 63 74 20 74 6f 20 62 6f 74 68 20 61 64 64 72 65 73 73 2e (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		uint16( 0 ) == 0x4120 and filesize < 9KB and all of them
}

