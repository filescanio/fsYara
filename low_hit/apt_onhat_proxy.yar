rule ONHAT_Proxy_Hacktool : hardened limited
{
	meta:
		description = "Detects ONHAT Proxy - Htran like SOCKS hack tool used by Chinese APT groups"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/p32Ozf"
		date = "2016-05-12"
		score = 100
		hash1 = "30b2de0a802a65b4db3a14593126301e6949c1249e68056158b2cc74798bac97"
		hash2 = "94bda24559713c7b8be91368c5016fc7679121fea5d565d3d11b2bb5d5529340"
		hash3 = "a26e75fec3b9f7d5a1c3d0ce1e89e4b0befb7a601da0c69a4cf96301921771dd"
		hash4 = "c202e9d5b99f6137c7c07305c7314e55f52bae832d460c44efc8f2a90ff03615"
		hash5 = "dded62ad85c0bdd68bcc96f88d8ba42d5ad0ef999911ebdea3f561a4491ebbc6"
		hash6 = "f0954774c91603fc2595f0ba0727b9af4e80f6f9be7bb629e7fb6ba4309ed4ea"
		hash7 = "f3906be01d51e2e1ae9b03cd09702b6e0794b9c9fd7dc04024f897e96bb13232"
		hash8 = "f65ae9ccf988a06a152f27a4c0d7992100a2d9d23d80efe8d8c2a5c9bd78a3a7"
		id = "cb18a5b0-dbbd-5dd3-af66-21b8302df6de"

	strings:
		$s1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 49 4e 56 41 4c 49 44 20 50 41 52 41 4d 45 54 45 52 53 2e 20 54 59 50 45 20 4f 4e 48 41 54 2e 45 58 45 20 2d 68 20 46 4f 52 20 48 45 4c 50 20 49 4e 46 4f 52 4d 41 54 49 4f 4e 2e (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 5b 4f 4e 48 41 54 5d 20 4c 49 53 54 45 4e 53 20 28 53 2c 20 25 64 2e 25 64 2e 25 64 2e 25 64 2c 20 25 64 29 20 45 52 52 4f 52 2e (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 5b 4f 4e 48 41 54 5d 20 43 4f 4e 4e 45 43 54 53 20 28 54 2c 20 25 64 2e 25 64 2e 25 64 2e 25 64 2c 20 25 64 2e 25 64 2e 25 64 2e 25 64 2c 20 25 64 29 20 45 52 52 4f 52 2e (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 80KB and ( 1 of ( $s* ) ) ) or ( 2 of them )
}

