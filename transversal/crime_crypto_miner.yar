rule SUSP_LNX_SH_CryptoMiner_Indicators_Dec20_1 : hardened
{
	meta:
		description = "Detects helper script used in a crypto miner campaign"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.intezer.com/blog/research/new-golang-worm-drops-xmrig-miner-on-servers/"
		date = "2020-12-31"
		hash1 = "3298dbd985c341d57e3219e80839ec5028585d0b0a737c994363443f4439d7a5"
		id = "e376e0e1-1490-5ad4-8ca2-d28ca1c0b51a"

	strings:
		$x1 = {6d 69 6e 65 72 20 72 75 6e 6e 69 6e 67}
		$x2 = {6d 69 6e 65 72 20 72 75 6e 69 6e 67}
		$x3 = {20 2d 2d 64 6f 6e 61 74 65 2d 6c 65 76 65 6c 20 31 20}
		$x4 = {20 2d 6f 20 70 6f 6f 6c 2e 6d 69 6e 65 78 6d 72 2e 63 6f 6d 3a 35 35 35 35 20}

	condition:
		filesize < 20KB and 1 of them
}

rule PUA_WIN_XMRIG_CryptoCoin_Miner_Dec20 : hardened
{
	meta:
		description = "Detects XMRIG crypto coin miners"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.intezer.com/blog/research/new-golang-worm-drops-xmrig-miner-on-servers/"
		date = "2020-12-31"
		hash1 = "b6154d25b3aa3098f2cee790f5de5a727fc3549865a7aa2196579fe39a86de09"
		id = "4dfb04e9-fbba-5a6f-ad20-d805025d2d74"

	strings:
		$x1 = {78 00 6d 00 72 00 69 00 67 00 2e 00 65 00 78 00 65 00}
		$x2 = {78 00 6d 00 72 00 69 00 67 00 2e 00 63 00 6f 00 6d 00}
		$x3 = {2a 20 66 6f 72 20 78 38 36 2c 20 43 52 59 50 54 4f 47 41 4d 53}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 6000KB and 2 of them or all of them
}

