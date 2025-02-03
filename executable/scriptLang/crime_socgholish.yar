rule MAL_ZIP_SocGholish_Mar21_1 : zip js socgholish hardened
{
	meta:
		description = "Triggers on small zip files with typical SocGholish JS files in it"
		author = "Nils Kuhnert"
		date = "2021-03-29"
		hash = "4f6566c145be5046b6be6a43c64d0acae38cada5eb49b2f73135b3ac3d6ba770"
		hash = "54f756fbf8c20c76af7c9f538ff861690800c622d1c9db26eb3afedc50835b09"
		hash = "dfdbec1846b74238ba3cfb8c7580c64a0fa8b14b6ed2b0e0e951cc6a9202dd8d"
		id = "da35eefd-b34d-59cd-8afc-da9c78ace96e"

	strings:
		$a1 = /\.[a-z0-9]{6}\.js/ ascii
		$a2 = {43 68 72 6f 6d 65}
		$a3 = {4f 70 65 72 61}
		$b1 = {46 69 72 65 66 6f 78 2e 6a 73}
		$b2 = {45 64 67 65 2e 6a 73}

	condition:
		uint16( 0 ) == 0x4b50 and filesize < 1600 and ( 2 of ( $a* ) or any of ( $b* ) )
}

rule EXT_MAL_JS_SocGholish_Mar21_1 : js socgholish hardened
{
	meta:
		description = "Triggers on SocGholish JS files"
		author = "Nils Kuhnert"
		date = "2021-03-29"
		modified = "2023-01-02"
		hash = "7ccbdcde5a9b30f8b2b866a5ca173063dec7bc92034e7cf10e3eebff017f3c23"
		hash = "f6d738baea6802cbbb3ae63b39bf65fbd641a1f0d2f0c819a8c56f677b97bed1"
		hash = "c7372ffaf831ad963c0a9348beeaadb5e814ceeb878a0cc7709473343d63a51c"
		id = "3ed7d2da-569b-5851-a821-4a3cda3e13ce"

	strings:
		$s1 = {6e 65 77 20 41 63 74 69 76 65 58 4f 62 6a 65 63 74 28 27 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 27 29 3b}
		$s2 = {5b 27 44 65 6c 65 74 65 46 69 6c 65 27 5d}
		$s3 = {5b 27 57 53 63 72 69 70 74 27 5d 5b 27 53 63 72 69 70 74 46 75 6c 6c 4e 61 6d 65 27 5d}
		$s4 = {5b 27 57 53 63 72 69 70 74 27 5d 5b 27 53 6c 65 65 70 27 5d 28 31 30 30 30 29}
		$s5 = {6e 65 77 20 41 63 74 69 76 65 58 4f 62 6a 65 63 74 28 27 4d 53 58 4d 4c 32 2e 58 4d 4c 48 54 54 50 27 29}
		$s6 = {74 68 69 73 5b 27 65 76 61 6c 27 5d}
		$s7 = {53 74 72 69 6e 67 5b 27 66 72 6f 6d 43 68 61 72 43 6f 64 65 27 5d}
		$s8 = {32 29 2c 20 31 36 29 2c}
		$s9 = {3d 20 31 30 33 2c}
		$s10 = {27 30 30 30 30 30 30 30 30 27}

	condition:
		filesize > 3KB and filesize < 5KB and 8 of ( $s* )
}

rule SocGholish_JS_22_02_2022 : hardened
{
	meta:
		description = "Detects SocGholish fake update Javascript files 22.02.2022"
		author = "Wojciech Cieślak"
		date = "2022-02-22"
		hash = "3e14d04da9cc38f371961f6115f37c30"
		hash = "dffa20158dcc110366f939bd137515c3"
		hash = "afee3af324951b1840c789540d5c8bff"
		hash = "c04a1625efec27fb6bbef9c66ca8372b"
		hash = "d08a2350df5abbd8fd530cff8339373e"
		id = "68d2dbb7-0079-527a-92c7-450c3dd953b3"
		score = 60

	strings:
		$s1 = {65 6e 63 6f 64 65 55 52 49 43 6f 6d 70 6f 6e 65 6e 74 28 27 27 2b}
		$s2 = {5b 27 6f 70 65 6e 27 5d 28 27 50 4f 53 54 27 2c}
		$s3 = {6e 65 77 20 41 63 74 69 76 65 58 4f 62 6a 65 63 74 28 27 4d 53 58 4d 4c 32 2e 58 4d 4c 48 54 54 50 27 29 3b}

	condition:
		filesize < 5KB and all of them
}

