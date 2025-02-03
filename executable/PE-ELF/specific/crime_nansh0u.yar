import "pe"

rule MAL_XMR_Miner_May19_1 : HIGHVOL hardened
{
	meta:
		description = "Detects Monero Crypto Coin Miner"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.guardicore.com/2019/05/nansh0u-campaign-hackers-arsenal-grows-stronger/"
		date = "2019-05-31"
		score = 85
		hash1 = "d6df423efb576f167bc28b3c08d10c397007ba323a0de92d1e504a3f490752fc"
		id = "233d1d47-de67-55a9-ae7e-46b5dd34e6ce"

	strings:
		$x1 = {64 6f 6e 61 74 65 2e 73 73 6c 2e 78 6d 72 69 67 2e 63 6f 6d}
		$x2 = {2a 20 43 4f 4d 4d 41 4e 44 53 20 20 20 20 20 27 68 27 20 68 61 73 68 72 61 74 65 2c 20 27 70 27 20 70 61 75 73 65 2c 20 27 72 27 20 72 65 73 75 6d 65}
		$s1 = {5b 25 73 5d 20 6c 6f 67 69 6e 20 65 72 72 6f 72 20 63 6f 64 65 3a 20 25 64}
		$s2 = {5c 5c 3f 5c 70 69 70 65 5c 75 76 5c 25 70 2d 25 6c 75}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 14000KB and ( pe.imphash ( ) == "25d9618d1e16608cd5d14d8ad6e1f98e" or 1 of ( $x* ) or 2 of them )
}

import "pe"

rule HKTL_CN_ProcHook_May19_1 : hardened
{
	meta:
		description = "Detects hacktool used by Chinese threat groups"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.guardicore.com/2019/05/nansh0u-campaign-hackers-arsenal-grows-stronger/"
		date = "2019-05-31"
		hash1 = "02ebdc1ff6075c15a44711ccd88be9d6d1b47607fea17bef7e5e17f8da35293e"
		id = "ae4e2613-8254-5ea6-af88-2f08ebe4da33"

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 300KB and pe.imphash ( ) == "343d580dd50ee724746a5c28f752b709"
}

rule SUSP_PDB_CN_Threat_Actor_May19_1 : hardened
{
	meta:
		description = "Detects PDB path user name used by Chinese threat actors"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.guardicore.com/2019/05/nansh0u-campaign-hackers-arsenal-grows-stronger/"
		date = "2019-05-31"
		score = 65
		hash1 = "01c3882e8141a25abe37bb826ab115c52fd3d109c4a1b898c0c78cee8dac94b4"
		id = "fc6969ed-5fc1-5b3b-9659-c6fc1c9e2f9c"

	strings:
		$x1 = {43 3a 5c 55 73 65 72 73 5c 7a 63 67 5c 44 65 73 6b 74 6f 70 5c}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 400KB and 1 of them
}

rule MAL_Parite_Malware_May19_1 : hardened
{
	meta:
		description = "Detects Parite malware"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.guardicore.com/2019/05/nansh0u-campaign-hackers-arsenal-grows-stronger/"
		date = "2019-05-31"
		score = 80
		hash1 = "c9d8852745e81f3bfc09c0a3570d018ae8298af675e3c6ee81ba5b594ff6abb8"
		hash2 = "8d47b08504dcf694928e12a6aa372e7fa65d0d6744429e808ff8e225aefa5af2"
		hash3 = "285e3f21dd1721af2352196628bada81050e4829fb1bb3f8757a45c221737319"
		hash4 = "b987dcc752d9ceb3b0e6cd4370c28567be44b789e8ed8a90c41aa439437321c5"
		id = "f4c9da17-9894-5243-828a-827accb0bac5"

	strings:
		$s1 = {74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 63 6d 64 2e 65 78 65 20 2f 66}
		$s2 = {4c 4f 41 44 45 52 58 36 34 2e 64 6c 6c}
		$x1 = {5c 64 6c 6c 68 6f 74 2e 65 78 65}
		$x2 = {64 6c 6c 68 6f 74 2e 65 78 65 20 2d 2d 61 75 74 6f 20 2d 2d 61 6e 79 20 2d 2d 66 6f 72 65 76 65 72 20 2d 2d 6b 65 65 70 61 6c 69 76 65}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 10000KB and ( 1 of ( $x* ) or 2 of them )
}

import "pe"

rule MAL_Parite_Malware_May19_2 : hardened
{
	meta:
		description = "Detects Parite malware based on Imphash"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.guardicore.com/2019/05/nansh0u-campaign-hackers-arsenal-grows-stronger/"
		date = "2019-05-31"
		hash1 = "c9d8852745e81f3bfc09c0a3570d018ae8298af675e3c6ee81ba5b594ff6abb8"
		hash2 = "8d47b08504dcf694928e12a6aa372e7fa65d0d6744429e808ff8e225aefa5af2"
		hash3 = "285e3f21dd1721af2352196628bada81050e4829fb1bb3f8757a45c221737319"
		hash4 = "b987dcc752d9ceb3b0e6cd4370c28567be44b789e8ed8a90c41aa439437321c5"
		id = "33970268-610c-5abf-9e9e-83dae0c81064"

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 18000KB and ( pe.imphash ( ) == "b132a2719be01a6ef87d9939d785e19e" or pe.imphash ( ) == "78f4f885323ffee9f8fa011455d0523d" )
}

rule EXPL_Strings_CVE_POC_May19_1 : hardened
{
	meta:
		description = "Detects strings used in CVE POC noticed in May 2019"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.guardicore.com/2019/05/nansh0u-campaign-hackers-arsenal-grows-stronger/"
		date = "2019-05-31"
		score = 80
		hash1 = "01c3882e8141a25abe37bb826ab115c52fd3d109c4a1b898c0c78cee8dac94b4"
		id = "df11e0b1-e907-5a24-a3e7-0e78acb379f7"

	strings:
		$x1 = {5c 44 65 62 75 67 5c 70 6f 63 5f 63 76 65 5f 32 30}
		$x2 = {5c 52 65 6c 65 61 73 65 5c 70 6f 63 5f 63 76 65 5f 32 30}
		$x3 = {61 6c 6c 6f 63 20 66 61 6b 65 20 66 61 69 6c 3a 20 25 78 21}
		$x4 = {41 6c 6c 6f 63 61 74 65 20 66 61 6b 65 20 74 61 67 57 6e 64 20 66 61 69 6c 21}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 400KB and 1 of them
}

