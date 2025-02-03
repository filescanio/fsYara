import "pe"

rule Pupy_Backdoor : hardened
{
	meta:
		description = "Detects Pupy backdoor"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/n1nj4sec/pupy-binaries"
		date = "2017-08-11"
		hash1 = "ae93714203c7ab4ab73f2ad8364819d16644c7649ea04f483b46924bd5bc0153"
		hash2 = "83380f351214c3bd2c8e62430f70f8f90d11c831695027f329af04806b9f8ea4"
		hash3 = "90757c1ae9597bea39bb52a38fb3d497358a2499c92c7636d71b95ec973186cc"
		hash4 = "20e19817f72e72f87c794843d46c55f2b8fd091582bceca0460c9f0640c7bbd8"
		hash5 = "06bb41c12644ca1761bcb3c14767180b673cb9d9116b555680073509e7063c3e"
		hash6 = "be83c513b24468558dc7df7f63d979af41287e568808ed8f807706f6992bfab2"
		hash7 = "8784c317e6977b4c201393913e76fc11ec34ea657de24e957d130ce9006caa01"
		score = 70
		id = "11509847-3454-5412-b3e1-02ad9cccc6ae"

	strings:
		$x1 = {72 65 66 6c 65 63 74 69 76 65 6c 79 20 69 6e 6a 65 63 74 20 61 20 64 6c 6c 20 69 6e 74 6f 20 61 20 70 72 6f 63 65 73 73 2e}
		$x2 = {6c 64 5f 70 72 65 6c 6f 61 64 5f 69 6e 6a 65 63 74 5f 64 6c 6c 28 63 6d 64 6c 69 6e 65 2c 20 64 6c 6c 5f 62 75 66 66 65 72 2c 20 68 6f 6f 6b 5f 65 78 69 74 29 20 2d 3e 20 70 69 64}
		$x3 = {4c 44 5f 50 52 45 4c 4f 41 44 3d 25 73 20 48 4f 4f 4b 5f 45 58 49 54 3d 25 64 20 43 4c 45 41 4e 55 50 3d 25 64 20 65 78 65 63 20 25 73 20 31 3e 2f 64 65 76 2f 6e 75 6c 6c 20 32 3e 2f 64 65 76 2f 6e 75 6c 6c}
		$x4 = {72 65 66 6c 65 63 74 69 76 65 5f 69 6e 6a 65 63 74 5f 64 6c 6c}
		$x5 = {6c 64 5f 70 72 65 6c 6f 61 64 5f 69 6e 6a 65 63 74 5f 64 6c 6c}
		$x6 = {67 65 74 5f 70 75 70 79 5f 63 6f 6e 66 69 67 28 29 20 2d 3e 20 73 74 72 69 6e 67}
		$x7 = {5b 49 4e 4a 45 43 54 5d 20 69 6e 6a 65 63 74 5f 64 6c 6c 2e 20 4f 70 65 6e 50 72 6f 63 65 73 73 20 66 61 69 6c 65 64 2e}
		$x8 = {72 65 66 6c 65 63 74 69 76 65 5f 69 6e 6a 65 63 74 5f 64 6c 6c}
		$x9 = {72 65 66 6c 65 63 74 69 76 65 5f 69 6e 6a 65 63 74 5f 64 6c 6c 28 70 69 64 2c 20 64 6c 6c 5f 62 75 66 66 65 72 2c 20 69 73 52 65 6d 6f 74 65 50 72 6f 63 65 73 73 36 34 62 69 74 73 29}
		$x10 = {6c 69 6e 75 78 5f 69 6e 6a 65 63 74 5f 6d 61 69 6e}

	condition:
		(( uint16( 0 ) == 0x457f or uint16( 0 ) == 0x5a4d ) and filesize < 7000KB and 1 of them ) or 3 of them or ( uint16( 0 ) == 0x5a4d and pe.imphash ( ) == "84a69bce2ff6d9f866b7ae63bd70b163" )
}

