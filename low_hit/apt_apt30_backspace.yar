rule APT30_Generic_H : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash1 = "2a4c8752f3e7fde0139421b8d5713b29c720685d"
		hash2 = "4350e906d590dca5fcc90ed3215467524e0a4e3d"
		id = "1908e985-9634-51dc-8972-53afa13c26a3"

	strings:
		$s0 = {5c 54 65 6d 70 31 30 32 30 2e 74 78 74}
		$s1 = {58 6d 64 2e 54 78 65}
		$s2 = {5c 49 6e 74 65 72 6e 65 74 20 45 78 70 31 6f 72 65 72}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_2 : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "0359ffbef6a752ee1a54447b26e272f4a5a35167"
		id = "821a2de9-48c4-58d8-acc4-1e25025ab5cf"

	strings:
		$s0 = {46 00 6f 00 72 00 5a 00 52 00 4c 00 6e 00 6b 00 57 00 6f 00 72 00 64 00 44 00 6c 00 67 00 2e 00 45 00 58 00 45 00}
		$s1 = {46 00 6f 00 72 00 5a 00 52 00 4c 00 6e 00 6b 00 57 00 6f 00 72 00 64 00 44 00 6c 00 67 00 20 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00}
		$s9 = {46 00 6f 00 72 00 5a 00 52 00 4c 00 6e 00 6b 00 57 00 6f 00 72 00 64 00 44 00 6c 00 67 00 20 00 31 00 2e 00 30 00 20 00}
		$s11 = {46 00 6f 00 72 00 5a 00 52 00 4c 00 6e 00 6b 00 57 00 6f 00 72 00 64 00 44 00 6c 00 67 00}
		$s12 = {20 00 28 00 43 00 29 00 20 00 32 00 30 00 31 00 31 00}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_3 : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "d0320144e65c9af0052f8dee0419e8deed91b61b"
		id = "62e81385-26f5-545d-92ff-6604ff4d0186"

	strings:
		$s5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63}
		$s6 = {48 48 4f 53 54 52}
		$s9 = {54 68 45 75 67 68}
		$s10 = {4d 6f 7a 69 65 61 2f}
		$s12 = {25 73 25 73 28 58 2d}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Generic_C : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash1 = "8667f635fe089c5e2c666b3fe22eaf3ff8590a69"
		hash2 = "0c4fcef3b583d0ffffc2b14b9297d3a4"
		hash3 = "37aee58655f5859e60ece6b249107b87"
		hash4 = "4154548e1f8e9e7eb39d48a4cd75bcd1"
		hash5 = "a2e0203e665976a13cdffb4416917250"
		hash6 = "b4ae0004094b37a40978ef06f311a75e"
		hash7 = "e39756bc99ee1b05e5ee92a1cdd5faf4"
		id = "25ec8d54-9875-5bf5-abc9-296f18f3c5e5"

	strings:
		$s0 = {4d 59 55 53 45 52 33 32 2e 64 6c 6c}
		$s1 = {4d 59 41 44 56 41 50 49 33 32 2e 64 6c 6c}
		$s2 = {4d 59 57 53 4f 43 4b 33 32 2e 64 6c 6c}
		$s3 = {4d 59 4d 53 56 43 52 54 2e 64 6c 6c}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_4 : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "75367d8b506031df5923c2d8d7f1b9f643a123cd"
		id = "e5c6afde-0ab5-54ed-8d18-5ad477a527d7"

	strings:
		$s0 = {47 65 74 53 74 61 72 74 75 70 49 6e}
		$s1 = {65 6e 4d 75 74 65 78}
		$s2 = {74 70 73 76 69 6d 69}
		$s3 = {72 65 61 74 65 50 72 6f 63 65 73 79}
		$s5 = {46 72 65 65 4c 69 62 72 31 79 2a 53}
		$s6 = {66 6f 41 4d 6f 64 75 6c 65 48 61 6e 64}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_5 : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "1a2dd2a0555dc746333e7c956c58f7c4cdbabd4b"
		id = "bdbebe44-7423-5793-8a42-4f9b70de2231"

	strings:
		$s0 = {56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 20 00 34 00 2e 00 37 00 2e 00 33 00 30 00 30 00 31 00}
		$s1 = {43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 28 00 63 00 29 00 20 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00 20 00 32 00 30 00 30 00 34 00}
		$s3 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 28 00 52 00 29 00 20 00 69 00 73 00 20 00 61 00 20 00 72 00 65 00 67 00 69 00 73 00 74 00 65 00 72 00 65 00 64 00 20 00 74 00 72 00 61 00 64 00 65 00 6d 00 61 00 72 00 6b 00 20 00 6f 00 66 00 20 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00 20 00 69 00 6e 00 20 00 74 00 68 00 65 00 20 00 55 00}
		$s7 = {6d 00 73 00 6d 00 73 00 67 00 73 00}
		$s10 = {2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 67 5f 6e 41 56 3d 25 64 2c 68 57 6e 64 3a 30 78 25 58 2c 63 6c 61 73 73 4e 61 6d 65 3a 25 73 2c 54 69 74 6c 65 3a 25 73 2c 28 25 64 2c 25 64 2c 25 64 2c 25 64 29 2c 42 4f 4f 4c 3d 25 64}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_6 : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "00e69b059ad6b51b76bc476a115325449d10b4c0"
		id = "2f19809c-09fc-51bf-9a20-6b95099a92dd"

	strings:
		$s0 = {47 72 65 61 74 65 50 72 6f 63 65 73 73 41}
		$s1 = {54 65 72 6e 65 6c 33 32 2e 64 6c 6c}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_7 : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "868d1f4c106a08bd2e5af4f23139f0e0cd798fba"
		id = "612732d9-8df5-5388-b299-2da4f8118435"

	strings:
		$s0 = {64 61 74 61 69 6e}
		$s3 = {43 3a 5c 50 72 6f 67}
		$s4 = {24 4c 44 44 41 54 41 24}
		$s5 = {4d 61 79 62 65 20 61 20 45 6e 63 72 79 70 74 65 64 20 46 6c 61 73 68}
		$s6 = {4a 65 61 6e 2d 6c 6f 75 70 20 47 61 69 6c 6c 79}
		$s8 = {64 65 66 6c 61 74 65 20 31 2e 31 2e 33 20 43 6f 70 79 72 69 67 68 74}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Generic_E : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash1 = "1dbb584e19499e26398fb0a7aa2a01b7"
		hash2 = "572c9cd4388699347c0b2edb7c6f5e25"
		hash3 = "8ff473bedbcc77df2c49a91167b1abeb"
		hash4 = "a813eba27b2166620bd75029cc1f04b0"
		hash5 = "b5546842e08950bc17a438d785b5a019"
		id = "69e76a59-3529-541d-9017-07e6d67fbda4"

	strings:
		$s0 = {4e 6b 66 76 74 79 76 6e 7d}
		$s6 = {2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 67 5f 6e 41 56 3d 25 64 2c 68 57 6e 64 3a 30 78 25 58 2c 63 6c 61 73 73 4e 61 6d 65 3a 25 73 2c 54 69 74 6c 65 3a 25 73 2c 28 25 64 2c 25 64 2c 25 64 2c 25 64 29 2c 42 4f 4f 4c 3d 25 64}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_8 : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "9531e21652143b8b129ab8c023dc05fef2a17cc3"
		id = "5053c2db-32a9-58ae-9a72-eb16ef14168e"

	strings:
		$s0 = {61 74 65 50 72 6f 63 65 73 73 41}
		$s1 = {54 65 72 6e 65 6c 33 32 2e 64 6c 6c 46 51}
		$s2 = {53 74 61 72 74 75 70 49 6e 66 6f 41 4d 6f 64 75 6c 65 48 61 6e 64}
		$s3 = {4f 70 65 6e 4d 75 74 65 78}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Generic_B : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash1 = "0fcb4ffe2eb391421ec876286c9ddb6c"
		hash2 = "29395c528693b69233c1c12bef8a64b3"
		hash3 = "4c6b21e98ca03e0ef0910e07cef45dac"
		hash4 = "550459b31d8dabaad1923565b7e50242"
		hash5 = "65232a8d555d7c4f7bc0d7c5da08c593"
		hash6 = "853a20f5fc6d16202828df132c41a061"
		hash7 = "ed151602dea80f39173c2f7b1dd58e06"
		id = "df3b8896-7229-5b3b-ad2f-774b0cea167c"

	strings:
		$s2 = {4d 6f 7a 69 65 61 2f 34 2e 30}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Generic_I : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash1 = "fe211c7a081c1dac46e3935f7c614549"
		hash2 = "8c9db773d387bf9b3f2b6a532e4c937c"
		id = "55046e1a-731a-5418-9a7a-4fe1611c77d0"

	strings:
		$s0 = {43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 32 00 30 00 31 00 32 00 20 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 20 00 49 00 6e 00 63 00 2e 00 20 00 41 00 6c 00 6c 00 20 00 72 00 69 00 67 00 68 00 74 00 73 00 20 00 72 00 65 00 73 00 65 00 72 00 76 00 65 00 64 00 2e 00}
		$s1 = {28 50 72 78 79 25 63 2d 25 73 3a 25 75 29}
		$s2 = {47 00 6f 00 6f 00 67 00 6c 00 65 00 20 00 49 00 6e 00 63 00 2e 00}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_9 : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "442bf8690401a2087a340ce4a48151c39101652f"
		id = "bf24bb57-aff9-579c-b8a2-265a6d2a06d0"

	strings:
		$s0 = {5c 57 69 6e 64 6f}
		$s2 = {6f 48 48 4f 53 54 52}
		$s3 = {53 6f 66 74 77 61 5d 5c 4d 69 63}
		$s4 = {53 74 61 72 74 75 70 27 54}
		$s6 = {4f 72 61 5c 25 5e}
		$s7 = {5c 4f 68 74 74 70 3d 72}
		$s17 = {68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 30 4c}
		$s18 = {54 69 6d 55 6d 6f 76 65 48}
		$s20 = {57 69 64 65 43 68 63 5b 6c 6f 62 61 6c 41 6c}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_10 : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "eb518cda3c4f4e6938aaaee07f1f7db8ee91c901"
		id = "e5dd6bc9-9383-5d48-92df-709996373655"

	strings:
		$s0 = {56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 20 00 34 00 2e 00 37 00 2e 00 33 00 30 00 30 00 31 00}
		$s1 = {43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 28 00 63 00 29 00 20 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00 20 00 32 00 30 00 30 00 34 00}
		$s2 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 28 00 52 00 29 00 20 00 69 00 73 00 20 00 61 00 20 00 72 00 65 00 67 00 69 00 73 00 74 00 65 00 72 00 65 00 64 00 20 00 74 00 72 00 61 00 64 00 65 00 6d 00 61 00 72 00 6b 00 20 00 6f 00 66 00 20 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00 20 00 69 00 6e 00 20 00 74 00 68 00 65 00 20 00 55 00}
		$s3 = {21 21 20 55 73 65 20 43 6f 6e 6e 65 63 74 20 4d 65 74 68 6f 64 20 21 21}
		$s4 = {28 50 72 78 79 25 63 2d 25 73 3a 25 75 29}
		$s5 = {6d 00 73 00 6d 00 73 00 67 00 73 00}
		$s18 = {28 50 72 78 79 2d 4e 6f 29}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_11 : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "59066d5d1ee3ad918111ed6fcaf8513537ff49a6"
		id = "e5dd6bc9-9383-5d48-92df-709996373655"

	strings:
		$s0 = {53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 63 6f 6e 74 72 6f 6c 5c 43 6f 6d 70 75 74 65 72 4e 61 6d 65 5c 43 6f 6d 70 75 74 65 72 4e 61 6d 65}
		$s1 = {6d 00 73 00 6f 00 66 00 73 00 63 00 61 00 6e 00 2e 00 65 00 78 00 65 00}
		$s2 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 35 2e 30 3b 20 57 69 6e 33 32 29}
		$s3 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 3f 00 20 00 69 00 73 00 20 00 61 00 20 00 72 00 65 00 67 00 69 00 73 00 74 00 65 00 72 00 65 00 64 00 20 00 74 00 72 00 61 00 64 00 65 00 6d 00 61 00 72 00 6b 00 20 00 6f 00 66 00 20 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00 2e 00}
		$s4 = {57 69 6e 64 6f 77 73 20 58 50 20 50 72 6f 66 65 73 73 69 6f 6e 61 6c 20 78 36 34 20 45 64 69 74 69 6f 6e 20 6f 72 20 57 69 6e 64 6f 77 73 20 53 65 72 76 65 72 20 32 30 30 33}
		$s9 = {4e 65 74 45 61 67 6c 65 5f 53 63 6f 75 74 20 2d 20}
		$s10 = {53 65 72 76 65 72 20 34 2e 30 2c 20 45 6e 74 65 72 70 72 69 73 65 20 45 64 69 74 69 6f 6e}
		$s11 = {57 69 6e 64 6f 77 73 20 33 2e 31 28 57 69 6e 33 32 73 29}
		$s12 = {25 73 25 73 25 73 20 25 73}
		$s13 = {53 65 72 76 65 72 20 34 2e 30}
		$s15 = {57 69 6e 64 6f 77 73 20 4d 69 6c 6c 65 6e 6e 69 75 6d 20 45 64 69 74 69 6f 6e}
		$s16 = {6d 00 73 00 6f 00 66 00 73 00 63 00 61 00 6e 00}
		$s17 = {45 61 67 6c 65 2d 4e 6f 72 74 6f 6e 33 36 30 2d 4f 66 66 69 63 65 53 63 61 6e}
		$s18 = {57 6f 72 6b 73 74 61 74 69 6f 6e 20 34 2e 30}
		$s19 = {32 00 30 00 30 00 33 00 20 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 4f 00 66 00 66 00 69 00 63 00 65 00 20 00 73 00 79 00 73 00 74 00 65 00 6d 00}

	condition:
		filesize < 250KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_12 : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "b02b5720ff0f73f01eb2ba029a58b645c987c4bc"
		id = "e5dd6bc9-9383-5d48-92df-709996373655"

	strings:
		$s0 = {52 69 63 68 69 63}
		$s1 = {41 63 63 65 70 74 3a 20 69 6d 61 67 65 2f 67 69 66 2c 20 2a 2f 2a}
		$s2 = {2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 67 5f 6e 41 56 3d 25 64 2c 68 57 6e 64 3a 30 78 25 58 2c 63 6c 61 73 73 4e 61 6d 65 3a 25 73 2c 54 69 74 6c 65 3a 25 73 2c 28 25 64 2c 25 64 2c 25 64 2c 25 64 29 2c 42 4f 4f 4c 3d 25 64}

	condition:
		filesize < 250KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_13 : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "a359f705a833c4a4254443b87645fd579aa94bcf"
		id = "e5dd6bc9-9383-5d48-92df-709996373655"

	strings:
		$s0 = {6d 00 73 00 6f 00 66 00 73 00 63 00 61 00 6e 00 2e 00 65 00 78 00 65 00}
		$s1 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 3f 00 20 00 69 00 73 00 20 00 61 00 20 00 72 00 65 00 67 00 69 00 73 00 74 00 65 00 72 00 65 00 64 00 20 00 74 00 72 00 61 00 64 00 65 00 6d 00 61 00 72 00 6b 00 20 00 6f 00 66 00 20 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00 2e 00}
		$s2 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 4f 00 66 00 66 00 69 00 63 00 65 00 20 00 57 00 6f 00 72 00 64 00 20 00 50 00 6c 00 75 00 67 00 69 00 6e 00 20 00 53 00 63 00 61 00 6e 00}
		$s3 = {3f 00 20 00 32 00 30 00 30 00 36 00 20 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 20 00 20 00 41 00 6c 00 6c 00 20 00 72 00 69 00 67 00 68 00 74 00 73 00 20 00 72 00 65 00 73 00 65 00 72 00 76 00 65 00 64 00 2e 00}
		$s4 = {6d 00 73 00 6f 00 66 00 73 00 63 00 61 00 6e 00}
		$s6 = {32 00 30 00 30 00 33 00 20 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 4f 00 66 00 66 00 69 00 63 00 65 00 20 00 73 00 79 00 73 00 74 00 65 00 6d 00}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_14 : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "b0740175d20eab79a5d62cdbe0ee1a89212a8472"
		id = "e5dd6bc9-9383-5d48-92df-709996373655"

	strings:
		$s0 = {41 00 64 00 6f 00 62 00 65 00 52 00 65 00 61 00 64 00 65 00 72 00 2e 00 65 00 78 00 65 00}
		$s4 = {31 00 30 00 2e 00 31 00 2e 00 37 00 2e 00 32 00 37 00}
		$s5 = {43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 31 00 39 00 38 00 34 00 2d 00 32 00 30 00 31 00 32 00 20 00 41 00 64 00 6f 00 62 00 65 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00 73 00 20 00 49 00 6e 00 63 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 65 00 64 00 20 00 61 00 6e 00 64 00 20 00 69 00 74 00 73 00 20 00 6c 00 69 00 63 00 65 00 6e 00 73 00 6f 00 72 00 73 00 2e 00 20 00 41 00 6c 00 6c 00 20 00 72 00 69 00}
		$s8 = {41 00 64 00 6f 00 62 00 65 00 20 00 52 00 65 00 61 00 64 00 65 00 72 00}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_15 : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "7a8576804a2bbe4e5d05d1718f90b6a4332df027"
		id = "e5dd6bc9-9383-5d48-92df-709996373655"

	strings:
		$s0 = {5c 57 69 6e 64 6f}
		$s2 = {48 48 4f 53 54 52}
		$s3 = {53 6f 66 74 77 61 5d 5c 4d 69 63}
		$s4 = {53 74 61 72 74 75 70 27 54}
		$s17 = {68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 30 4c}
		$s18 = {54 69 6d 55 6d 6f 76 65 48}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_16 : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "066d06ac08b48d3382d46bbeda6ad411b6d6130e"
		id = "e5dd6bc9-9383-5d48-92df-709996373655"

	strings:
		$s0 = {5c 54 65 6d 70 31 30 32 30 2e 74 78 74}
		$s1 = {63 6d 63 62 71 79 6a 73}
		$s2 = {53 50 56 53 57 68 5c}
		$s4 = {50 53 53 68 78 77 40}
		$s5 = {56 57 68 48 77 40}
		$s7 = {53 56 57 68 48 77 40}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Generic_A : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash1 = "9f49aa1090fa478b9857e15695be4a89f8f3e594"
		hash2 = "396116cfb51cee090822913942f6ccf81856c2fb"
		hash3 = "fef9c3b4b35c226501f7d60816bb00331a904d5b"
		hash4 = "7c9a13f1fdd6452fb6d62067f958bfc5fec1d24e"
		hash5 = "5257ba027abe3a2cf397bfcae87b13ab9c1e9019"
		id = "6b851d94-d3bd-5c76-8fd0-adb42b3fab73"

	strings:
		$s5 = {57 50 56 57 68 68 69 41}
		$s6 = {56 50 57 56 68 68 69 41}
		$s11 = {56 50 68 68 69 41}
		$s12 = {75 55 68 58 69 41}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_17 : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "c3aa52ff1d19e8fc6704777caf7c5bd120056845"
		id = "e5dd6bc9-9383-5d48-92df-709996373655"

	strings:
		$s1 = {4e 6b 66 76 74 79 76 6e 7d 5d 74 79 7d 7a 74 55}
		$s4 = {49 45 58 50 4c 30 52 45}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_18 : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "355436a16d7a2eba8a284b63bb252a8bb1644751"
		id = "e5dd6bc9-9383-5d48-92df-709996373655"

	strings:
		$s0 = {77 2e 6b 6d 2d 6e 79 63 2e 63 6f 6d}
		$s1 = {74 73 63 76 2e 65 78 65}
		$s2 = {45 78 69 74 2f 61 70 70 2e 68 74 6d}
		$s3 = {55 42 44 3a 5c 44}
		$s4 = {4c 61 73 74 45 72 72 6f 72}
		$s5 = {4d 69 63 72 6f 73 6f 66 74 48 61 76 65 41 63 6b}
		$s7 = {48 48 4f 53 54 52}
		$s20 = {58 50 4c 30 52 45 2e}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Generic_G : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "1612b392d6145bfb0c43f8a48d78c75f"
		hash = "53f1358cbc298da96ec56e9a08851b4b"
		hash = "c2acc9fc9b0f050ec2103d3ba9cb11c0"
		hash = "f18be055fae2490221c926e2ad55ab11"
		id = "34269de3-4559-58a5-a621-0ad72857dc9e"

	strings:
		$s0 = {25 73 5c 25 73 5c 25 73 3d 25 73}
		$s1 = {43 6f 70 79 20 46 69 6c 65 20 25 73 20 4f 4b 21}
		$s2 = {25 73 20 53 70 61 63 65 3a 25 75 4d 2c 46 72 65 65 53 70 61 63 65 3a 25 75 4d}
		$s4 = {6f 70 65 6e 3d 25 73}
		$s5 = {4d 61 79 62 65 20 61 20 45 6e 63 72 79 70 74 65 64 20 46 6c 61 73 68 20 44 69 73 6b}
		$s12 = {25 30 34 75 2d 25 30 32 75 2d 25 30 32 75 20 25 30 32 75 3a 25 30 32 75 3a 25 30 32 75}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_19 : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/03"
		modified = "2023-01-06"
		score = 75
		hash = "cfa438449715b61bffa20130df8af778ef011e15"
		id = "e5dd6bc9-9383-5d48-92df-709996373655"

	strings:
		$s0 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 53 79 73 74 65 6d 5c 77 61 62 33 32}
		$s1 = {25 73 2c 56 6f 6c 75 6d 65 3a 25 73 2c 54 79 70 65 3a 25 73 2c 54 6f 74 61 6c 53 69 7a 65 3a 25 75 4d 42 2c 46 72 65 65 53 69 7a 65 3a 25 75 4d 42}
		$s2 = {5c 54 45 4d 50 5c}
		$s3 = {5c 54 65 6d 70 6f 72 61 72 79 20 49 6e 74 65 72 6e 65 74 20 46 69 6c 65 73 5c}
		$s5 = {25 73 20 54 6f 74 61 6c 53 69 7a 65 3a 25 75 20 42 79 74 65 73}
		$s6 = {54 68 69 73 20 44 69 73 6b 20 4d 61 79 62 65 20 61 20 45 6e 63 72 79 70 74 65 64 20 46 6c 61 73 68 20 44 69 73 6b 21}
		$s7 = {55 73 65 72 3a 25 2d 33 32 73}
		$s8 = {5c 44 65 73 6b 74 6f 70 5c}
		$s9 = {25 73 2e 25 75 5f 25 75}
		$s10 = {4e 69 63 6b 3a 25 2d 33 32 73}
		$s11 = {45 2d 6d 61 69 6c 3a 25 2d 33 32 73}
		$s13 = {25 30 34 75 2d 25 30 32 75 2d 25 30 32 75 20 25 30 32 75 3a 25 30 32 75 3a 25 30 32 75}
		$s14 = {54 79 70 65 3a 25 2d 38 73}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and 8 of them
}

rule APT30_Generic_E_v2 : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "eca53a9f6251ddf438508b28d8a483f91b99a3fd"
		id = "40897687-fb17-568e-9907-e9588a53bbe0"

	strings:
		$s0 = {4e 6b 66 76 74 79 76 6e 7d 64 75 66 5f 5a 7d 7b 59 73}
		$s1 = {4e 6b 66 76 74 79 76 6e 7d 2a 5a 72 73 77 72 75 31 69}
		$s2 = {4e 6b 66 76 74 79 76 6e 7d 64 75 66 5f 5a 7d 7b 56}
		$s3 = {4e 6b 66 76 74 79 76 6e 7d 2a 5a 72 73 77 72 75 6d 54 5c 62}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_20 : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "b1c37632e604a5d1f430c9351f87eb9e8ea911c0"
		id = "91246101-246b-5da9-9e55-7f361d1f6437"

	strings:
		$s0 = {64 69 7a 68 69 2e 67 69 66}
		$s2 = {4d 6f 7a 69 6c 6c 61 2f 75}
		$s3 = {58 69 63 72 6f 73 6f 66 74 48 61 76 65 41 63 6b}
		$s4 = {66 6c 79 65 61 67 6c 65 73}
		$s10 = {69 65 78 70 6c 6f 72 65 2e}
		$s13 = {57 69 6e 64 6f 77 73 47 56}
		$s16 = {43 61 74 65 50 69 70 65}
		$s17 = {27 51 57 45 52 54 59 3a 2f 77 65 62 70 61 67 65 33}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_21 : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "d315daa61126616a79a8582145777d8a1565c615"
		id = "72005b40-91f7-5661-9478-8680f999b245"

	strings:
		$s0 = {53 65 72 76 69 63 65 2e 64 6c 6c}
		$s1 = {28 25 73 3a 25 73 20 25 73 29}
		$s2 = {25 73 20 22 25 73 22 2c 25 73 20 25 73}
		$s5 = {50 72 6f 78 79 2d 25 73 3a 25 75}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_22 : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "0d17a58c24753e5f8fd5276f62c8c7394d8e1481"
		id = "6c1b3dd2-4383-51a2-9185-2365a4d1e784"

	strings:
		$s1 = {28 5c 54 45 4d 50}
		$s2 = {57 69 6e 64 6f 77 73 5c 43 75 72}
		$s3 = {4c 53 53 41 53 2e 65 78 65 4a}
		$s4 = {51 43 3a 5c 57 49 4e 44 4f 57 53}
		$s5 = {53 79 73 74 65 6d 20 56 6f 6c 75 6d 65}
		$s8 = {50 52 4f 47 52 41 4d 20 46 49 4c 45}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Generic_F : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash1 = "09010917cd00dc8ddd21aeb066877aa2"
		hash2 = "4c10a1efed25b828e4785d9526507fbc"
		hash3 = "b7b282c9e3eca888cbdb5a856e07e8bd"
		hash4 = "df1799845b51300b03072c6569ab96d5"
		id = "cff8b921-9afc-5a52-84cb-825de33fc86e"

	strings:
		$s0 = {5c 7e 7a 6c 7a 6c 2e 65 78 65}
		$s2 = {5c 49 6e 74 65 72 6e 65 74 20 45 78 70 31 6f 72 65 72}
		$s3 = {4e 6f 64 41 6e 64 4b 61 62 49 73 45 78 63 65 6c 6c 65 6e 74}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_23 : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "9865e24aadb4480bd3c182e50e0e53316546fc01"
		id = "9366dd34-9967-5b40-935e-4b0d8f2f5e9e"

	strings:
		$s0 = {68 6f 73 74 69 64}
		$s1 = {5c 57 69 6e 64 6f 77}
		$s2 = {25 75 3a 25 75 25 73}
		$s5 = {53 32 74 77 61 72 65 5c 4d 69 63}
		$s6 = {6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61}
		$s7 = {4e 61 6d 65 41 43 4b 65 72 6e 65 6c}
		$s12 = {54 6f 57 69 64 65 43 68 63 5b 6c 6f}
		$s14 = {68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 66 4c}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_24 : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "572caa09f2b600daa941c60db1fc410bef8d1771"
		id = "aed2201d-b557-56ec-aa53-fff5b1e17dbd"

	strings:
		$s1 = {64 69 7a 68 69 2e 67 69 66}
		$s3 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30}
		$s4 = {6c 79 65 61 67 6c 65 73}
		$s6 = {48 48 4f 53 54 52}
		$s7 = {23 4d 69 63 72 6f 73 6f 66 74 48 61 76 65 41 63 6b 37}
		$s8 = {69 65 78 70 6c 6f 72 65 2e}
		$s17 = {4d 6f 64 75 6c 65 48}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_25 : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "44a21c8b3147fabc668fee968b62783aa9d90351"
		id = "8b2f2ba2-e9cc-5b3c-8af9-4217d662bc3f"

	strings:
		$s1 = {43 3a 5c 57 49 4e 44 4f 57 53}
		$s2 = {61 72 61 67 75 61}
		$s4 = {5c 64 72 69 76 65 72 33 32 5c 37 24}
		$s8 = {53 79 73 74 65 6d 20 56}
		$s9 = {43 6f 6d 70 75 7e 72}
		$s10 = {50 52 4f 47 52 41 4d 20 4c}
		$s18 = {47 50 52 54 4d 41 58}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_26 : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "e26588113417bf68cb0c479638c9cd99a48e846d"
		id = "aa80a142-c8fc-504e-b475-e9838607bec6"

	strings:
		$s1 = {66 6f 72 63 65 67 75 65}
		$s3 = {57 69 6e 64 6f 77 73 5c 43 75 72}
		$s4 = {53 79 73 74 65 6d 20 49 64}
		$s5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63}
		$s6 = {75 74 69 42 79 30 54 6f 57 69 64 65 43 68 26 24 61}
		$s10 = {4d 6f 64 75 6c 65 48}
		$s15 = {50 65 65 6b 4e 61 6d 65 64 36 47}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Generic_D : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash1 = "35dfb55f419f476a54241f46e624a1a4"
		hash2 = "4fffcbdd4804f6952e0daf2d67507946"
		hash3 = "597805832d45d522c4882f21db800ecf"
		hash4 = "6bd422d56e85024e67cc12207e330984"
		hash5 = "82e13f3031130bd9d567c46a9c71ef2b"
		hash6 = "b79d87ff6de654130da95c73f66c15fa"
		id = "9b8d8a60-a357-5cfd-8ff1-6264144ad7be"

	strings:
		$s0 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 46 00 65 00 65 00 64 00 62 00 61 00 63 00 6b 00}
		$s1 = {77 00 73 00 73 00 66 00 6d 00 67 00 72 00 2e 00 65 00 78 00 65 00}
		$s2 = {5c 72 62 2e 68 74 6d}
		$s3 = {72 62 2e 68 74 6d}
		$s4 = {63 6f 6f 6b 35}
		$s5 = {35 00 2c 00 20 00 34 00 2c 00 20 00 32 00 36 00 30 00 30 00 2c 00 20 00 30 00}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_27 : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "959573261ca1d7e5ddcd19447475b2139ca24fe1"
		id = "22815745-086f-59ee-aac1-f35e49aa5835"

	strings:
		$s0 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30}
		$s1 = {64 69 7a 68 69 2e 67 69 66}
		$s5 = {6f 66 74 48 61 76 65 41 63 6b 2b}
		$s10 = {48 6c 6f 62 61 6c 41 6c}
		$s13 = {24 4e 74 52 4e 44 31 24}
		$s14 = {5f 4e 53 74 61 72 74 75 70}
		$s16 = {47 58 53 59 53 54 45 4d}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_28 : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash1 = "e62a63307deead5c9fcca6b9a2d51fb0"
		hash2 = "5b590798da581c894d8a87964763aa8b"
		id = "1bc8c68f-ebbb-58b1-92aa-5954318096a0"

	strings:
		$s0 = {77 77 77 2e 66 6c 79 65 61 67 6c 65 73 2e 63 6f 6d}
		$s1 = {69 65 78 70 6c 6f 72 65 2e 65 78 65}
		$s2 = {77 77 77 2e 6b 6d 2d 6e 79 63 2e 63 6f 6d}
		$s3 = {63 6d 64 4c 69 6e 65 2e 65 78 65}
		$s4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 43 75 72 72 65 6e 74 4e 65 74 49 6e 66}
		$s5 = {2f 64 69 7a 68 69 2e 67 69 66}
		$s6 = {2f 63 6f 6e 6e 65 63 74 2e 67 69 66}
		$s7 = {55 53 42 54 65 73 74 2e 73 79 73}
		$s8 = {2f 76 65 72 2e 68 74 6d}
		$s11 = {5c 6e 65 74 73 63 76 2e 65 78 65}
		$s12 = {2f 61 70 70 2e 68 74 6d}
		$s13 = {5c 6e 65 74 73 76 63 2e 65 78 65}
		$s14 = {2f 65 78 65 2e 68 74 6d}
		$s18 = {4d 69 63 72 6f 73 6f 66 74 48 61 76 65 41 63 6b}
		$s19 = {4d 69 63 72 6f 73 6f 66 74 48 61 76 65 45 78 69 74}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and 7 of them
}

rule APT30_Sample_29 : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "44492c53715d7c79895904543843a321491cb23a"
		id = "24334885-fcb4-5a13-82e8-c8465f97361e"

	strings:
		$s0 = {4c 53 53 41 53 2e 65 78 65}
		$s1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 46 6c 61 73 68 44 69 73 6b 49 6e 66}
		$s2 = {2e 70 65 74 69 74 65}
		$s3 = {4d 69 63 72 6f 73 6f 66 74 46 6c 61 73 68 45 78 69 74}
		$s4 = {4d 69 63 72 6f 73 6f 66 74 46 6c 61 73 68 48 61 76 65 45 78 69 74}
		$s5 = {4d 69 63 72 6f 73 6f 66 74 46 6c 61 73 68 48 61 76 65 41 63 6b}
		$s6 = {5c 64 72 69 76 65 72 33 32}
		$s7 = {4d 69 63 72 6f 73 6f 66 74 46 6c 61 73 68 5a 4a}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_30 : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "3b684fa40b4f096e99fbf535962c7da5cf0b4528"
		id = "787b288a-6fb4-5483-af76-933651ec6d58"

	strings:
		$s0 = {35 00 2e 00 31 00 2e 00 32 00 36 00 30 00 30 00 2e 00 32 00 31 00 38 00 30 00 20 00 28 00 78 00 70 00 73 00 70 00 5f 00 73 00 70 00 32 00 5f 00 72 00 74 00 6d 00 2e 00 30 00 34 00 30 00 38 00 30 00 33 00 2d 00 32 00 31 00 35 00 38 00 29 00}
		$s3 = {52 6e 68 77 74 78 74 6b 79 4c 52 52 4d 66 7b 6a 4a 7d 6e 79}
		$s4 = {52 6e 68 77 74 78 74 6b 79 4c 52 52 4a 7d 6e 79}
		$s5 = {5a 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41}
		$s9 = {35 00 2e 00 31 00 2e 00 32 00 36 00 30 00 30 00 2e 00 32 00 31 00 38 00 30 00}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_31 : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "8b4271167655787be1988574446125eae5043aca"
		id = "9333870b-7eaa-54dd-a801-7292708fb592"

	strings:
		$s0 = {5c 5a 4a 52 73 76 2e 74 65 6d}
		$s1 = {66 6f 72 63 65 67 75 65 73 74}
		$s4 = {5c 24 4e 74 55 6e 69 6e 73 74 61 6c 6c 4b 42 35 37 30 33 31 37 24}
		$s8 = {5b 43 61 6e 27 74 47 65 74 49 50 5d}
		$s14 = {51 57 45 52 54 59 3a 2c 60 2f}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Generic_J : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash1 = "49aca228674651cba776be727bdb7e60"
		hash2 = "5c7a6b3d1b85fad17333e02608844703"
		hash3 = "649fa64127fef1305ba141dd58fb83a5"
		hash4 = "9982fd829c0048c8f89620691316763a"
		hash5 = "baff5262ae01a9217b10fcd5dad9d1d5"
		hash6 = "9982fd829c0048c8f89620691316763a"
		id = "64a5106e-d7f3-5c68-a14e-410149a1bb9e"

	strings:
		$s0 = {4c 00 61 00 75 00 6e 00 63 00 68 00 65 00 72 00 2e 00 45 00 58 00 45 00}
		$s1 = {53 00 79 00 6d 00 61 00 6e 00 74 00 65 00 63 00 20 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 20 00 54 00 65 00 63 00 68 00 6e 00 6f 00 6c 00 6f 00 67 00 69 00 65 00 73 00}
		$s2 = {5c 53 79 6d 61 6e 74 65 63 20 4c 69 76 65 55 70 64 61 74 65 2e 6c 6e 6b}
		$s3 = {53 00 79 00 6d 00 61 00 6e 00 74 00 65 00 63 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00}
		$s4 = {5c 63 63 53 76 63 48 73 74 2e 65 78 65}
		$s5 = {5c 77 73 73 66 6d 67 72 2e 65 78 65}
		$s6 = {53 00 79 00 6d 00 61 00 6e 00 74 00 65 00 63 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00}
		$s7 = {5c 35 2e 31 2e 30 2e 32 39}
		$s8 = {5c 45 6e 67 69 6e 65}
		$s9 = {43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 28 00 43 00 29 00 20 00 32 00 30 00 30 00 30 00 2d 00 32 00 30 00 31 00 30 00 20 00 53 00 79 00 6d 00 61 00 6e 00 74 00 65 00 63 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 20 00 41 00 6c 00 6c 00 20 00 72 00 69 00 67 00 68 00 74 00 73 00 20 00 72 00 65 00 73 00 65 00 72 00 76 00 65 00 64 00 2e 00}
		$s10 = {53 79 6d 61 6e 74 65 63 20 4c 69 76 65 55 70 64 61 74 65}
		$s11 = {5c 4e 6f 72 74 6f 6e 33 36 30}
		$s15 = {42 69 6e 52 65 73}
		$s16 = {5c 72 65 61 64 6d 65 2e 6c 7a}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Microfost : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "57169cb4b8ef7a0d7ebd7aa039d1a1efd6eb639e"
		id = "19231001-1da3-5be6-8275-03c9fc7c6377"

	strings:
		$s1 = {43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 28 00 63 00 29 00 20 00 32 00 30 00 30 00 37 00 20 00 4d 00 69 00 63 00 72 00 6f 00 66 00 6f 00 73 00 74 00 20 00 41 00 6c 00 6c 00 20 00 52 00 69 00 67 00 68 00 74 00 73 00 20 00 52 00 65 00 73 00 65 00 72 00 76 00 65 00 64 00}
		$s2 = {4d 00 69 00 63 00 72 00 6f 00 66 00 6f 00 73 00 74 00}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Generic_K : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/03"
		modified = "2023-01-06"
		score = 75
		hash = "142bc01ad412799a7f9ffed994069fecbd5a2f93"
		id = "49629825-4233-5d74-b763-b2500536eb90"

	strings:
		$x1 = {4d 61 79 62 65 20 61 20 45 6e 63 72 79 70 74 65 64 20 46 6c 61 73 68}
		$s0 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 53 79 73 74 65 6d 5c 77 61 62 33 32}
		$s1 = {5c 54 45 4d 50 5c}
		$s2 = {5c 54 65 6d 70 6f 72 61 72 79 20 49 6e 74 65 72 6e 65 74 20 46 69 6c 65 73 5c}
		$s5 = {25 73 20 53 69 7a 65 3a 25 75 20 42 79 74 65 73}
		$s7 = {24 2e 44 41 54 41 24}
		$s10 = {3f 20 53 69 7a 65 3a 25 75 20 42 79 20 73}
		$s12 = {4d 61 79 62 65 20 61 20 45 6e 63 72 79 70 74 65 64 20 46 6c 61 73 68}
		$s14 = {4e 61 6d 65 3a 25 2d 33 32 73}
		$s15 = {4e 69 63 6b 4e 61 6d 65 3a 25 2d 33 32 73}
		$s19 = {45 6d 61 69 6c 3a 25 2d 33 32 73}
		$s21 = {43 3a 5c 50 72 6f 67}
		$s22 = {24 4c 44 44 41 54 41 24}
		$s31 = {43 6f 70 79 20 46 69 6c 65 20 25 73 20 4f 4b 21}
		$s32 = {25 73 20 53 70 61 63 65 3a 25 75 4d 2c 46 72 65 65 53 70 61 63 65 3a 25 75 4d}
		$s34 = {6f 70 65 6e 3d 25 73}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and ( all of ( $x* ) and 3 of ( $s* ) )
}

rule APT30_Sample_33 : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "72c568ee2dd75406858c0294ccfcf86ad0e390e4"
		id = "be6afc4a-97fe-56ba-b057-e21415f9833d"

	strings:
		$s0 = {56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 20 00 34 00 2e 00 37 00 2e 00 33 00 30 00 30 00 31 00}
		$s1 = {6d 00 73 00 6d 00 73 00 67 00 72 00 2e 00 65 00 78 00 65 00}
		$s2 = {4d 59 55 53 45 52 33 32 2e 64 6c 6c}
		$s3 = {4d 59 41 44 56 41 50 49 33 32 2e 64 6c 6c}
		$s4 = {43 65 6c 65 57 61 72 65 2e 4e 45 54 31}
		$s6 = {4d 59 4d 53 56 43 52 54 2e 64 6c 6c}
		$s7 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 28 00 52 00 29 00 20 00 69 00 73 00 20 00 61 00 20 00 72 00 65 00 67 00 69 00 73 00 74 00 65 00 72 00 65 00 64 00 20 00 74 00 72 00 61 00 64 00 65 00 6d 00 61 00 72 00 6b 00 20 00 6f 00 66 00 20 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00 20 00 69 00 6e 00 20 00 74 00 68 00 65 00}
		$s8 = {57 57 57 2e 43 65 6c 65 57 61 72 65 2e 4e 45 54 31}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and 6 of them
}

rule APT30_Sample_34 : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "216868edbcdd067bd2a9cce4f132d33ba9c0d818"
		id = "a4802e13-4151-5f17-ba91-dcf9ef6b52bb"

	strings:
		$s0 = {64 69 7a 68 69 2e 67 69 66}
		$s1 = {65 61 67 6c 65 73 2e 76 69 70 2e 6e 73 65}
		$s4 = {6f 25 53 3a 53 30}
		$s5 = {6c 61 2f 34 2e 30}
		$s6 = {73 23 21 3c 34 21 32 3e 73 30 32 3d 3d 3c 27 73 31}
		$s7 = {48 6c 6f 62 61 6c 41 6c}
		$s9 = {76 63 4d 69 63 72 6f 73 6f 66 74 48 61 76 65 41 63 6b 37}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_35 : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "df48a7cd6c4a8f78f5847bad3776abc0458499a6"
		id = "8a30720b-06da-5a82-8bab-bf06121afd68"

	strings:
		$s0 = {57 68 42 6f 79 49 45 58 50 4c 4f 52 45 2e 45 58 45 2e 65 78 65}
		$s5 = {53 74 61 72 74 75 70 3e 41}
		$s18 = {6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_1 : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "8cea83299af8f5ec6c278247e649c9d91d4cf3bc"
		id = "e5dd6bc9-9383-5d48-92df-709996373655"

	strings:
		$s0 = {23 68 6f 73 74 69 64}
		$s1 = {5c 57 69 6e 64 6f 77 73 5c 43}
		$s5 = {54 69 6d 55 6d 6f 76 65}
		$s6 = {4d 6f 7a 69 65 61 2f 34 2e 30 20 28 63}
		$s7 = {53 74 61 72 74 75 70 4e 41}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Generic_1 : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		super_rule = 1
		hash0 = "aaa5c64200ff0818c56ebe4c88bcc1143216c536"
		hash1 = "cb4263cab467845dae9fae427e3bbeb31c6a14c2"
		hash2 = "b69b95db8a55a050d6d6c0cba13d73975b8219ca"
		hash3 = "5c29e21bbe8873778f9363258f5e570dddcadeb9"
		hash4 = "d5cb07d178963f2dea2c754d261185ecc94e09d6"
		hash5 = "626dcdd7357e1f8329e9137d0f9883f57ec5c163"
		hash6 = "843997b36ed80d3aeea3c822cb5dc446b6bfa7b9"
		id = "4d21f402-24da-5e38-9225-a1461e61802f"

	strings:
		$s0 = {25 73 5c 25 73 2e 74 78 74}
		$s1 = {5c 6c 64 73 79 73 69 6e 66 6f 2e 74 78 74}
		$s4 = {28 45 78 74 65 6e 64 65 64 20 57 61 6e 73 75 6e 67 29}
		$s6 = {43 6f 6d 70 75 74 65 72 20 4e 61 6d 65 3a}
		$s7 = {25 73 20 25 75 4b 42 20 25 30 34 75 2d 25 30 32 75 2d 25 30 32 75 20 25 30 32 75 3a 25 30 32 75}
		$s8 = {41 53 53 41 4d 45 53 45}
		$s9 = {42 45 4c 41 52 55 53 49 41 4e}
		$s10 = {28 50 52 20 43 68 69 6e 61 29}
		$s14 = {28 46 72 65 6e 63 68 29}
		$s15 = {41 64 76 61 6e 63 65 64 53 65 72 76 65 72}
		$s16 = {44 61 74 61 43 65 6e 74 65 72 53 65 72 76 65 72}
		$s18 = {28 46 69 6e 6c 61 6e 64 29}
		$s19 = {25 73 20 25 30 34 75 2d 25 30 32 75 2d 25 30 32 75 20 25 30 32 75 3a 25 30 32 75}
		$s20 = {28 43 68 69 6c 65 29}

	condition:
		filesize < 250KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Generic_2 : hardened
{
	meta:
		description = "FireEye APT30 Report Sample - from many files"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		super_rule = 1
		hash0 = "aba8b9fa213e5e2f1f0404d13fecc20ea8651b57"
		hash1 = "7f11f5c9475240e5dd2eea7726c9229972cffc1f"
		hash2 = "94d3f91d1e50ecea729617729013c3d143bf2c3e"
		hash3 = "7e516ec04f28c76d67b8111ddfe58bbd628362cc"
		hash4 = "6b27bc0b0460b0a25b45d897ed4f399106c284d9"
		hash5 = "6df5b4b3da0964153bad22fb1f69483ae8316655"
		hash6 = "b68bce61dfd8763c3003480ba4066b3cb1ef126e"
		hash7 = "cc124682246d098740cfa7d20aede850d49b6597"
		hash8 = "1ef415bca310575944934fc97b0aa720943ba512"
		hash9 = "0559ab9356dcc869da18b2c96f48b76478c472b3"
		hash10 = "f15272042a4f9324ad5de884bd50f4072f4bdde3"
		hash11 = "1d93d5f5463cdf85e3c22c56ed1381957f4efaac"
		hash12 = "b6f1fb0f8a2fb92a3c60e154f24cfbca1984529f"
		hash13 = "9967a99a1b627ddb6899919e32a0f544ea498b48"
		hash14 = "95a3c812ca0ad104f045b26c483495129bcf37ca"
		hash15 = "bde9a72b2113d18b4fa537cc080d8d8ba1a231e8"
		hash16 = "ce1f53e06feab1e92f07ed544c288bf39c6fce19"
		hash17 = "72dae031d885dbf492c0232dd1c792ab4785a2dc"
		hash18 = "a2ccba46e40d0fb0dd3e1dba160ecbb5440862ec"
		hash19 = "c8007b59b2d495029cdf5b7b8fc8a5a1f7aa7611"
		hash20 = "9c6f470e2f326a055065b2501077c89f748db763"
		hash21 = "af3e232559ef69bdf2ee9cd96434dcec58afbe5a"
		hash22 = "e72e67ba32946c2702b7662c510cc1242cffe802"
		hash23 = "8fc0b1618b61dce5f18eba01809301cb7f021b35"
		hash24 = "6a8159da055dac928ba7c98ea1cdbe6dfb4a3c22"
		hash25 = "47463412daf0b0a410d3ccbb7ea294db5ff42311"
		hash26 = "e6efa0ccfddda7d7d689efeb28894c04ebc72be2"
		hash27 = "43a3fc9a4fee43252e9a570492e4efe33043e710"
		hash28 = "7406ebef11ca9f97c101b37f417901c70ab514b1"
		hash29 = "53ed9b22084f89b4b595938e320f20efe65e0409"
		id = "60d7d661-50e8-5a9b-8366-eda8ff8ad9d4"

	strings:
		$s0 = {25 73 5c 25 73 5c 4b 42 39 38 35 31 30 39 2e 6c 6f 67}
		$s1 = {25 73 5c 25 73 5c 4b 42 39 38 39 31 30 39 2e 6c 6f 67}
		$s2 = {4f 00 70 00 65 00 72 00 61 00 2e 00 65 00 78 00 65 00}
		$s3 = {25 73 3a 41 6c 6c 20 6f 6e 6c 69 6e 65 20 73 75 63 63 65 73 73 20 6f 6e 20 25 75 21}
		$s4 = {25 73 3a 6c 69 73 74 20 6f 6e 6c 69 6e 65 20 73 75 63 63 65 73 73 20 6f 6e 20 25 75 21}
		$s5 = {25 73 3a 41 6c 6c 20 6f 6e 6c 69 6e 65 20 66 61 69 6c 21}
		$s6 = {43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 4f 00 70 00 65 00 72 00 61 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 20 00 31 00 39 00 39 00 35 00 2d 00}
		$s7 = {25 73 3a 6c 69 73 74 20 6f 6e 6c 69 6e 65 20 66 61 69 6c 21}
		$s8 = {4f 6e 6c 69 6e 65 54 6d 70 2e 74 78 74}
		$s9 = {4f 00 70 00 65 00 72 00 61 00 20 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00}
		$s12 = {4f 00 70 00 65 00 72 00 61 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00}
		$s15 = {43 68 65 63 6b 20 6c 61 6e 20 68 61 76 65 20 64 6f 6e 65 21 21 21}
		$s16 = {4c 69 73 74 20 45 6e 64 2e}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Generic_4 : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		super_rule = 1
		hash0 = "bb390f99bfde234bbed59f6a0d962ba874b2396c"
		hash1 = "b47e20ac5889700438dc241f28f4e224070810d2"
		hash2 = "a9a50673ac000a313f3ddba55d63d9773b9f4143"
		hash3 = "ac96d7f5957aef09bd983465c497de24c6d17a92"
		id = "2b246ae2-ec7d-5813-913e-729e4192da59"

	strings:
		$s0 = {64 65 6c 20 4e 65 74 45 61 67 6c 65 5f 53 63 6f 75 74 2e 62 61 74}
		$s1 = {4e 65 74 45 61 67 6c 65 5f 53 63 6f 75 74 2e 62 61 74}
		$s2 = {5c 76 69 73 69 74 2e 65 78 65}
		$s3 = {5c 53 79 73 74 65 6d 2e 65 78 65}
		$s4 = {5c 53 79 73 74 65 6d 2e 64 61 74}
		$s5 = {5c 69 65 75 70 64 61 74 65 2e 65 78 65}
		$s6 = {47 4f 54 4f 20 45 52 52 4f 52}
		$s7 = {3a 45 52 52 4f 52}
		$s9 = {49 46 20 45 58 49 53 54 20}
		$s10 = {69 6f 69 6f 63 6e}
		$s11 = {53 65 74 46 69 6c 65 41 74 74 72 69 62 75 74 65}
		$s12 = {6c 65 5f 30 2a 5e 69 6c}
		$s13 = {6c 65 5f 2e 2a 5e 69 6c}
		$s14 = {6c 65 5f 2d 2a 5e 69 6c}

	condition:
		filesize < 250KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Generic_5 : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		super_rule = 1
		hash0 = "cb4833220c508182c0ccd4e0d5a867d6c4e675f8"
		hash1 = "dfc9a87df2d585c479ab02602133934b055d156f"
		hash2 = "bf59d5ff7d38ec5ffb91296e002e8742baf24db5"
		id = "e00a670e-cd95-515f-8109-219ce5121ba4"

	strings:
		$s0 = {72 65 67 73 76 72 33 32 20 2f 73 20 22 25 50 72 6f 67 72 61 6d 46 69 6c 65 73 25 5c 4e 6f 72 74 6f 6e 33 36 30 5c 45 6e 67 69 6e 65 5c 35 2e 31 2e 30 2e 32 39 5c 61 73 68 65 6c 70 65 72 2e 64 6c 6c 22}
		$s1 = {6e 61 6d 65 3d 22 66 74 70 73 65 72 76 65 72 2e 65 78 65 22 2f 3e}
		$s2 = {4c 00 69 00 76 00 65 00 55 00 70 00 64 00 61 00 74 00 65 00 2e 00 45 00 58 00 45 00}
		$s3 = {3c 64 65 73 63 72 69 70 74 69 6f 6e 3e 46 54 50 20 45 78 70 6c 6f 72 65 72 3c 2f 64 65 73 63 72 69 70 74 69 6f 6e 3e}
		$s4 = {5c 61 73 68 65 6c 70 65 72 2e 64 6c 6c}
		$s5 = {4c 00 69 00 76 00 65 00 55 00 70 00 64 00 61 00 74 00 65 00}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Generic_6 : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		super_rule = 1
		hash0 = "b9aafb575d3d1732cb8fdca5ea226cebf86ea3c9"
		hash1 = "2c5e347083b77c9ead9e75d41e2fabe096460bba"
		hash2 = "5d39a567b50c74c4a921b5f65713f78023099933"
		id = "dfd104bd-daf4-593a-b161-61f43aec048c"

	strings:
		$s0 = {47 65 74 53 74 61 72}
		$s1 = {2e 72 64 55 61 53}
		$s2 = {25 73 4f 54 77 70 2f 26 41 5c 4c}
		$s3 = {61 20 45 6e 63 72 74 25 20 46 6c 61 73 68 20 44 69 73 6b}
		$s4 = {79 70 65 41 75 74 6f 52 75 43 68 65 63}
		$s5 = {4e 6f 44 72 69 76 65 54}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Generic_7 : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		super_rule = 1
		hash0 = "2415f661046fdbe3eea8cd276b6f13354019b1a6"
		hash1 = "e814914079af78d9f1b71000fee3c29d31d9b586"
		hash2 = "0263de239ccef669c47399856d481e3361408e90"
		id = "bba40092-267b-5231-92f1-f222c9f888ee"

	strings:
		$s1 = {58 6a 61 70 6f 72 5f 2a 61 74 61}
		$s2 = {58 6a 61 70 6f 72 5f 6f 2a 61 74 61}
		$s4 = {4f 75 6f 70 61 69}

	condition:
		filesize < 100KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Generic_8 : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		super_rule = 1
		hash0 = "b47e20ac5889700438dc241f28f4e224070810d2"
		hash1 = "a9a50673ac000a313f3ddba55d63d9773b9f4143"
		hash2 = "ac96d7f5957aef09bd983465c497de24c6d17a92"
		id = "a6845222-0a3e-5327-a448-36e8d54362a5"

	strings:
		$s0 = {57 69 6e 64 6f 77 73 20 4e 54 34 2e 30}
		$s1 = {57 69 6e 64 6f 77 73 20 4e 54 33 2e 35 31}
		$s2 = {25 64 3b 25 64 3b 25 64 3b 25 6c 64 3b 25 6c 64 3b 25 6c 64 3b}
		$s3 = {25 73 20 25 64 2e 25 64 20 42 75 69 6c 64 25 64 20 25 73}
		$s4 = {4d 53 41 46 44 20 54 63 70 69 70 20 5b 54 43 50 2f 49 50 5d}
		$s5 = {53 51 53 52 53 53}
		$s8 = {57 4d 5f 43 4f 4d 50}
		$s9 = {57 4d 5f 4d 42 55}
		$s11 = {57 4d 5f 47 52 49 44}
		$s12 = {57 4d 5f 52 42 55}

	condition:
		filesize < 250KB and uint16( 0 ) == 0x5A4D and all of them
}

rule APT30_Generic_9 : hardened
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		super_rule = 1
		hash0 = "00d9949832dc3533592c2ce06a403ef19deddce9"
		hash1 = "27a2b981d4c0bb8c3628bfe990db4619ddfdff74"
		hash2 = "05f66492c163ec2a24c6a87c7a43028c5f632437"
		hash3 = "263f094da3f64e72ef8dc3d02be4fb33de1fdb96"
		id = "cf259f8d-e0a9-579d-93e7-ec14d99faf81"

	strings:
		$s0 = {25 73 5c 25 73 5c 24 4e 74 52 65 63 44 6f 63 24}
		$s1 = {25 73 28 25 75 29 25 73}
		$s2 = {68 74 74 70 3a 2f 2f 25 73 25 73 25 73}
		$s3 = {31 00 2e 00 39 00 2e 00 31 00 2e 00 31 00 37 00}
		$s4 = {28 00 43 00 29 00 46 00 69 00 72 00 65 00 66 00 6f 00 78 00 20 00 61 00 6e 00 64 00 20 00 4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 20 00 44 00 65 00 76 00 65 00 6c 00 6f 00 70 00 65 00 72 00 73 00 2c 00 20 00 61 00 63 00 63 00 6f 00 72 00 64 00 69 00 6e 00 67 00 20 00 74 00 6f 00 20 00 74 00 68 00 65 00 20 00 4d 00 50 00 4c 00 20 00 31 00 2e 00 31 00 2f 00 47 00 50 00 4c 00 20 00 32 00 2e 00 30 00 2f 00 4c 00 47 00 50 00 4c 00}

	condition:
		filesize < 250KB and uint16( 0 ) == 0x5A4D and all of them
}

