rule Msfpayloads_msf : hardened
{
	meta:
		description = "Metasploit Payloads - file msf.sh"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-02-09"
		modified = "2022-08-18"
		hash1 = "320a01ec4e023fb5fbbaef963a2b57229e4f918847e5a49c7a3f631cb556e96c"
		id = "c56dbb8e-1e03-5112-b2ef-a0adfd14dffa"

	strings:
		$s1 = {65 78 70 6f 72 74 20 62 75 66 3d 5c}

	condition:
		filesize < 5MB and $s1
}

rule Msfpayloads_msf_2 : hardened
{
	meta:
		description = "Metasploit Payloads - file msf.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-02-09"
		hash1 = "e52f98466b92ee9629d564453af6f27bd3645e00a9e2da518f5a64a33ccf8eb5"
		id = "ec1ae1b6-18a3-5590-ae15-1e2b362c545a"

	strings:
		$s1 = {26 20 22 5c 5c 22 20 26 20 22 73 76 63 68 6f 73 74 2e 65 78 65 22}
		$s2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 73 63 72 69 70 74 2e 53 68 65 6c 6c 22 29}
		$s3 = {3c 25 20 40 6c 61 6e 67 75 61 67 65 3d 22 56 42 53 63 72 69 70 74 22 20 25 3e}

	condition:
		all of them
}

rule Msfpayloads_msf_psh : hardened
{
	meta:
		description = "Metasploit Payloads - file msf-psh.vba"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-02-09"
		hash1 = "5cc6c7f1aa75df8979be4a16e36cece40340c6e192ce527771bdd6463253e46f"
		id = "5b760f03-b0f8-5871-bd34-e7e44443530c"

	strings:
		$s1 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 6e 6f 70 20 2d 77 20 68 69 64 64 65 6e 20 2d 65}
		$s2 = {43 61 6c 6c 20 53 68 65 6c 6c 28}
		$s3 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29}

	condition:
		all of them
}

rule Msfpayloads_msf_exe : hardened
{
	meta:
		description = "Metasploit Payloads - file msf-exe.vba"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-02-09"
		hash1 = "321537007ea5052a43ffa46a6976075cee6a4902af0c98b9fd711b9f572c20fd"
		id = "fd07240e-0ee0-5318-a436-d97054e92414"

	strings:
		$s1 = {27 2a 20 50 41 59 4c 4f 41 44 20 44 41 54 41}
		$s2 = {20 3d 20 53 68 65 6c 6c 28}
		$s3 = {3d 20 45 6e 76 69 72 6f 6e 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29}
		$s4 = {27 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a}
		$s5 = {43 68 44 69 72 20 28}
		$s6 = {27 2a 20 4d 41 43 52 4f 20 43 4f 44 45}

	condition:
		4 of them
}

rule Msfpayloads_msf_3 : hardened
{
	meta:
		description = "Metasploit Payloads - file msf.psh"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-02-09"
		hash1 = "335cfb85e11e7fb20cddc87e743b9e777dc4ab4e18a39c2a2da1aa61efdbd054"
		id = "ad09167f-a12a-5f07-940b-df679fa8e6c0"
		score = 80

	strings:
		$s1 = {5b 44 6c 6c 49 6d 70 6f 72 74 28 22 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 22 29 5d 20 70 75 62 6c 69 63 20 73 74 61 74 69 63 20 65 78 74 65 72 6e 20 69 6e 74 20 57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 28}
		$s2 = {70 75 62 6c 69 63 20 65 6e 75 6d 20 4d 65 6d 6f 72 79 50 72 6f 74 65 63 74 69 6f 6e 20 7b 20 45 78 65 63 75 74 65 52 65 61 64 57 72 69 74 65 20 3d 20 30 78 34 30 20 7d}
		$s3 = {2e 66 75 6e 63 5d 3a 3a 56 69 72 74 75 61 6c 41 6c 6c 6f 63 28 30 2c}
		$s4 = {2e 66 75 6e 63 2b 41 6c 6c 6f 63 61 74 69 6f 6e 54 79 70 65 5d 3a 3a 52 65 73 65 72 76 65 20 2d 62 4f 72 20 5b}
		$s5 = {4e 65 77 2d 4f 62 6a 65 63 74 20 53 79 73 74 65 6d 2e 43 6f 64 65 44 6f 6d 2e 43 6f 6d 70 69 6c 65 72 2e 43 6f 6d 70 69 6c 65 72 50 61 72 61 6d 65 74 65 72 73}
		$s6 = {52 65 66 65 72 65 6e 63 65 64 41 73 73 65 6d 62 6c 69 65 73 2e 41 64 64 52 61 6e 67 65 28 40 28 22 53 79 73 74 65 6d 2e 64 6c 6c 22 2c 20 5b 50 73 4f 62 6a 65 63 74 5d 2e 41 73 73 65 6d 62 6c 79 2e 4c 6f 63 61 74 69 6f 6e 29 29}
		$s7 = {70 75 62 6c 69 63 20 65 6e 75 6d 20 41 6c 6c 6f 63 61 74 69 6f 6e 54 79 70 65 20 7b 20 43 6f 6d 6d 69 74 20 3d 20 30 78 31 30 30 30 2c 20 52 65 73 65 72 76 65 20 3d 20 30 78 32 30 30 30 20 7d}
		$s8 = {2e 66 75 6e 63 5d 3a 3a 43 72 65 61 74 65 54 68 72 65 61 64 28 30 2c 30 2c 24}
		$s9 = {70 75 62 6c 69 63 20 65 6e 75 6d 20 54 69 6d 65 20 3a 20 75 69 6e 74 20 7b 20 49 6e 66 69 6e 69 74 65 20 3d 20 30 78 46 46 46 46 46 46 46 46 20 7d}
		$s10 = {3d 20 5b 53 79 73 74 65 6d 2e 43 6f 6e 76 65 72 74 5d 3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 22 2f}
		$s11 = {7b 20 24 67 6c 6f 62 61 6c 3a 72 65 73 75 6c 74 20 3d 20 33 3b 20 72 65 74 75 72 6e 20 7d}

	condition:
		4 of them
}

rule Msfpayloads_msf_4 : hardened
{
	meta:
		description = "Metasploit Payloads - file msf.aspx"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-02-09"
		hash1 = "26b3e572ba1574164b76c6d5213ab02e4170168ae2bcd2f477f246d37dbe84ef"
		id = "00d7681b-6041-5fe1-adbb-8b7c40df0193"

	strings:
		$s1 = {3d 20 56 69 72 74 75 61 6c 41 6c 6c 6f 63 28 49 6e 74 50 74 72 2e 5a 65 72 6f 2c 28 55 49 6e 74 50 74 72 29}
		$s2 = {2e 4c 65 6e 67 74 68 2c 4d 45 4d 5f 43 4f 4d 4d 49 54 2c 20 50 41 47 45 5f 45 58 45 43 55 54 45 5f 52 45 41 44 57 52 49 54 45 29 3b}
		$s3 = {5b 53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 49 6e 74 65 72 6f 70 53 65 72 76 69 63 65 73 2e 44 6c 6c 49 6d 70 6f 72 74 28 22 6b 65 72 6e 65 6c 33 32 22 29 5d}
		$s4 = {70 72 69 76 61 74 65 20 73 74 61 74 69 63 20 49 6e 74 50 74 72 20 50 41 47 45 5f 45 58 45 43 55 54 45 5f 52 45 41 44 57 52 49 54 45 3d 28 49 6e 74 50 74 72 29 30 78 34 30 3b}
		$s5 = {70 72 69 76 61 74 65 20 73 74 61 74 69 63 20 65 78 74 65 72 6e 20 49 6e 74 50 74 72 20 56 69 72 74 75 61 6c 41 6c 6c 6f 63 28 49 6e 74 50 74 72 20 6c 70 53 74 61 72 74 41 64 64 72 2c 55 49 6e 74 50 74 72 20 73 69 7a 65 2c 49 6e 74 33 32 20 66 6c 41 6c 6c 6f 63 61 74 69 6f 6e 54 79 70 65 2c 49 6e 74 50 74 72 20 66 6c 50 72 6f 74 65 63 74 29 3b}

	condition:
		4 of them
}

rule Msfpayloads_msf_exe_2 : hardened
{
	meta:
		description = "Metasploit Payloads - file msf-exe.aspx"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-02-09"
		hash1 = "3a2f7a654c1100e64d8d3b4cd39165fba3b101bbcce6dd0f70dae863da338401"
		id = "a55a33e1-8f04-5417-af0c-b7e2da36fb46"

	strings:
		$x1 = {3d 20 6e 65 77 20 53 79 73 74 65 6d 2e 44 69 61 67 6e 6f 73 74 69 63 73 2e 50 72 6f 63 65 73 73 28 29 3b}
		$x2 = {2e 53 74 61 72 74 49 6e 66 6f 2e 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 20 3d 20 74 72 75 65 3b}
		$x3 = {2c 20 22 73 76 63 68 6f 73 74 2e 65 78 65 22 29 3b}
		$s4 = {20 3d 20 50 61 74 68 2e 47 65 74 54 65 6d 70 50 61 74 68 28 29 3b}

	condition:
		all of them
}

rule Msfpayloads_msf_5 : hardened
{
	meta:
		description = "Metasploit Payloads - file msf.msi"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-02-09"
		hash1 = "7a6c66dfc998bf5838993e40026e1f400acd018bde8d4c01ef2e2e8fba507065"
		id = "030d1982-c9a8-539d-a995-7901ae425857"

	strings:
		$s1 = {72 65 71 75 69 72 65 64 20 74 6f 20 69 6e 73 74 61 6c 6c 20 46 6f 6f 62 61 72 20 31 2e 30 2e}
		$s2 = {43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 32 00 30 00 30 00 39 00 20 00 54 00 68 00 65 00 20 00 41 00 70 00 61 00 63 00 68 00 65 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 20 00 46 00 6f 00 75 00 6e 00 64 00 61 00 74 00 69 00 6f 00 6e 00 2e 00}
		$s3 = {7b 35 30 46 33 36 44 38 39 2d 35 39 41 38 2d 34 41 34 30 2d 39 36 38 39 2d 38 37 39 32 30 32 39 31 31 33 41 43 7d}

	condition:
		all of them
}

rule Msfpayloads_msf_6 : hardened
{
	meta:
		description = "Metasploit Payloads - file msf.vbs"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-02-09"
		hash1 = "8d6f55c6715c4a2023087c3d0d7abfa21e31a629393e4dc179d31bb25b166b3f"
		id = "5485102b-e709-5111-814a-e6878b4bd889"
		score = 50

	strings:
		$s1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 73 63 72 69 70 74 2e 53 68 65 6c 6c 22 29}
		$s2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29}
		$s3 = {2e 47 65 74 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 28 32 29}
		$s4 = {2e 57 72 69 74 65 20 43 68 72 28 43 4c 6e 67 28 22}
		$s5 = {3d 20 22 34 64 35 61 39 30 30 30 30 33 30 30 30 30 30 30 30 34 30 30 30 30 30 30 66 66 66 66 30 30}
		$s6 = {46 6f 72 20 69 20 3d 20 31 20 74 6f 20 4c 65 6e 28}
		$s7 = {29 20 53 74 65 70 20 32}

	condition:
		5 of them
}

rule Msfpayloads_msf_7 : hardened
{
	meta:
		description = "Metasploit Payloads - file msf.vba"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-02-09"
		hash1 = "425beff61a01e2f60773be3fcb74bdfc7c66099fe40b9209745029b3c19b5f2f"
		id = "8d1b742e-510a-5807-ad3f-f10cc325d292"

	strings:
		$s1 = {50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 46 75 6e 63 74 69 6f 6e 20 43 72 65 61 74 65 54 68 72 65 61 64 20 4c 69 62 20 22 6b 65 72 6e 65 6c 33 32 22 20 28 42 79 56 61 6c}
		$s2 = {3d 20 56 69 72 74 75 61 6c 41 6c 6c 6f 63 28 30 2c 20 55 42 6f 75 6e 64 28 54 73 77 29 2c 20 26 48 31 30 30 30 2c 20 26 48 34 30 29}
		$s3 = {3d 20 52 74 6c 4d 6f 76 65 4d 65 6d 6f 72 79 28}

	condition:
		all of them
}

rule Msfpayloads_msf_8 : hardened
{
	meta:
		description = "Metasploit Payloads - file msf.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-02-09"
		hash1 = "519717e01f0cb3f460ef88cd70c3de8c7f00fb7c564260bd2908e97d11fde87f"
		id = "54466663-12ef-5fa4-a13c-e80ddbc0f4f8"

	strings:
		$s1 = {5b 44 6c 6c 49 6d 70 6f 72 74 28 22 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 22 29 5d}
		$s2 = {5b 44 6c 6c 49 6d 70 6f 72 74 28 22 6d 73 76 63 72 74 2e 64 6c 6c 22 29 5d}
		$s3 = {2d 4e 61 6d 65 20 22 57 69 6e 33 32 22 20 2d 6e 61 6d 65 73 70 61 63 65 20 57 69 6e 33 32 46 75 6e 63 74 69 6f 6e 73 20 2d 70 61 73 73 74 68 72 75}
		$s4 = {3a 3a 56 69 72 74 75 61 6c 41 6c 6c 6f 63 28 30 2c 5b 4d 61 74 68 5d 3a 3a 4d 61 78 28 24}
		$s5 = {2e 4c 65 6e 67 74 68 2c 30 78 31 30 30 30 29 2c 30 78 33 30 30 30 2c 30 78 34 30 29}
		$s6 = {70 75 62 6c 69 63 20 73 74 61 74 69 63 20 65 78 74 65 72 6e 20 49 6e 74 50 74 72 20 56 69 72 74 75 61 6c 41 6c 6c 6f 63 28 49 6e 74 50 74 72 20 6c 70 41 64 64 72 65 73 73 2c 20 75 69 6e 74 20 64 77 53 69 7a 65 2c 20 75 69 6e 74 20 66 6c 41 6c 6c 6f 63 61 74 69 6f 6e 54 79 70 65 2c 20 75 69 6e 74 20 66 6c 50 72 6f 74 65 63 74 29 3b}
		$s7 = {3a 3a 6d 65 6d 73 65 74 28 5b 49 6e 74 50 74 72 5d 28 24}

	condition:
		6 of them
}

rule Msfpayloads_msf_cmd : hardened
{
	meta:
		description = "Metasploit Payloads - file msf-cmd.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-02-09"
		score = 60
		hash1 = "9f41932afc9b6b4938ee7a2559067f4df34a5c8eae73558a3959dd677cb5867f"
		id = "71d42c34-a0b0-5173-8f2f-f48a7af0e4ff"

	strings:
		$x1 = {25 43 4f 4d 53 50 45 43 25 20 2f 62 20 2f 63 20 73 74 61 72 74 20 2f 62 20 2f 6d 69 6e 20 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 6e 6f 70 20 2d 77 20 68 69 64 64 65 6e 20 2d 65}

	condition:
		all of them
}

rule Msfpayloads_msf_9 : hardened
{
	meta:
		description = "Metasploit Payloads - file msf.war - contents"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-02-09"
		hash1 = "e408678042642a5d341e8042f476ee7cef253871ef1c9e289acf0ee9591d1e81"
		id = "488a2e97-ebc2-5ccf-ab5d-dfed4b534b52"

	strings:
		$s1 = {69 66 20 28 53 79 73 74 65 6d 2e 67 65 74 50 72 6f 70 65 72 74 79 28 22 6f 73 2e 6e 61 6d 65 22 29 2e 74 6f 4c 6f 77 65 72 43 61 73 65 28 29 2e 69 6e 64 65 78 4f 66 28 22 77 69 6e 64 6f 77 73 22 29 20 21 3d 20 2d 31 29}
		$s2 = {2e 63 6f 6e 63 61 74 28 22 2e 65 78 65 22 29 3b}
		$s3 = {5b 30 5d 20 3d 20 22 63 68 6d 6f 64 22 3b}
		$s4 = {3d 20 52 75 6e 74 69 6d 65 2e 67 65 74 52 75 6e 74 69 6d 65 28 29 2e 65 78 65 63 28}
		$s5 = {2c 20 31 36 29 20 26 20 30 78 66 66 3b}
		$x1 = {34 64 35 61 39 30 30 30 30 33 30 30 30 30 30 30 30}

	condition:
		4 of ( $s* ) or ( uint32( 0 ) == 0x61356434 and $x1 at 0 )
}

rule Msfpayloads_msf_10 : hardened
{
	meta:
		description = "Metasploit Payloads - file msf.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-02-09"
		hash1 = "3cd74fa28323c0d64f45507675ac08fb09bae4dd6b7e11f2832a4fbc70bb7082"
		id = "3bc3b66a-9f8a-55c2-ae2a-00faa778cef7"
		score = 70

	strings:
		$s1 = { 0c 8b 52 14 8b 72 28 0f b7 4a 26 31 ff ac 3c 61 }
		$s2 = { 01 c7 38 e0 75 f6 03 7d f8 3b 7d 24 75 e4 58 8b }
		$s3 = { 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0 5f 5f }

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 200KB and all of them )
}

rule Msfpayloads_msf_svc : hardened
{
	meta:
		description = "Metasploit Payloads - file msf-svc.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-02-09"
		hash1 = "2b02c9c10577ee0c7590d3dadc525c494122747a628a7bf714879b8e94ae5ea1"
		id = "45d1c527-1f90-50f3-8e64-e77d69386b0a"

	strings:
		$s1 = {50 41 59 4c 4f 41 44 3a}
		$s2 = {2e 65 78 65 68 6c 6c}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 50KB and all of them )
}

rule Msfpayloads_msf_11 : hardened
{
	meta:
		description = "Metasploit Payloads - file msf.hta"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-02-09"
		hash1 = "d1daf7bc41580322333a893133d103f7d67f5cd8a3e0f919471061d41cf710b6"
		id = "59b0cced-ffdc-5f2f-878c-856883ee275f"

	strings:
		$s1 = {2e 45 78 70 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 28 22 25 50 53 4d 6f 64 75 6c 65 50 61 74 68 25 22 29 20 2b 20 22 2e 2e 5c 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 22 29 20 54 68 65 6e}
		$s2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29}
		$s3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 73 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 20}

	condition:
		all of them
}

rule Msfpayloads_msf_ref : hardened
{
	meta:
		description = "Metasploit Payloads - file msf-ref.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-02-09"
		hash1 = "4ec95724b4c2b6cb57d2c63332a1dd6d4a0101707f42e3d693c9aab19f6c9f87"
		id = "517ed365-03c6-5563-984b-dae10464671a"
		score = 70

	strings:
		$s1 = {6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 20 57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 29 2c}
		$s2 = {3d 20 28 5b 41 70 70 44 6f 6d 61 69 6e 5d 3a 3a 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e 2e 47 65 74 41 73 73 65 6d 62 6c 69 65 73 28 29 20 7c 20 57 68 65 72 65 2d 4f 62 6a 65 63 74 20 7b 20 24 5f 2e 47 6c 6f 62 61 6c 41 73 73 65 6d 62 6c 79 43 61 63 68 65 20 2d 41 6e 64 20 24 5f 2e 4c 6f 63 61 74 69 6f 6e 2e 53 70 6c 69 74 28 27 5c 5c 27 29}
		$s3 = {47 65 74 4d 65 74 68 6f 64 28 27 47 65 74 50 72 6f 63 41 64 64 72 65 73 73 27 29 2e 49 6e 76 6f 6b 65 28 24 6e 75 6c 6c 2c 20 40 28 5b 53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 49 6e 74 65 72 6f 70 53 65 72 76 69 63 65 73 2e 48 61 6e 64 6c 65 52 65 66 5d 28 4e 65 77 2d 4f 62 6a 65 63 74}
		$s4 = {2e 44 65 66 69 6e 65 4d 65 74 68 6f 64 28 27 49 6e 76 6f 6b 65 27 2c 20 27 50 75 62 6c 69 63 2c 20 48 69 64 65 42 79 53 69 67 2c 20 4e 65 77 53 6c 6f 74 2c 20 56 69 72 74 75 61 6c 27 2c}
		$s5 = {3d 20 5b 53 79 73 74 65 6d 2e 43 6f 6e 76 65 72 74 5d 3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28}
		$s6 = {5b 50 61 72 61 6d 65 74 65 72 28 50 6f 73 69 74 69 6f 6e 20 3d 20 30 2c 20 4d 61 6e 64 61 74 6f 72 79 20 3d 20 24 54 72 75 65 29 5d 20 5b 54 79 70 65 5b 5d 5d}
		$s7 = {44 65 66 69 6e 65 43 6f 6e 73 74 72 75 63 74 6f 72 28 27 52 54 53 70 65 63 69 61 6c 4e 61 6d 65 2c 20 48 69 64 65 42 79 53 69 67 2c 20 50 75 62 6c 69 63 27 2c 20 5b 53 79 73 74 65 6d 2e 52 65 66 6c 65 63 74 69 6f 6e 2e 43 61 6c 6c 69 6e 67 43 6f 6e 76 65 6e 74 69 6f 6e 73 5d 3a 3a 53 74 61 6e 64 61 72 64 2c}

	condition:
		5 of them
}

rule MAL_Metasploit_Framework_UA : hardened
{
	meta:
		description = "Detects User Agent used in Metasploit Framework"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/rapid7/metasploit-framework/commit/12a6d67be48527f5d3987e40cac2a0cbb4ab6ce7"
		date = "2018-08-16"
		score = 65
		hash1 = "1743e1bd4176ffb62a1a0503a0d76033752f8bd34f6f09db85c2979c04bbdd29"
		id = "e5a18456-3a07-5b58-ad95-086152298a1f"

	strings:
		$s3 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 36 2e 31 3b 20 57 69 6e 64 6f 77 73 20 4e 54 29}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 400KB and 1 of them
}

rule HKTL_Meterpreter_inMemory : hardened
{
	meta:
		description = "Detects Meterpreter in-memory"
		author = "netbiosX, Florian Roth"
		reference = "https://www.reddit.com/r/purpleteamsec/comments/hjux11/meterpreter_memory_indicators_detection_tooling/"
		date = "2020-06-29"
		modified = "2023-04-21"
		score = 85
		id = "29c3bb7e-4da8-5924-ada7-2f28d9352009"

	strings:
		$sxc1 = { 6D 65 74 73 72 76 2E 64 6C 6C 00 00 52 65 66 6C
               65 63 74 69 76 65 4C 6F 61 64 65 72 }
		$sxs1 = {6d 65 74 73 72 76 2e 78 36 34 2e 64 6c 6c}
		$ss1 = {57 53 32 5f 33 32 2e 64 6c 6c}
		$ss2 = {52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72}
		$fp1 = {((53 65 6e 74 69 6e 65 6c 4f 6e 65) | (53 00 65 00 6e 00 74 00 69 00 6e 00 65 00 6c 00 4f 00 6e 00 65 00))}
		$fp2 = {((66 6f 72 74 69 45 53 4e 41 43) | (66 00 6f 00 72 00 74 00 69 00 45 00 53 00 4e 00 41 00 43 00))}
		$fp3 = {((50 53 4e 4d 56 48 6f 6f 6b 4d 53) | (50 00 53 00 4e 00 4d 00 56 00 48 00 6f 00 6f 00 6b 00 4d 00 53 00))}

	condition:
		(1 of ( $sx* ) or 2 of ( $s* ) ) and not 1 of ( $fp* )
}

