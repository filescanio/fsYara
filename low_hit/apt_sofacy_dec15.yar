rule Sofacy_Malware_StrangeSpaces : hardened
{
	meta:
		description = "Detetcs strange strings from Sofacy malware with many spaces"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
		date = "2015-12-04"
		id = "60f99b88-f256-5289-852c-c0bf27f1cbd4"

	strings:
		$s2 = {44 00 65 00 6c 00 65 00 74 00 65 00 20 00 54 00 65 00 6d 00 70 00 20 00 46 00 6f 00 6c 00 64 00 65 00 72 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00}
		$s3 = {20 00 4f 00 70 00 65 00 72 00 61 00 74 00 69 00 6e 00 67 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00}
		$s4 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00}
		$s5 = {20 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 20 00 41 00 6c 00 6c 00 20 00 72 00 69 00 67 00 68 00 74 00 73 00 20 00 72 00 65 00 73 00 65 00 72 00 76 00 65 00 64 00 2e 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 50KB and 3 of them
}

rule Sofacy_Malware_AZZY_Backdoor_1 : hardened
{
	meta:
		description = "AZZY Backdoor - Sample 1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
		date = "2015-12-04"
		hash = "a9dc96d45702538c2086a749ba2fb467ba8d8b603e513bdef62a024dfeb124cb"
		id = "184dc45e-8014-5dcf-a033-d77586c60fdf"

	strings:
		$s0 = {61 00 64 00 76 00 73 00 74 00 6f 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 64 00 6c 00 6c 00}
		$s1 = {61 64 76 73 68 65 6c 6c 73 74 6f 72 65 2e 64 6c 6c}
		$s2 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 41 00 64 00 76 00 61 00 6e 00 63 00 65 00 64 00 20 00 53 00 74 00 6f 00 72 00 61 00 67 00 65 00 20 00 53 00 68 00 65 00 6c 00 6c 00 20 00 45 00 78 00 74 00 65 00 6e 00 73 00 69 00 6f 00 6e 00 20 00 44 00 4c 00 4c 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 150KB and 2 of them
}

rule Sofacy_AZZY_Backdoor_Implant_1 : hardened
{
	meta:
		description = "AZZY Backdoor Implant 4.3 - Sample 1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
		date = "2015-12-04"
		hash = "1bab1a3e0e501d3c14652ecf60870e483ed4e90e500987c35489f17a44fef26c"
		id = "ec6bf8ca-ccb9-532e-8b0d-1fba59efa2da"

	strings:
		$s1 = {5c 00 74 00 66 00 33 00 39 00 34 00 6b 00 76 00 2e 00 64 00 6c 00 6c 00}
		$s2 = {44 57 4e 5f 44 4c 4c 5f 4d 41 49 4e 2e 64 6c 6c}
		$s3 = {3f 53 65 6e 64 44 61 74 61 54 6f 53 65 72 76 65 72 5f 32 40 40 59 47 48 50 41 45 4b 45 50 41 50 41 45 50 41 4b 40 5a}
		$s4 = {3f 41 70 70 6c 69 63 61 74 65 40 40 59 47 48 58 5a}
		$s5 = {3f 6b 40 40 59 47 50 41 55 48 49 4e 53 54 41 4e 43 45 5f 5f 40 40 50 42 44 40 5a}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 300KB and 2 of them
}

rule Sofacy_AZZY_Backdoor_HelperDLL : hardened
{
	meta:
		description = "Dropped C&C helper DLL for AZZY 4.3"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
		date = "2015-12-04"
		hash = "6cd30c85dd8a64ca529c6eab98a757fb326de639a39b597414d5340285ba91c6"
		id = "eae089a0-21dc-5d6e-a4bc-7181dc9b8b35"

	strings:
		$s0 = {73 6e 64 2e 64 6c 6c}
		$s1 = {49 6e 74 65 72 6e 65 74 45 78 63 68 61 6e 67 65}
		$s2 = {53 65 6e 64 44 61 74 61}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 100KB and all of them
}

rule Sofacy_CollectorStealer_Gen1 : hardened
{
	meta:
		description = "Generic rule to detect Sofacy Malware Collector Stealer"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
		date = "2015-12-04"
		super_rule = 1
		hash1 = "4e4606313c423b681e11110ca5ed3a2b2632ec6c556b7ab9642372ae709555f3"
		hash2 = "92dcb0d8394d0df1064e68d90cd90a6ae5863e91f194cbaac85ec21c202f581f"
		id = "f9462dd9-f6b6-59f4-a443-12d6f3be444e"

	strings:
		$s0 = {4e 76 43 70 6c 64 2e 64 6c 6c}
		$s1 = {4e 76 53 74 6f 70}
		$s2 = {4e 76 53 74 61 72 74}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 300KB and all of them
}

rule Sofacy_CollectorStealer_Gen2 : hardened
{
	meta:
		description = "File collectors / USB stealers - Generic"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
		date = "2015-12-04"
		hash = "e917166adf6e1135444f327d8fff6ec6c6a8606d65dda4e24c2f416d23b69d45"
		hash = "92dcb0d8394d0df1064e68d90cd90a6ae5863e91f194cbaac85ec21c202f581f"
		hash = "b1f2d461856bb6f2760785ee1af1a33c71f84986edf7322d3e9bd974ca95f92d"
		id = "03ced94f-de20-56c5-bf17-1ec7d8610684"

	strings:
		$s1 = {6d 73 64 65 74 6c 74 65 6d 70 2e 64 6c 6c}
		$s2 = {6d 00 73 00 64 00 65 00 6c 00 74 00 65 00 6d 00 70 00 2e 00 64 00 6c 00 6c 00}
		$s3 = {44 00 65 00 6c 00 65 00 74 00 65 00 20 00 54 00 65 00 6d 00 70 00 20 00 46 00 6f 00 6c 00 64 00 65 00 72 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 100KB and 2 of them
}

rule Sofacy_CollectorStealer_Gen3 : hardened
{
	meta:
		description = "File collectors / USB stealers - Generic"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
		date = "2015-12-04"
		hash = "92dcb0d8394d0df1064e68d90cd90a6ae5863e91f194cbaac85ec21c202f581f"
		hash = "4e4606313c423b681e11110ca5ed3a2b2632ec6c556b7ab9642372ae709555f3"
		id = "d2ee1a22-6aae-51fc-9043-a7ba99769376"

	strings:
		$s1 = {4e 76 43 70 6c 64 2e 64 6c 6c}
		$s4 = {4e 76 53 74 61 72 74}
		$s5 = {4e 76 53 74 6f 70}
		$a1 = {25 00 2e 00 34 00 64 00 25 00 2e 00 32 00 64 00 25 00 2e 00 32 00 64 00 25 00 2e 00 32 00 64 00 25 00 2e 00 32 00 64 00 25 00 2e 00 32 00 64 00 25 00 2e 00 32 00 64 00 25 00 2e 00 34 00 64 00}
		$a2 = {49 00 47 00 46 00 53 00 52 00 56 00 43 00 2e 00 64 00 6c 00 6c 00}
		$a3 = {43 00 6f 00 6d 00 6d 00 6f 00 6e 00 20 00 55 00 73 00 65 00 72 00 20 00 49 00 6e 00 74 00 65 00 72 00 66 00 61 00 63 00 65 00}
		$a4 = {69 00 67 00 66 00 73 00 72 00 76 00 63 00 20 00 4d 00 6f 00 64 00 75 00 6c 00 65 00}
		$b1 = {20 00 4f 00 70 00 65 00 72 00 61 00 74 00 69 00 6e 00 67 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00}
		$b2 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 150KB and ( all of ( $s* ) and ( all of ( $a* ) or all of ( $b* ) ) )
}

