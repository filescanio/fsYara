rule Andromeda_MalBot_Jun_1A : hardened
{
	meta:
		description = "Detects a malicious Worm Andromeda / RETADUP"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://blog.trendmicro.com/trendlabs-security-intelligence/information-stealer-found-hitting-israeli-hospitals/"
		date = "2017-06-30"
		modified = "2022-12-21"
		score = 50
		hash1 = "3c223bbf83ac2f91c79383a53ed15b0c8ffe2caa1bf52b26c17fd72278dc7ef9"
		hash2 = "73cecc67bb12cf5a837af9fba15b7792a6f1a746b246b34f8ed251c4372f1a98"
		hash3 = "66035cc81e811735beab573013950153749b02703eae58b90430646f6e3e3eb4"
		hash4 = "42a02e6cf7c424c12f078fca21805de072842ec52a25ea87bd7d53e7feb536ed"
		id = "42ee6ba3-85ea-5369-bd9b-8ffdec6e17bc"

	strings:
		$x1 = {25 00 74 00 65 00 6d 00 70 00 25 00 5c 00 46 00 6f 00 6c 00 64 00 65 00 72 00 4e 00 5c 00 6e 00 61 00 6d 00 65 00 2e 00 65 00 78 00 65 00}
		$x2 = {25 00 74 00 65 00 6d 00 70 00 25 00 5c 00 46 00 6f 00 6c 00 64 00 65 00 72 00 4e 00 5c 00 6e 00 61 00 6d 00 65 00 2e 00 65 00 78 00 65 00 2e 00 6c 00 6e 00 6b 00}
		$x3 = {5c 00 53 00 74 00 61 00 72 00 74 00 75 00 70 00 5c 00 6e 00 61 00 6d 00 65 00 2e 00 65 00 78 00 65 00}
		$x4 = {66 00 69 00 72 00 65 00 66 00 6f 00 78 00 2e 00 65 00 78 00 65 00 2e 00 65 00 78 00 65 00}
		$x5 = {5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 4e 00 65 00 77 00 20 00 66 00 6f 00 6c 00 64 00 65 00 72 00 5c 00 64 00 61 00 72 00 6b 00 2e 00 65 00 78 00 65 00}
		$x6 = {5c 78 38 36 5c 52 65 6c 65 61 73 65 5c 77 6f 72 64 2e 70 64 62}
		$x7 = {5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 62 6f 74 6b 69 6c 6c 2e 70 64 62}
		$s1 = {34 53 79 73 74 65 6d 2e 57 65 62 2e 53 65 72 76 69 63 65 73 2e 50 72 6f 74 6f 63 6f 6c 73 2e 53 6f 61 70 48 74 74 70 43 6c 69 65 6e 74 50 72 6f 74 6f 63 6f 6c}
		$s2 = {73 00 76 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 2000KB and ( 1 of ( $x* ) or 2 of them )
}

