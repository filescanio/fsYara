rule Winnti_fonfig : hardened
{
	meta:
		description = "Winnti sample - file fonfig.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/VbvJtL"
		date = "2017-01-25"
		hash1 = "2c9882854a60c624ecf6b62b6c7cc7ed04cf4a29814aa5ed1f1a336854697641"
		id = "ca3c186c-0286-5b9b-9585-7680336c8c3d"

	strings:
		$s1 = {6d 00 63 00 69 00 71 00 74 00 7a 00 2e 00 65 00 78 00 65 00}
		$s2 = {6b 6e 61 74 39 79 37 6d}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 2000KB and all of them )
}

