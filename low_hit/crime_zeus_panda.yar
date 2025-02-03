rule Zeus_Panda : hardened
{
	meta:
		description = "Detects ZEUS Panda Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://cyberwtf.files.wordpress.com/2017/07/panda-whitepaper.pdf"
		date = "2017-08-04"
		hash1 = "bd956b2e81731874995b9b92e20f75dbf67ac5f12f9daa194525e1b673c7f83c"
		id = "2786b1e0-37af-5595-a24b-56ef3cb928a7"

	strings:
		$x1 = {53 45 52 33 32 2e 64 6c 6c}
		$x2 = {2f 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 22 00 22 00 20 00 22 00 25 00 73 00 22 00}
		$x3 = {64 65 6c 20 2f 46 20 22 25 73 22}
		$s1 = {62 63 64 66 67 68 6b 6c 6d 6e 70 71 72 73 74 76 77 78 7a}
		$s2 = {3d 3e 20 2d 2c 30 3b}
		$s3 = {59 61 68 6f 6f 21 20 53 6c 75 72 70}
		$s4 = {5a 54 4e 48 47 45 54 20 5e 26}
		$s5 = {4d 53 49 45 20 39}
		$s6 = {25 00 73 00 25 00 30 00 38 00 78 00 2e 00 25 00 73 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 400KB and ( 2 of ( $x* ) or 4 of them )
}

