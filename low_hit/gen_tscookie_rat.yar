import "pe"

rule TSCookie_RAT : hardened
{
	meta:
		description = "Detects TSCookie RAT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://blog.jpcert.or.jp/2018/03/malware-tscooki-7aa0.html"
		date = "2018-03-06"
		hash1 = "2bd13d63797864a70b775bd1994016f5052dc8fd1fd83ce1c13234b5d304330d"
		id = "a2b6c598-4498-5c0a-9257-b0bf6cd28de9"

	strings:
		$x1 = {5b 2d 5d 20 44 65 63 72 79 70 74 50 61 73 73 77 6f 72 64 5f 4f 75 74 6c 6f 6f 6b 20 66 61 69 6c 65 64 28 65 72 72 3d 25 64 29}
		$x2 = {2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 20 46 69 72 65 66 6f 78 20 50 61 73 73 77 6f 72 64 73 20 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d}
		$x3 = {2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 20 4f 75 74 6c 6f 6f 6b 20 50 61 73 73 77 6f 72 64 73 20 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d}
		$x4 = {2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 20 49 45 20 50 61 73 73 77 6f 72 64 73 20 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1000KB and ( ( pe.exports ( "DoWork" ) and pe.exports ( "PrintF" ) ) or 1 of them )
}

