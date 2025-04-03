rule SUSP_TINY_PE : hardened
{
	meta:
		description = "Detects Tiny PE file"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://webserver2.tecgraf.puc-rio.br/~ismael/Cursos/YC++/apostilas/win32_xcoff_pe/tyne-example/Tiny%20PE.htm"
		date = "2019-10-23"
		score = 80
		id = "5081c24e-91d1-5705-9459-f675be4f0e3c"

	strings:
		$header = { 4D 5A 00 00 50 45 00 00 }

	condition:
		uint16( 0 ) == 0x5a4d and uint16( 4 ) == 0x4550 and filesize <= 20KB and $header at 0
}

rule SUSP_GIF_Anomalies : hardened
{
	meta:
		description = "Detects files with GIF headers and format anomalies - which means that this image could be an obfuscated file of a different type"
		author = "Florian Roth (Nextron Systems)"
		score = 50
		reference = "https://en.wikipedia.org/wiki/GIF"
		date = "2020-07-02"
		id = "2e77c2ff-a8f6-5444-a93d-843312640a28"

	condition:
		uint16( 0 ) == 0x4947 and uint8( 2 ) == 0x46 and uint8( 11 ) != 0x00 and uint8( 12 ) != 0x00 and uint8( filesize - 1 ) != 0x3b
}

import "pe"

rule SUSP_HxD_Icon_Anomaly_May23_1 : hardened loosened limited
{
	meta:
		description = "Detects suspicious use of the the free hex editor HxD's icon in PE files that don't seem to be a legitimate version of HxD"
		author = "Florian Roth"
		reference = "https://www.linkedin.com/feed/update/urn:li:activity:7068631930040188929/?utm_source=share&utm_medium=member_ios"
		date = "2023-05-29"
		score = 65
		id = "3ac8cc92-6d76-5787-ada0-cfb6eabb4b20"

	strings:
		$ac1 = { 99 00 77 0D DD 09 99 80 99 00 77 0D DD 09 99 80
               99 00 77 0D DD 09 99 80 99 00 77 0D DD 09 99 80
               99 00 77 0D DD 09 99 80 99 00 77 0D DD 09 99 80
               99 00 77 0D DD 09 99 80 99 00 77 0D DD 09 99 80
               99 00 77 0D DD 09 99 80 99 00 77 0D D0 99 98 09
               99 99 00 0D D0 99 98 09 99 99 00 0D D0 99 98 09
               99 99 00 0D D0 99 98 0F F9 99 00 0D D0 99 98 09
               9F 99 00 0D D0 99 98 09 FF 99 00 0D D0 99 98 09
               FF 99 00 0D D0 99 98 09 99 99 00 0D D0 99 98 0F
               F9 99 00 0D D0 99 98 09 99 99 00 0D 09 99 80 9F
               F9 99 99 00 09 99 80 99 F9 99 99 00 09 99 80 FF }
		$ac2 = { FF FF FF FF FF FF FF FF FF FF FF FF FF FF B9 DE
               FA 68 B8 F4 39 A2 F1 39 A2 F1 39 A2 F1 39 A2 F1
               39 A2 F1 39 A2 F1 68 B8 F4 B9 DE FA FF FF FF FF
               FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF }
		$s1 = { 00 4D 00 61 00 EB 00 6C 00 20 00 48 00 F6 00 72 00 7A }
		$s2 = {((6d 68 2d 6e 65 78 75 73 2e 64 65) | (6d 00 68 00 2d 00 6e 00 65 00 78 00 75 00 73 00 2e 00 64 00 65 00))}
		$upx1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 55 50 58 30 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$xs1 = {((74 65 72 6d 69 6e 61 74 6f 72) | (74 00 65 00 72 00 6d 00 69 00 6e 00 61 00 74 00 6f 00 72 00))}
		$xs2 = {((54 65 72 6d 69 6e 61 74 6f 72) | (54 00 65 00 72 00 6d 00 69 00 6e 00 61 00 74 00 6f 00 72 00))}

	condition:
		uint16( 0 ) == 0x5a4d and 1 of ( $ac* ) and ( not 1 of ( $s* ) or filesize > 6930000 or ( pe.is_32bit ( ) and filesize < 1540000 and not $upx1 ) or ( pe.is_32bit ( ) and filesize < 590000 and $upx1 ) or ( pe.is_64bit ( ) and filesize < 6670000 and not $upx1 ) or ( pe.is_64bit ( ) and filesize < 1300000 and $upx1 ) or 1 of ( $xs* ) )
}

