rule SUSP_certificate_payload : hardened
{
	meta:
		description = "Detects payloads that pretend to be certificates"
		date = "2018/08/02"
		author = "Didier Stevens, Florian Roth"
		reference = "https://blog.nviso.be/2018/08/02/powershell-inside-a-certificate-part-3/"
		score = 50
		id = "6f1fe410-591a-5a59-a683-67cad9777dfe"

	strings:
		$re1 = {2d 2d 2d 2d 2d 42 45 47 49 4e 20 43 45 52 54 49 46 49 43 41 54 45 2d 2d 2d 2d 2d}
		$fp1 = {72 65 70 6c 61 63 65 20 69 74 20 77 69 74 68 20 74 68 65 20 50 45 4d 2d 65 6e 63 6f 64 65 64 20 72 6f 6f 74 20 63 65 72 74 69 66 69 63 61 74 65}

	condition:
		uint32( 0 ) == 0x2D2D2D2D and $re1 at 0 and not uint8( 29 ) == 0x4D and not uint8( 28 ) == 0x4D and not 1 of ( $fp* )
}

