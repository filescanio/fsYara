rule XHide : MALW hardened
{
	meta:
		description = "XHide - Process Faker"
		author = "Joan Soriano / @w0lfvan"
		date = "2017-12-01"
		version = "1.0"
		MD5 = "c644c04bce21dacdeb1e6c14c081e359"
		SHA256 = "59f5b21ef8a570c02453b5edb0e750a42a1382f6"

	strings:
		$a = {58 48 69 64 65 20 2d 20 50 72 6f 63 65 73 73 20 46 61 6b 65 72}
		$b = {46 61 6b 65 6e 61 6d 65 3a 20 25 73 20 50 69 64 4e 75 6d 3a 20 25 64}

	condition:
		all of them
}

