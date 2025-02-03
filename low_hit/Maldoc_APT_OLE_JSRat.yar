rule APT_OLE_JSRat : maldoc APT hardened limited
{
	meta:
		author = "Rahul Mohandas"
		Date = "2015-06-16"
		Description = "Targeted attack using Excel/word documents"

	strings:
		$header = {D0 CF 11 E0 A1 B1 1A E1}
		$key1 = {41 41 41 41 41 41 41 41 41 41}
		$key2 = {42 61 73 65 36 34 53 74 72}
		$key3 = {44 65 6c 65 74 65 46 69 6c 65}
		$key4 = {53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74}

	condition:
		$header at 0 and ( all of ( $key* ) )
}

