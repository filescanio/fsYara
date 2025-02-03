rule with_sqlite : sqlite hardened
{
	meta:
		author = "Julian J. Gonzalez <info@seguridadparatodos.es>"
		reference = "http://www.st2labs.com"
		description = "Rule to detect the presence of SQLite data in raw image"

	strings:
		$hex_string = {53 51 4c 69 74 65 20 66 6f 72 6d 61 74 20 33 00}

	condition:
		all of them
}

