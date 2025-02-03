rule NetpassStrings : NetPass Variant hardened
{
	meta:
		description = "Identifiers for netpass variant"
		author = "Katie Kleemola"
		last_updated = "2014-05-29"

	strings:
		$exif1 = {44 00 65 00 76 00 69 00 63 00 65 00 20 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 20 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 4e 00}
		$exif2 = {62 00 65 00 65 00 70 00 2e 00 73 00 79 00 73 00}
		$exif3 = {42 00 45 00 45 00 50 00 20 00 44 00 72 00 69 00 76 00 65 00 72 00}
		$string1 = {00 4e 65 74 50 61 73 73 20 55 70 64 61 74 65 00}
		$string2 = {00 25 73 3a 44 4f 57 4e 4c 4f 41 44 00}
		$string3 = {00 25 73 3a 55 50 44 41 54 45 00}
		$string4 = {00 25 73 3a 75 4e 49 4e 53 54 41 4c 4c 00}

	condition:
		all of ( $exif* ) or any of ( $string* )
}

rule NetTravStrings : NetTraveler Family hardened
{
	meta:
		description = "Identifiers for NetTraveler DLL"
		author = "Katie Kleemola"
		last_updated = "2014-05-20"

	strings:
		$ = {3f 61 63 74 69 6f 6e 3d 75 70 64 61 74 65 64 26 68 6f 73 74 69 64 3d}
		$ = {74 72 61 76 6c 65 72 62 61 63 6b 69 6e 66 6f}
		$ = {3f 61 63 74 69 6f 6e 3d 67 65 74 63 6d 64 26 68 6f 73 74 69 64 3d}
		$ = {25 73 3f 61 63 74 69 6f 6e 3d 67 6f 74 63 6d 64 26 68 6f 73 74 69 64 3d}
		$ = {25 73 3f 68 6f 73 74 69 64 3d 25 73 26 68 6f 73 74 6e 61 6d 65 3d 25 73 26 68 6f 73 74 69 70 3d 25 73 26 66 69 6c 65 6e 61 6d 65 3d 25 73 26 66 69 6c 65 73 74 61 72 74 3d 25 75 26 66 69 6c 65 74 65 78 74 3d}
		$ = {00 4d 65 74 68 6f 64 31 20 46 61 69 6c 21 21 21 21 21 00}
		$ = {00 4d 65 74 68 6f 64 33 20 46 61 69 6c 21 21 21 21 21 00}
		$ = {00 6d 65 74 68 6f 64 20 63 75 72 72 65 63 74 3a 00}
		$ = /\x00\x00[\w\-]+ is Running!\x00\x00/
		$ = {00 4f 74 68 65 72 54 77 6f 00}

	condition:
		3 of them
}

rule NetTravExports : NetTraveler Family hardened
{
	meta:
		description = "Export names for dll component"
		author = "Katie Kleemola"
		last_updated = "2014-05-20"

	strings:
		$ = {3f 49 6e 6a 65 63 74 44 6c 6c 40 40 59 41 48 50 41 55 48 57 4e 44 5f 5f 40 40 4b 40 5a}
		$ = {3f 55 6e 6d 61 70 44 6c 6c 40 40 59 41 48 58 5a}
		$ = {3f 67 5f 62 53 75 62 63 6c 61 73 73 65 64 40 40 33 48 41}

	condition:
		any of them
}

