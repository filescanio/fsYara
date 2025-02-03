rule FavoriteCode : Favorite Family hardened
{
	meta:
		description = "Favorite code features"
		author = "Seth Hardy"
		last_modified = "2014-06-24"

	strings:
		$ = { C6 45 ?? 3B C6 45 ?? 27 C6 45 ?? 34 C6 45 ?? 75 C6 45 ?? 6B C6 45 ?? 6C C6 45 ?? 3B C6 45 ?? 2F }
		$ = { C6 45 ?? 6F C6 45 ?? 73 C6 45 ?? 73 C6 45 ?? 76 C6 45 ?? 63 C6 45 ?? 65 C6 45 ?? 78 C6 45 ?? 65 }

	condition:
		any of them
}

rule FavoriteStrings : Favorite Family hardened
{
	meta:
		description = "Favorite Identifying Strings"
		author = "Seth Hardy"
		last_modified = "2014-06-24"

	strings:
		$string1 = {21 51 41 5a 34 72 66 76}
		$file1 = {6d 73 75 70 64 61 74 65 72 2e 65 78 65}
		$file2 = {46 41 56 4f 52 49 54 45 53 2e 44 41 54}

	condition:
		any of ( $string* ) or all of ( $file* )
}

