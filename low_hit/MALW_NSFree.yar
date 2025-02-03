rule NSFreeCode : NSFree Family hardened
{
	meta:
		description = "NSFree code features"
		author = "Seth Hardy"
		last_modified = "2014-06-24"

	strings:
		$ = { 53 56 57 66 81 38 4D 5A }
		$ = { 90 90 90 90 81 3F 50 45 00 00 }

	condition:
		all of them
}

rule NSFreeStrings : NSFree Family hardened limited
{
	meta:
		description = "NSFree Identifying Strings"
		author = "Seth Hardy"
		last_modified = "2014-06-24"

	strings:
		$ = {5c 4d 69 63 4e 53 5c}
		$ = {((4e 53 46 72 65 65 44 6c 6c) | (4e 00 53 00 46 00 72 00 65 00 65 00 44 00 6c 00 6c 00))}
		$ = { 0c 30 31 2b 78 28 2a 37 3f 2a 39 35 78 3b 39 36 36 37 }

	condition:
		any of them
}

rule NSFree : Family hardened
{
	meta:
		description = "NSFree"
		author = "Seth Hardy"
		last_modified = "2014-06-24"

	condition:
		NSFreeCode or NSFreeStrings
}

