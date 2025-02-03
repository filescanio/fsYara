rule Molerats_Jul17_Sample_1 : hardened
{
	meta:
		description = "Detects Molerats sample - July 2017"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://mymalwareparty.blogspot.de/2017/07/operation-desert-eagle.html"
		date = "2017-07-07"
		hash1 = "ebf2423b9de131eab1c61ac395cbcfc2ac3b15bd9c83b96ae0a48619a4a38d0a"
		id = "b5277255-3ced-5dc5-9490-c5829a0c248b"

	strings:
		$s1 = {65 00 7a 00 45 00 78 00 4f 00 44 00 41 00 30 00 59 00 32 00 55 00 30 00 4c 00 54 00 6b 00 7a 00 4d 00 47 00 45 00 74 00 4e 00 47 00 49 00 77 00 4f 00 53 00 31 00 69 00 5a 00 6a 00 63 00 77 00 4c 00 54 00 6c 00 6d 00 4d 00 57 00 45 00 35 00 4e 00 57 00 51 00 77 00 5a 00 44 00 63 00 77 00 5a 00 48 00 30 00 73 00 49 00 45 00 4e 00 31 00 62 00 48 00 52 00 31 00 63 00 6d 00 55 00 39 00 62 00 6d 00 56 00 31 00 64 00 48 00 4a 00 68 00 62 00 43 00 77 00 67 00 55 00 48 00 56 00 69 00 62 00 47 00 6c 00 6a 00 53 00 32 00 56 00 35 00 56 00 47 00 39 00 72 00 5a 00 57 00 34 00 39 00 4d 00 32 00 55 00 31 00 4e 00 6a 00 4d 00 31 00 4d 00 44 00 59 00 35 00 4d 00 32 00 59 00 33 00 4d 00 7a 00 55 00 31 00 5a 00 51 00 3d 00 3d 00 2c 00 5b 00 7a 00 5d 00 7b 00 63 00 30 00 30 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 200KB and all of them )
}

rule Molerats_Jul17_Sample_2 : hardened
{
	meta:
		description = "Detects Molerats sample - July 2017"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://mymalwareparty.blogspot.de/2017/07/operation-desert-eagle.html"
		date = "2017-07-07"
		hash1 = "7e122a882d625f4ccac019efb7bf1b1024b9e0919d205105e7e299fb1a20a326"
		id = "7ef02003-83d1-5ec7-952d-1e693375dd4b"

	strings:
		$s1 = {46 6f 6c 64 65 72 2e 65 78 65}
		$s2 = {4e 00 6f 00 74 00 65 00 70 00 61 00 64 00 2b 00 2b 00 2e 00 65 00 78 00 65 00}
		$s3 = {52 53 4a 4c 52 53 4a 4f 4d 53 4a}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 1000KB and all of them )
}

rule Molerats_Jul17_Sample_3 : hardened
{
	meta:
		description = "Detects Molerats sample - July 2017"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://mymalwareparty.blogspot.de/2017/07/operation-desert-eagle.html"
		date = "2017-07-07"
		hash1 = "995eee4122802c2dc83bb619f8c53173a5a9c656ad8f43178223d78802445131"
		hash2 = "fec657a19356753008b0f477083993aa5c36ebaf7276742cf84bfe614678746b"
		id = "e1a3323e-fe84-59e5-86d9-dca0c261e3c3"

	strings:
		$s1 = {63 00 63 00 6c 00 65 00 61 00 6e 00 65 00 72 00 2e 00 65 00 78 00 65 00}
		$s2 = {46 6f 6c 64 65 72 2e 65 78 65}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 600KB and all of them )
}

rule Molerats_Jul17_Sample_4 : hardened
{
	meta:
		description = "Detects Molerats sample - July 2017"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://mymalwareparty.blogspot.de/2017/07/operation-desert-eagle.html"
		date = "2017-07-07"
		hash1 = "512a14130a7a8b5c2548aa488055051ab7e725106ddf2c705f6eb4cfa5dc795c"
		id = "cad0c6a2-d286-52fa-b9b8-793ab9ae048f"

	strings:
		$x1 = {67 00 65 00 74 00 2d 00 69 00 74 00 65 00 6d 00 70 00 72 00 6f 00 70 00 65 00 72 00 74 00 79 00 20 00 2d 00 70 00 61 00 74 00 68 00 20 00 27 00 48 00 4b 00 43 00 55 00 3a 00 5c 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 27 00 20 00 2d 00 6e 00 61 00 6d 00 65 00 20 00 27 00 4b 00 65 00 79 00 4e 00 61 00 6d 00 65 00 27 00 29 00}
		$x2 = {4f 00 2e 00 52 00 75 00 6e 00 20 00 43 00 20 00 26 00 20 00 63 00 68 00 72 00 77 00 28 00 33 00 34 00 29 00 20 00 26 00 20 00 22 00 5b 00 53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 49 00 4f 00 2e 00 46 00 69 00 6c 00 65 00 5d 00 3a 00 3a 00}
		$x3 = {48 00 4b 00 43 00 55 00 5c 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 5c 00 4b 00 65 00 79 00 4e 00 61 00 6d 00 65 00 22 00}

	condition:
		( filesize < 700KB and 1 of them )
}

rule Molerats_Jul17_Sample_5 : hardened limited
{
	meta:
		description = "Detects Molerats sample - July 2017"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://mymalwareparty.blogspot.de/2017/07/operation-desert-eagle.html"
		date = "2017-07-07"
		hash1 = "ebf2423b9de131eab1c61ac395cbcfc2ac3b15bd9c83b96ae0a48619a4a38d0a"
		id = "c9dd4f4a-a980-5339-b238-9f53360b89ae"

	strings:
		$x1 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 6e 6f 70 20 2d 63 20 22 69 65 78}
		$x2 = {2e 72 75 6e 28 27 25 77 69 6e 64 69 72 25 5c 5c 53 79 73 57 4f 57 36 34 5c 5c 57 69 6e 64 6f 77 73 50 6f 77 65 72 53 68 65 6c 6c 5c 5c}
		$a1 = {4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67}
		$a2 = {67 69 73 74 2e 67 69 74 68 75 62 75 73 65 72 63 6f 6e 74 65 6e 74 2e 63 6f 6d}

	condition:
		filesize < 200KB and ( 1 of ( $x* ) or 2 of them )
}

rule Molerats_Jul17_Sample_Dropper : hardened
{
	meta:
		description = "Detects Molerats sample dropper SFX - July 2017"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://mymalwareparty.blogspot.de/2017/07/operation-desert-eagle.html"
		date = "2017-07-07"
		hash1 = "ad0b3ac8c573d84c0862bf1c912dba951ec280d31fe5b84745ccd12164b0bcdb"
		id = "b4622373-b496-51de-abaa-caa665b558b3"

	strings:
		$s1 = {50 00 6c 00 65 00 61 00 73 00 65 00 20 00 72 00 65 00 6d 00 6f 00 76 00 65 00 20 00 25 00 73 00 20 00 66 00 72 00 6f 00 6d 00 20 00 25 00 73 00 20 00 66 00 6f 00 6c 00 64 00 65 00 72 00 2e 00 20 00 49 00 74 00 20 00 69 00 73 00 20 00 75 00 6e 00 73 00 65 00 63 00 75 00 72 00 65 00 20 00 74 00 6f 00 20 00 72 00 75 00 6e 00 20 00 25 00 73 00 20 00 75 00 6e 00 74 00 69 00 6c 00 20 00 69 00 74 00 20 00 69 00 73 00 20 00 64 00 6f 00 6e 00 65 00 2e 00}
		$s2 = {73 66 78 72 61 72 2e 65 78 65}
		$s3 = {61 74 74 61 63 68 6d 65 6e 74 2e 68 74 61}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 1000KB and all of them )
}

