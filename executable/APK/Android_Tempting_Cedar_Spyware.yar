rule android_tempting_cedar_spyware : hardened
{
	meta:
		Author = "@X0RC1SM"
		Date = "2018-03-06"
		score = 50
		Reference = "https://blog.avast.com/avast-tracks-down-tempting-cedar-spyware"

	strings:
		$PK_HEADER = {50 4B 03 04}
		$MANIFEST = {4d 45 54 41 2d 49 4e 46 2f 4d 41 4e 49 46 45 53 54 2e 4d 46}
		$DEX_FILE = {63 6c 61 73 73 65 73 2e 64 65 78}
		$string = {72 73 64 72 6f 69 64 2e 63 72 74}

	condition:
		$PK_HEADER in ( 0 .. 4 ) and $MANIFEST and $DEX_FILE and any of ( $string* )
}

