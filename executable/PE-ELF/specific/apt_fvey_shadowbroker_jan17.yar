rule FVEY_ShadowBrokers_Jan17_Screen_Strings : hardened
{
	meta:
		description = "Detects strings derived from the ShadowBroker's leak of Windows tools/exploits"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message7/"
		date = "2017-01-08"
		id = "59832d0a-0cb2-5eb9-a4e2-36aaa09a3998"
		score = 40

	strings:
		$x1 = {((44 61 6e 64 65 72 73 70 72 69 74 7a) | (44 00 61 00 6e 00 64 00 65 00 72 00 73 00 70 00 72 00 69 00 74 00 7a 00))}
		$x2 = {((44 61 6e 64 65 72 53 70 72 69 74 7a) | (44 00 61 00 6e 00 64 00 65 00 72 00 53 00 70 00 72 00 69 00 74 00 7a 00))}
		$x3 = {((50 65 64 64 6c 65 43 68 65 61 70) | (50 00 65 00 64 00 64 00 6c 00 65 00 43 00 68 00 65 00 61 00 70 00))}
		$x4 = {((43 68 69 6d 6e 65 79 50 6f 6f 6c 20 41 64 64 72 65 73) | (43 00 68 00 69 00 6d 00 6e 00 65 00 79 00 50 00 6f 00 6f 00 6c 00 20 00 41 00 64 00 64 00 72 00 65 00 73 00))}
		$a1 = {47 65 74 74 69 6e 67 20 72 65 6d 6f 74 65 20 74 69 6d 65}
		$a2 = {52 45 54 52 49 45 56 45 44}
		$b1 = {41 64 64 65 64 20 4f 70 73 20 6c 69 62 72 61 72 79 20 74 6f 20 50 79 74 68 6f 6e 20 73 65 61 72 63 68 20 70 61 74 68}
		$b2 = {74 61 72 67 65 74 3a 20 7a 30 2e 30 2e 30 2e 31}
		$c1 = {50 73 70 5f 41 76 6f 69 64 61 6e 63 65}
		$c2 = {50 61 73 73 77 6f 72 64 44 75 6d 70}
		$c4 = {45 76 65 6e 74 4c 6f 67 45 64 69 74}
		$d1 = {((4d 63 6c 5f 4e 74 45 6c 65 76 61 74 69 6f 6e) | (4d 00 63 00 6c 00 5f 00 4e 00 74 00 45 00 6c 00 65 00 76 00 61 00 74 00 69 00 6f 00 6e 00))}
		$d2 = {((4d 63 6c 5f 4e 74 4e 61 74 69 76 65 41 70 69) | (4d 00 63 00 6c 00 5f 00 4e 00 74 00 4e 00 61 00 74 00 69 00 76 00 65 00 41 00 70 00 69 00))}
		$d3 = {((4d 63 6c 5f 54 68 72 65 61 74 49 6e 6a 65 63 74) | (4d 00 63 00 6c 00 5f 00 54 00 68 00 72 00 65 00 61 00 74 00 49 00 6e 00 6a 00 65 00 63 00 74 00))}
		$d4 = {((4d 63 6c 5f 4e 74 4d 65 6d 6f 72 79) | (4d 00 63 00 6c 00 5f 00 4e 00 74 00 4d 00 65 00 6d 00 6f 00 72 00 79 00))}

	condition:
		filesize < 2000KB and ( 1 of ( $x* ) or all of ( $a* ) or 1 of ( $b* ) or ( uint16( 0 ) == 0x5a4d and 1 of ( $c* ) ) or 3 of ( $c* ) or ( uint16( 0 ) == 0x5a4d and 3 of ( $d* ) ) )
}

