rule lateral_movement : hardened
{
	meta:
		date = "3/12/2014"
		author = "https://github.com/reed1713"
		description = "methodology sig looking for signs of lateral movement"

	strings:
		$type = {4d 69 63 72 6f 73 6f 66 74 2d 57 69 6e 64 6f 77 73 2d 53 65 63 75 72 69 74 79 2d 41 75 64 69 74 69 6e 67}
		$eventid = {34 36 38 38}
		$data = {50 73 45 78 65 63 2e 65 78 65}
		$type1 = {4d 69 63 72 6f 73 6f 66 74 2d 57 69 6e 64 6f 77 73 2d 53 65 63 75 72 69 74 79 2d 41 75 64 69 74 69 6e 67}
		$eventid1 = {34 36 38 38}
		$data1 = {57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 6e 65 74 2e 65 78 65}
		$type2 = {4d 69 63 72 6f 73 6f 66 74 2d 57 69 6e 64 6f 77 73 2d 53 65 63 75 72 69 74 79 2d 41 75 64 69 74 69 6e 67}
		$eventid2 = {34 36 38 38}
		$data2 = {57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 61 74 2e 65 78 65}

	condition:
		($type and $eventid and $data ) or ( $type1 and $eventid1 and $data1 ) or ( $type2 and $eventid2 and $data2 )
}

