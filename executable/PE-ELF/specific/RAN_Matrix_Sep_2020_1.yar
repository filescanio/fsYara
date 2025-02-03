rule RAN_Matrix_Sep_2020_1 : hardened
{
	meta:
		description = "Detect MATRIX ransomware"
		author = "Arkbird_SOLG"
		reference = "Internal Research"
		date = "2020-10-15"
		hash1 = "7b5e536827c3bb9f8077aed78726585739bcde796904edd6c4faadc9a8d22eaf"
		hash2 = "afca3b84177133ff859d9b9d620b582d913218723bfcf83d119ec125b88a8c40"
		hash3 = "d87d1fbeffe5b18e22f288780bf50b1e7d5af9bbe2480c80ea2a7497a3d52829"
		hash4 = "5474b58de90ad79d6df4c633fb773053fecc16ad69fb5b86e7a2b640a2a056d6"

	strings:
		$debug1 = {5b 00 4c 00 44 00 52 00 49 00 56 00 45 00 53 00 5d 00 3a 00 20 00 6e 00 6f 00 74 00 20 00 66 00 6f 00 75 00 6e 00 64 00 21 00}
		$debug2 = {5b 00 44 00 4f 00 4e 00 45 00 5d 00 3a 00 20 00 4e 00 4f 00 5f 00 53 00 48 00 41 00 52 00 45 00 53 00 21 00}
		$debug3 = {5b 00 41 00 4c 00 4c 00 5f 00 4c 00 4f 00 43 00 41 00 4c 00 5f 00 4b 00 49 00 44 00 5d 00 3a 00 20 00}
		$debug4 = {5b 00 46 00 49 00 4e 00 49 00 53 00 48 00 45 00 44 00 5d 00 3a 00 20 00 47 00 3d 00}
		$debug5 = {5b 00 46 00 45 00 58 00 5f 00 53 00 54 00 41 00 52 00 54 00 5d 00}
		$debug6 = {5b 00 4c 00 4f 00 47 00 53 00 41 00 56 00 45 00 44 00 5d 00}
		$debug7 = {5b 00 47 00 45 00 4e 00 4b 00 45 00 59 00 5d 00}
		$debug8 = {5b 00 53 00 48 00 41 00 52 00 45 00 53 00 5d 00}
		$debug9 = {5b 00 53 00 48 00 41 00 52 00 45 00 53 00 53 00 43 00 41 00 4e 00 5d 00 3a 00 20 00}
		$reg1 = { 2e 00 70 00 68 00 70 00 3f 00 61 00 70 00 69 00 6b 00 65 00 79 00 3d }
		$reg2 = { 26 00 63 00 6f 00 6d 00 70 00 75 00 73 00 65 00 72 00 3d }
		$reg3 = { 26 00 73 00 69 00 64 00 3d 00 }
		$reg4 = { 26 00 70 00 68 00 61 00 73 00 65 00 3d }
		$reg5 = { 47 00 45 00 54 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 500KB and 4 of ( $debug* ) and 3 of ( $reg* )
}

