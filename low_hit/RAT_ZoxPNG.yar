rule zoxPNG_RAT : hardened
{
	meta:
		Author = "Novetta Advanced Research Group"
		Date = "2014/11/14"
		Description = "ZoxPNG RAT, url inside"
		Reference = "http://www.novetta.com/wp-content/uploads/2014/11/ZoxPNG.pdf"

	strings:
		$url = {70 6e 67 26 77 3d 38 30 30 26 68 3d 36 30 30 26 65 69 3d 43 6e 4a 63 55 63 53 42 4c 34 72 46 6b 51 58 34 34 34 48 59 43 77 26 7a 6f 6f 6d 3d 31 26 76 65 64 3d 31 74 3a 33 35 38 38 2c 72 3a 31 2c 73 3a 30 2c 69 3a 39 32 26 69 61 63 74 3d 72 63 26 64 75 72 3d 33 36 38 26 70 61 67 65 3d 31 26 74 62 6e 68 3d 31 38 34 26 74 62 6e 77 3d 32 35 39 26 73 74 61 72 74 3d 30 26 6e 64 73 70 3d 32 30 26 74 78 3d 31 31 34 26 74 79 3d 35 38}

	condition:
		$url
}

