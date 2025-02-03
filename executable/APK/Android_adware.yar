rule adware : ads android hardened
{
	meta:
		author = "Fernando Denis Ramirez https://twitter.com/fdrg21"
		reference = "https://koodous.com/"
		description = "Adware"
		score = 60
		sample = "5a331231f997decca388ba2d73b7dec1554e966a0795b0cb8447a336bdafd71b"

	strings:
		$string_a = {62 61 6e 6e 65 72 5f 6c 61 79 6f 75 74}
		$string_b = {61 63 74 69 76 69 74 79 5f 61 64 70 61 74 68 5f 73 6d 73}
		$string_c = {61 64 70 61 74 68 5f 74 69 74 6c 65 5f 6f 6e 65}
		$string_d = {37 32 39 31 2d 32 65 63 39 33 36 32 62 64 36 39 39 64 30 63 64 36 66 35 33 61 35 63 61 36 63 64}

	condition:
		all of ( $string_* )
}

