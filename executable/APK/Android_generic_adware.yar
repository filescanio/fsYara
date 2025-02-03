rule dowgin : adware android hardened
{
	meta:
		author = "https://twitter.com/plutec_net"
		reference = "https://koodous.com/"
		score = 75
		sample = "4d7f2d6ff4ed8ced6f8f7f96e9899273cc3090ea108f2cc3b32dd1a06e63cf70"
		sample2 = "cde8160d09c486bdd6d96b2ed81bd52390d77094d13ff9cfbc6949ed00206a83"
		sample3 = "d2e81e6db5f4964246d10241588e0e97cde524815c4de7c0ea1c34a48da1bcaf"
		sample4 = "cc2d0b3d8f00690298b0e5813f6ace8f4d4b04c9704292407c2b83a12c69617b"

	strings:
		$a = {68 74 74 70 3a 2f 2f 31 31 32 2e 37 34 2e 31 31 31 2e 34 32 3a 38 30 30 30}
		$b = {53 48 41 31 2d 44 69 67 65 73 74 3a 20 6f 49 78 34 69 59 57 65 54 74 4b 69 62 34 66 42 48 37 68 63 4f 4e 65 48 75 61 45 3d}
		$c = {4f 4e 4c 49 4e 45 47 41 4d 45 50 52 4f 43 45 44 55 52 45 5f 57 48 49 43 48 5f 57 41 50 5f 49 44}
		$d = {68 74 74 70 3a 2f 2f 64 61 2e 6d 6d 61 72 6b 65 74 2e 63 6f 6d 2f 6d 6d 73 64 6b 2f 6d 6d 73 64 6b 3f 66 75 6e 63 3d 6d 6d 73 64 6b 3a 70 6f 73 74 65 76 65 6e 74 6c 6f 67}

	condition:
		all of them
}

