rule SUSP_Macro_StarOffice : hardened limited
{
	meta:
		description = "Suspicious macro in StarOffice"
		author = "John Lambert @JohnLaTwC"
		date = "2019-02-06"
		modified = "2021-05-27"
		score = 60
		reference = "https://twitter.com/JohnLaTwC/status/1093259873993732096"
		hash1 = "8495d37825dab8744f7d2c8049fc6b70b1777b9184f0abe69ce314795480ce39"
		hash2 = "25b4214da1189fd30d3de7c538aa8b606f22c79e50444e5733fb1c6d23d71fbe"
		hash3 = "322f314102f67a16587ab48a0f75dfaf27e4b044ffdc3b88578351c05b4f39db"
		hash4 = "705429725437f7e0087a6159708df97992abaadff0fa48fdf25111d34a3e2f20"
		hash5 = "7141d94e827d3b24810813d6b2e3fb851da0ee2958ef347154bc28153b23874a"
		hash6 = "7c0e85c0a4d96080ca341d3496743f0f113b17613660812d40413be6d453eab4"
		hash7 = "8d59f1e2abcab9efb7f833d478d1d1390e7456092f858b656ee0024daf3d1aa3"
		hash8 = "9846b942d9d1e276c95361180e9326593ea46d3abcce9c116c204954bbfe3fdc"
		hash9 = "aa0c83f339c8c16ad21dec41e4605d4e327adbbb78827dcad250ed64d2ceef1c"
		hash10 = "b0be54c7210b06e60112a119c235e23c9edbe40b1c1ce1877534234f82b6b302"
		hash11 = "bf581ebb96b8ca4f254ab4d200f9a053aff8187715573d9a1cbd443df0f554e3"
		hash12 = "de45634064af31cb6768e4912cac284a76a6e66d398993df1aeee8ce26e0733b"
		id = "92110a87-66b4-5fc5-b3f5-3e59ec2671b2"

	strings:
		$r1 = {53 74 61 72 42 61 73 69 63}
		$r2 = {3c 2f 73 63 72 69 70 74 3a 6d 6f 64 75 6c 65 3e}
		$s1 = {53 68 65 6c 6c}
		$s2 = {2e 52 75 6e}
		$s3 = {2e 50 75 74 49 6e 43 6c 69 70 62 6f 61 72 64}
		$s4 = {70 6f 77 65 72 73 68 65 6c 6c}
		$fp1 = {4c 69 62 72 65 4f 66 66 69 63 65 20 70 72 6f 6a 65 63 74}

	condition:
		filesize < 1MB and uint32be( 0 ) == 0x3c3f786d and all of ( $r* ) and 1 of ( $s* ) and not 1 of ( $fp* )
}

