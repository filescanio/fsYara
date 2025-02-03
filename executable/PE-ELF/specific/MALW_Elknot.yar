rule elknot_xor : malware hardened
{
	meta:
		author = "liuya@360.cn"
		date = "2016-04-25"
		description = "elknot/Billgates variants with XOR like C2 encryption scheme"
		reference = "http://liuya0904.blogspot.tw/2016/04/new-elknotbillgates-variant-with-xor.html"
		sample = "474429d9da170e733213940acc9a2b1c, 2579aa65a28c32778790ec1c673abc49"
		score = 40

	strings:
		$decrypt_c2_func_1 = {08 83 [5] 02 75 07 81 04 24 00 01 00 00 50 e8 [4] e9}
		$decrypt_c2_func_2 = {e8 00 00 00 00 87 [2] 83 eb 05 8d 83 [4] 83 bb [4] 02 75 05}

	condition:
		1 of ( $decrypt_c2_func_* )
}

