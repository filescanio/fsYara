import "pe"

rule SAmSAmRansom2016 : hardened
{
	meta:
		author = "Christiaan Beek"
		date = "2018-01-25"
		hash1 = "45e00fe90c8aa8578fce2b305840e368d62578c77e352974da6b8f8bc895d75b"
		hash2 = "946dd4c4f3c78e7e4819a712c7fd6497722a3d616d33e3306a556a9dc99656f4"
		hash3 = "979692a34201f9fc1e1c44654dc8074a82000946deedfdf6b8985827da992868"
		hash4 = "939efdc272e8636fd63c1b58c2eec94cf10299cd2de30c329bd5378b6bbbd1c8"
		hash5 = "a763ed678a52f77a7b75d55010124a8fccf1628eb4f7a815c6d635034227177e"
		hash6 = "e682ac6b874e0a6cfc5ff88798315b2cb822d165a7e6f72a5eb74e6da451e155"
		hash7 = "6bc2aa391b8ef260e79b99409e44011874630c2631e4487e82b76e5cb0a49307"
		hash8 = "036071786d7db553e2415ec2e71f3967baf51bdc31d0a640aa4afb87d3ce3050"
		hash9 = "ffef0f1c2df157e9c2ee65a12d5b7b0f1301c4da22e7e7f3eac6b03c6487a626"
		hash10 = "89b4abb78970cd524dd887053d5bcd982534558efdf25c83f96e13b56b4ee805"
		hash11 = "7aa585e6fd0a895c295c4bea2ddb071eed1e5775f437602b577a54eef7f61044"
		hash12 = "0f2c5c39494f15b7ee637ad5b6b5d00a3e2f407b4f27d140cd5a821ff08acfac"
		hash13 = "58ef87523184d5df3ed1568397cea65b3f44df06c73eadeb5d90faebe4390e3e"

	strings:
		$x1 = {43 00 6f 00 75 00 6c 00 64 00 20 00 6e 00 6f 00 74 00 20 00 6c 00 69 00 73 00 74 00 20 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 65 00 73 00 20 00 6c 00 6f 00 63 00 6b 00 69 00 6e 00 67 00 20 00 72 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 2e 00 20 00 46 00 61 00 69 00 6c 00 65 00 64 00 20 00 74 00 6f 00 20 00 67 00 65 00 74 00 20 00 73 00 69 00 7a 00 65 00 20 00 6f 00 66 00 20 00 72 00 65 00 73 00 75 00 6c 00 74 00 2e 00}
		$s2 = {43 00 6f 00 75 00 6c 00 64 00 20 00 6e 00 6f 00 74 00 20 00 6c 00 69 00 73 00 74 00 20 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 65 00 73 00 20 00 6c 00 6f 00 63 00 6b 00 69 00 6e 00 67 00 20 00 72 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 2e 00}
		$s3 = {73 61 6d 73 61 6d 2e 64 65 6c 2e 65 78 65}
		$s4 = {73 00 61 00 6d 00 73 00 61 00 6d 00 2e 00 65 00 78 00 65 00}
		$s5 = {52 4d 5f 55 4e 49 51 55 45 5f 50 52 4f 43 45 53 53}
		$s6 = {4b 69 6c 6c 50 72 6f 63 65 73 73 57 69 74 68 57 61 69 74}
		$s7 = {6b 69 6c 6c 4f 70 65 6e 65 64 50 72 6f 63 65 73 73 54 72 65 65}
		$s8 = {52 4d 5f 50 52 4f 43 45 53 53 5f 49 4e 46 4f}
		$s9 = {45 00 78 00 63 00 65 00 70 00 74 00 69 00 6f 00 6e 00 20 00 63 00 61 00 75 00 67 00 68 00 74 00 20 00 69 00 6e 00 20 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 3a 00 20 00 7b 00 30 00 7d 00}
		$s10 = {43 00 6f 00 75 00 6c 00 64 00 20 00 6e 00 6f 00 74 00 20 00 62 00 65 00 67 00 69 00 6e 00 20 00 72 00 65 00 73 00 74 00 61 00 72 00 74 00 20 00 73 00 65 00 73 00 73 00 69 00 6f 00 6e 00 2e 00 20 00 20 00 55 00 6e 00 61 00 62 00 6c 00 65 00 20 00 74 00 6f 00 20 00 64 00 65 00 74 00 65 00 72 00 6d 00 69 00 6e 00 65 00 20 00 66 00 69 00 6c 00 65 00 20 00 6c 00 6f 00 63 00 6b 00 65 00 72 00 2e 00}
		$s11 = {73 61 6d 73 61 6d 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73}
		$s12 = {45 6e 63 72 79 70 74 53 74 72 69 6e 67 54 6f 42 79 74 65 73}
		$s13 = {72 65 63 75 72 73 69 76 65 67 65 74 66 69 6c 65 73}
		$s14 = {52 53 41 45 6e 63 72 79 70 74 42 79 74 65 73}
		$s15 = {65 6e 63 72 79 70 74 46 69 6c 65}
		$s16 = {73 00 61 00 6d 00 73 00 61 00 6d 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00}
		$s17 = {54 53 53 65 73 73 69 6f 6e 49 64}
		$s18 = {43 00 6f 00 75 00 6c 00 64 00 20 00 6e 00 6f 00 74 00 20 00 72 00 65 00 67 00 69 00 73 00 74 00 65 00 72 00 20 00 72 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 2e 00}
		$s19 = {3c 72 65 63 75 72 73 69 76 65 67 65 74 66 69 6c 65 73 3e 62 5f 5f 30}
		$s20 = {63 72 65 61 74 65 5f 66 72 6f 6d 5f 72 65 73 6f 75 72 63 65}
		$op0 = { 96 00 e0 00 29 00 0b 00 34 23 }
		$op1 = { 96 00 12 04 f9 00 34 00 6c 2c }
		$op2 = { 72 a5 0a 00 70 a2 06 20 94 }

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 700KB and pe.imphash ( ) == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ( $x* ) and 4 of them ) and all of ( $op* ) ) or ( all of them )
}

import "pe"

rule SamSam_Ransomware_Latest : hardened
{
	meta:
		description = "Latest SamSA ransomware samples"
		author = "Christiaan Beek"
		reference = "http://blog.talosintelligence.com/2018/01/samsam-evolution-continues-netting-over.html"
		date = "2018-01-23"
		hash1 = "e7bebd1b1419f42293732c70095f35c8310fa3afee55f1df68d4fe6bbee5397e"
		hash2 = "72832db9b951663b8f322778440b8720ea95cde0349a1d26477edd95b3915479"
		hash3 = "3531bb1077c64840b9c95c45d382448abffa4f386ad88e125c96a38166832252"
		hash4 = "88d24b497cfeb47ec6719752f2af00c802c38e7d4b5d526311d552c6d5f4ad34"
		hash5 = "8eabfa74d88e439cfca9ccabd0ee34422892d8e58331a63bea94a7c4140cf7ab"
		hash6 = "88e344977bf6451e15fe202d65471a5f75d22370050fe6ba4dfa2c2d0fae7828"

	strings:
		$s1 = {62 00 65 00 64 00 66 00 30 00 38 00 31 00 37 00 35 00 64 00 33 00 31 00 39 00 61 00 32 00 66 00 38 00 37 00 39 00 66 00 65 00 37 00 32 00 30 00 30 00 33 00 32 00 64 00 31 00 31 00 65 00 35 00}
		$s2 = {6b 73 64 67 68 6b 73 64 67 68 6b 64 64 67 64 66 67 64 66 67 66 64}
		$s3 = {6f 73 69 65 79 72 67 76 62 73 67 6e 68 6b 66 6c 6b 73 74 65 73 61 64 66 61 6b 64 68 61 6b 73 6a 66 67 79 6a 71 71 77 67 6a 72 77 67 65 68 6a 67 66 64 6a 67 64 66 66 67}
		$s4 = {35 00 63 00 32 00 64 00 33 00 37 00 36 00 63 00 39 00 37 00 36 00 36 00 36 00 39 00 65 00 66 00 61 00 66 00 39 00 63 00 62 00 31 00 30 00 37 00 66 00 35 00 61 00 38 00 33 00 64 00 30 00 63 00}
		$s5 = {42 39 31 37 37 35 34 42 43 46 45 37 31 37 45 42 34 46 37 43 45 30 34 41 35 42 31 31 41 36 33 35 31 45 45 43 35 30 31 35}
		$s6 = {66 00 39 00 39 00 65 00 34 00 37 00 63 00 31 00 64 00 34 00 63 00 63 00 62 00 32 00 62 00 31 00 30 00 33 00 66 00 35 00 66 00 37 00 33 00 30 00 66 00 38 00 65 00 62 00 35 00 39 00 38 00 61 00}
		$s7 = {64 00 32 00 64 00 62 00 32 00 38 00 34 00 32 00 31 00 37 00 61 00 36 00 65 00 35 00 35 00 39 00 36 00 39 00 31 00 33 00 65 00 32 00 65 00 31 00 61 00 35 00 62 00 32 00 36 00 37 00 32 00 66 00}
		$s8 = {30 00 62 00 64 00 64 00 62 00 38 00 61 00 63 00 64 00 33 00 38 00 66 00 36 00 64 00 61 00 31 00 31 00 38 00 66 00 34 00 37 00 32 00 34 00 33 00 61 00 66 00 34 00 38 00 64 00 38 00 61 00 66 00}
		$s9 = {66 00 37 00 33 00 36 00 32 00 33 00 64 00 63 00 62 00 34 00 66 00 36 00 32 00 62 00 30 00 65 00 35 00 62 00 39 00 62 00 34 00 64 00 38 00 33 00 65 00 31 00 65 00 65 00 34 00 33 00 32 00 33 00}
		$s10 = {39 00 31 00 36 00 61 00 62 00 34 00 38 00 65 00 33 00 32 00 65 00 39 00 30 00 34 00 62 00 38 00 65 00 31 00 62 00 38 00 37 00 62 00 37 00 65 00 33 00 63 00 65 00 64 00 36 00 64 00 35 00 35 00}
		$s11 = {63 00 36 00 65 00 36 00 31 00 36 00 32 00 32 00 64 00 63 00 35 00 31 00 65 00 31 00 37 00 31 00 39 00 35 00 65 00 34 00 64 00 66 00 36 00 65 00 33 00 35 00 39 00 32 00 31 00 38 00 61 00 32 00}
		$s12 = {32 00 61 00 39 00 65 00 38 00 64 00 35 00 34 00 39 00 61 00 66 00 31 00 33 00 30 00 33 00 31 00 66 00 36 00 62 00 66 00 37 00 38 00 30 00 37 00 32 00 34 00 32 00 63 00 65 00 32 00 37 00 66 00}
		$s13 = {65 00 33 00 32 00 30 00 38 00 39 00 35 00 37 00 61 00 64 00 37 00 36 00 64 00 32 00 66 00 32 00 65 00 32 00 34 00 39 00 32 00 37 00 36 00 34 00 31 00 30 00 37 00 34 00 34 00 62 00 32 00 39 00}
		$s14 = {62 00 34 00 64 00 32 00 38 00 62 00 62 00 64 00 36 00 35 00 64 00 61 00 39 00 37 00 34 00 33 00 31 00 66 00 34 00 39 00 34 00 64 00 64 00 37 00 37 00 34 00 31 00 62 00 65 00 65 00 37 00 30 00}
		$s15 = {38 00 31 00 65 00 65 00 33 00 34 00 36 00 34 00 38 00 39 00 63 00 32 00 37 00 32 00 66 00 34 00 35 00 36 00 66 00 32 00 62 00 31 00 37 00 64 00 39 00 36 00 33 00 36 00 35 00 63 00 33 00 34 00}
		$s16 = {39 00 34 00 36 00 38 00 32 00 64 00 65 00 62 00 63 00 36 00 66 00 31 00 35 00 36 00 62 00 37 00 65 00 39 00 30 00 65 00 30 00 64 00 36 00 64 00 63 00 37 00 37 00 32 00 37 00 33 00 34 00 64 00}
		$s17 = {36 00 39 00 34 00 33 00 65 00 31 00 37 00 61 00 39 00 38 00 39 00 66 00 31 00 31 00 61 00 66 00 37 00 35 00 30 00 65 00 61 00 30 00 34 00 34 00 31 00 61 00 37 00 31 00 33 00 62 00 38 00 39 00}
		$s18 = {62 00 31 00 63 00 37 00 65 00 32 00 34 00 62 00 33 00 31 00 35 00 66 00 66 00 39 00 63 00 37 00 33 00 61 00 39 00 61 00 38 00 39 00 61 00 66 00 61 00 63 00 35 00 32 00 38 00 36 00 62 00 65 00}
		$s19 = {39 00 30 00 39 00 32 00 38 00 66 00 64 00 31 00 32 00 35 00 30 00 34 00 33 00 35 00 35 00 38 00 39 00 63 00 63 00 30 00 31 00 35 00 30 00 38 00 34 00 39 00 62 00 63 00 30 00 63 00 66 00 66 00}
		$s20 = {36 00 37 00 64 00 61 00 38 00 30 00 37 00 32 00 36 00 38 00 37 00 36 00 34 00 61 00 37 00 62 00 61 00 64 00 63 00 34 00 39 00 30 00 34 00 64 00 66 00 33 00 35 00 31 00 39 00 33 00 32 00 65 00}
		$op0 = { 30 01 00 2b 68 79 33 38 68 34 77 65 36 34 74 72 }
		$op1 = { 01 00 b2 04 00 00 01 00 84 }
		$op2 = { 68 09 00 00 38 66 00 00 23 55 53 00 a0 6f 00 00 }

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 100KB and pe.imphash ( ) == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them ) and all of ( $op* ) ) or ( all of them )
}

