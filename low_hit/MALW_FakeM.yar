rule HTMLVariant : FakeM Family HTML Variant hardened
{
	meta:
		description = "Identifier for html variant of FAKEM"
		author = "Katie Kleemola"
		last_updated = "2014-05-20"

	strings:
		$s1 = { 8B 55 08 B9 00 50 00 00 8D 3D ?? ?? ?? 00 8B F7 AD 33 C2 AB 83 E9 04 85 C9 75 F5 }
		$s2 = { C6 45 F? (3?|4?) }

	condition:
		$s1 and #s2 == 16
}

rule FakeM_Generic : hardened
{
	meta:
		description = "Detects FakeM malware samples"
		author = "Florian Roth"
		reference = "http://researchcenter.paloaltonetworks.com/2016/01/scarlet-mimic-years-long-espionage-targets-minority-activists/"
		date = "2016-01-25"
		score = 85
		hash1 = "631fc66e57acd52284aba2608e6f31ba19e2807367e33d8704f572f6af6bd9c3"
		hash2 = "3d9bd26f5bd5401efa17690357f40054a3d7b438ce8c91367dbf469f0d9bd520"
		hash3 = "53af257a42a8f182e97dcbb8d22227c27d654bea756d7f34a80cc7982b70aa60"
		hash4 = "4a4dfffae6fc8be77ac9b2c67da547f0d57ffae59e0687a356f5105fdddc88a3"
		hash5 = "7bfbf49aa71b8235a16792ef721b7e4195df11cb75371f651595b37690d108c8"
		hash6 = "12dedcdda853da9846014186e6b4a5d6a82ba0cf61d7fa4cbe444a010f682b5d"
		hash7 = "9adda3d95535c6cf83a1ba08fe83f718f5c722e06d0caff8eab4a564185971c5"
		hash8 = "3209ab95ca7ee7d8c0140f95bdb61a37d69810a7a23d90d63ecc69cc8c51db90"
		hash9 = "41948c73b776b673f954f497e09cc469d55f27e7b6e19acb41b77f7e64c50a33"
		hash10 = "53cecc0d0f6924eacd23c49d0d95a6381834360fbbe2356778feb8dd396d723e"
		hash11 = "523ad50b498bfb5ab688d9b1958c8058f905b634befc65e96f9f947e40893e5b"

	strings:
		$a1 = {5c 73 79 73 74 65 6d 33 32 5c 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c}
		$a2 = {5c 62 6f 6f 74 2e 6c 6e 6b}
		$a3 = {25 55 53 45 52 50 52 4f 46 49 4c 45 25}
		$b1 = {57 00 69 00 7a 00 61 00 72 00 64 00 2e 00 45 00 58 00 45 00}
		$b2 = {43 6f 6d 6d 61 6e 64 4c 69 6e 65 41}
		$c1 = {5c 73 79 73 74 65 6d 33 32 5c 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c}
		$c2 = {5c 61 61 70 7a 2e 74 6d 70}
		$e1 = {43 3a 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 41 5c}
		$e2 = {5c 73 76 63 68 6f 73 74 2e 65 78 65}
		$e3 = {5c 50 65 72 66 6f 72 6d 5c 52 65 6c 65 61 73 65 5c 50 65 72 66 6f 72 6d 2e 70 64 62}
		$f1 = {42 00 72 00 6f 00 77 00 73 00 65 00 72 00 2e 00 45 00 58 00 45 00}
		$f2 = {5c 62 72 6f 77 73 65 72 2e 65 78 65}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 100KB and ( all of ( $a* ) or all of ( $b* ) or all of ( $c* ) or all of ( $e* ) or 1 of ( $f* ) )
}

