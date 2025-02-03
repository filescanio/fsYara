rule OpClandestineWolf : hardened
{
	meta:
		alert_severity = "HIGH"
		log = "false"
		author = "NDF"
		weight = 10
		alert = true
		source = " https://www.fireeye.com/blog/threat-research/2015/06/operation-clandestine-wolf-adobe-flash-zero-day.html"
		version = 1
		date = "2015-06-23"
		description = "Operation Clandestine Wolf signature based on OSINT from 06.23.15"
		hash0 = "1a4b710621ef2e69b1f7790ae9b7a288"
		hash1 = "917c92e8662faf96fffb8ffe7b7c80fb"
		hash2 = "975b458cb80395fa32c9dda759cb3f7b"
		hash3 = "3ed34de8609cd274e49bbd795f21acc4"
		hash4 = "b1a55ec420dd6d24ff9e762c7b753868"
		hash5 = "afd753a42036000ad476dcd81b56b754"
		hash6 = "fad20abf8aa4eda0802504d806280dd7"
		hash7 = "ab621059de2d1c92c3e7514e4b51751a"
		hash8 = "510b77a4b075f09202209f989582dbea"
		hash9 = "d1b1abfcc2d547e1ea1a4bb82294b9a3"
		hash10 = "4692337bf7584f6bda464b9a76d268c1"
		hash11 = "7cae5757f3ba9fef0a22ca0d56188439"
		hash12 = "1a7ba923c6aa39cc9cb289a17599fce0"
		hash13 = "f86db1905b3f4447eb5728859f9057b5"
		hash14 = "37c6d1d3054e554e13d40ea42458ebed"
		hash15 = "3e7430a09a44c0d1000f76c3adc6f4fa"
		hash16 = "98eb249e4ddc4897b8be6fe838051af7"
		hash17 = "1b57a7fad852b1d686c72e96f7837b44"
		hash18 = "ffb84b8561e49a8db60e0001f630831f"
		hash19 = "98eb249e4ddc4897b8be6fe838051af7"
		hash20 = "dfb4025352a80c2d81b84b37ef00bcd0"
		hash21 = "4457e89f4aec692d8507378694e0a3ba"
		hash22 = "48de562acb62b469480b8e29821f33b8"
		hash23 = "7a7eed9f2d1807f55a9308e21d81cccd"
		hash24 = "6817b29e9832d8fd85dcbe4af176efb6"

	strings:
		$s0 = {66 6c 61 73 68 2e 4d 65 64 69 61 2e 53 6f 75 6e 64 28 29}
		$s1 = {63 61 6c 6c 20 4b 65 72 6e 65 6c 33 32 21 56 69 72 74 75 61 6c 41 6c 6c 6f 63 28 30 78 31 66 31 34 30 30 30 30 68 61 73 68 24 3d 30 78 31 30 30 30 30 68 61 73 68 24 3d 30 78 31 30 30 30 68 61 73 68 24 3d 30 78 34 30 29}
		$s2 = {7b 34 44 33 36 45 39 37 32 2d 45 33 32 35 2d 31 31 43 45 2d 42 46 43 31 2d 30 38 30 30 32 42 45 31 30 33 31 38 7d}
		$s3 = {4e 65 74 53 74 72 65 61 6d}

	condition:
		all of them
}

