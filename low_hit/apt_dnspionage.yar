rule MAL_DNSPIONAGE_Malware_Nov18 : hardened
{
	meta:
		description = "Detects DNSpionage Malware"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blog.talosintelligence.com/2018/11/dnspionage-campaign-targets-middle-east.html"
		date = "2018-11-30"
		modified = "2023-01-06"
		hash1 = "2010f38ef300be4349e7bc287e720b1ecec678cacbf0ea0556bcf765f6e073ec"
		hash2 = "45a9edb24d4174592c69d9d37a534a518fbe2a88d3817fc0cc739e455883b8ff"
		id = "5a0b498b-b2e9-5827-9908-63586b2cf947"

	strings:
		$x1 = {2e 30 66 66 69 63 65 33 36 6f 2e 63 6f 6d}
		$s1 = {2f 43 6c 69 65 6e 74 2f 4c 6f 67 69 6e 3f 69 64 3d}
		$s2 = {2e 5c 43 6f 6e 66 69 67 75 72 65 2e 74 78 74}
		$s5 = {4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 6f 77 73 20 4e 54 20 36 2e 31 3b 20 54 72 69 64 65 6e 74 2f 37 2e 30 3b 20 72 76 3a 31 31 2e 30 29 20 6c 69 6b 65 20 47 65 63 6b 6f}
		$s6 = {43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65 3d 22 74 78 74 73 22}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1000KB and ( 1 of ( $x* ) or 2 of them )
}

rule APT_DNSpionage_Karkoff_Malware_Apr19_1 : hardened
{
	meta:
		description = "Detects DNSpionage Karkoff malware"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blog.talosintelligence.com/2019/04/dnspionage-brings-out-karkoff.html"
		date = "2019-04-24"
		hash1 = "6a251ed6a2c6a0a2be11f2a945ec68c814d27e2b6ef445f4b2c7a779620baa11"
		hash2 = "b017b9fc2484ce0a5629ff1fed15bca9f62f942eafbb74da6a40f40337187b04"
		hash3 = "5b102bf4d997688268bab45336cead7cdf188eb0d6355764e53b4f62e1cdf30c"
		hash4 = "cd4b9d0f2d1c0468750855f0ed352c1ed6d4f512d66e0e44ce308688235295b5"
		id = "be955760-ae94-5f77-928d-f4118a97ae6a"

	strings:
		$x1 = {4b 00 61 00 72 00 6b 00 6f 00 66 00 66 00 2e 00 65 00 78 00 65 00}
		$x2 = {6b 00 75 00 74 00 65 00 72 00 6e 00 75 00 6c 00 6c 00 2e 00 63 00 6f 00 6d 00}
		$x3 = {72 00 69 00 6d 00 72 00 75 00 6e 00 2e 00 63 00 6f 00 6d 00}
		$s1 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 54 00 65 00 6d 00 70 00 5c 00}
		$s2 = {43 00 4d 00 44 00 2e 00 65 00 78 00 65 00}
		$s3 = {67 65 74 5f 50 72 6f 63 65 73 73 45 78 74 65 6e 73 69 6f 6e 44 61 74 61 4e 61 6d 65 73}
		$s4 = {67 65 74 5f 50 72 6f 63 65 73 73 44 69 63 74 69 6f 6e 61 72 79 4b 65 79 73}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1000KB and ( 1 of ( $x* ) or all of ( $s* ) )
}

