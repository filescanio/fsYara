rule Sliver_Implant_32bit : hardened
{
	meta:
		description = "Sliver 32-bit implant (with and without --debug flag at compile)"
		hash = "911f4106350871ddb1396410d36f2d2eadac1166397e28a553b28678543a9357"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		score = 75
		id = "6bc4d7d1-64cf-5920-8f07-54a8a7a94f26"

	strings:
		$s_tcppivot = { 81 ?? 74 63 70 70 [2-20] 81 ?? 04 69 76 6F 74  }
		$s_wg = { 66 81 ?? 77 67 }
		$s_dns = { 66 81 ?? 64 6E [2-20] 80 ?? 02 73 }
		$s_http = { 81 ?? 68 74 74 70 }
		$s_https = { 81 ?? 68 74 74 70 [2-20] 80 ?? 04 73 }
		$s_mtls = { 81 ?? 6D 74 6C 73 }
		$fp1 = {63 6c 6f 75 64 66 6f 75 6e 64 72 79}

	condition:
		4 of ( $s* ) and not 1 of ( $fp* )
}

rule Sliver_Implant_64bit : hardened
{
	meta:
		description = "Sliver 64-bit implant (with and without --debug flag at compile)"
		hash = "2d1c9de42942a16c88a042f307f0ace215cdc67241432e1152080870fe95ea87"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		score = 75
		id = "b84db933-0e11-5871-821d-43697c015665"

	strings:
		$s_tcppivot = { 48 ?? 74 63 70 70 69 76 6F 74 }
		$s_namedpipe = { 48 ?? 6E 61 6D 65 64 70 69 70 [2-32] 80 ?? 08 65 }
		$s_https = { 81 ?? 68 74 74 70 [2-32] 80 ?? 04 73 }
		$s_wg = {66 81 ?? 77 67}
		$s_dns = { 66 81 ?? 64 6E [2-20] 80 ?? 02 73 }
		$s_mtls = {  81 ?? 6D 74 6C 73  }
		$fp1 = {63 6c 6f 75 64 66 6f 75 6e 64 72 79}

	condition:
		5 of ( $s* ) and not 1 of ( $fp* )
}

