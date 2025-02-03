rule QuarksPwDump_Gen : hardened
{
	meta:
		description = "Detects all QuarksPWDump versions"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2015-09-29"
		score = 80
		hash1 = "2b86e6aea37c324ce686bd2b49cf5b871d90f51cec24476daa01dd69543b54fa"
		hash2 = "87e4c76cd194568e65287f894b4afcef26d498386de181f568879dde124ff48f"
		hash3 = "a59be92bf4cce04335bd1a1fcf08c1a94d5820b80c068b3efe13e2ca83d857c9"
		hash4 = "c5cbb06caa5067fdf916e2f56572435dd40439d8e8554d3354b44f0fd45814ab"
		hash5 = "677c06db064ee8d8777a56a641f773266a4d8e0e48fbf0331da696bea16df6aa"
		hash6 = "d3a1eb1f47588e953b9759a76dfa3f07a3b95fab8d8aa59000fd98251d499674"
		hash7 = "8a81b3a75e783765fe4335a2a6d1e126b12e09380edc4da8319efd9288d88819"
		id = "7de4f59e-6cf5-5ad7-ae1f-8532d9e80c9e"

	strings:
		$s1 = {4f 70 65 6e 50 72 6f 63 65 73 73 54 6f 6b 65 6e 28 29 20 65 72 72 6f 72 3a 20 30 78 25 30 38 58}
		$s2 = {25 64 20 64 75 6d 70 65 64}
		$s3 = {41 64 6a 75 73 74 54 6f 6b 65 6e 50 72 69 76 69 6c 65 67 65 73 28 29 20 65 72 72 6f 72 3a 20 30 78 25 30 38 58}
		$s4 = {5c 53 41 4d 2d 25 75 2e 64 6d 70}

	condition:
		all of them
}

