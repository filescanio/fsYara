import "hash"

rule CrossRAT : RAT hardened limited
{
	meta:
		description = "Detects CrossRAT known hash"
		author = "Simon Sigre (simon.sigre@gmail.com)"
		date = "26/01/2018"
		ref = "https://simonsigre.com"
		ref = "https://objective-see.com/blog/blog_0x28.html"

	strings:
		$magic = { 50 4b 03 04 ( 14 | 0a ) 00 }
		$string_1 = {4d 45 54 41 2d 49 4e 46 2f}
		$string_2 = {2e 63 6c 61 73 73}

	condition:
		filesize < 400KB and $magic at 0 and 1 of ( $string_* ) and hash.md5 ( 0 , filesize ) == "85b794e080d83a91e904b97769e1e770"
}

