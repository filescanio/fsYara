rule KeyBoy_Dropper : hardened
{
	meta:
		Author = "Rapid7 Labs"
		Date = "2013/06/07"
		Description = "Strings inside"
		Reference = "https://community.rapid7.com/community/infosec/blog/2013/06/07/keyboy-targeted-attacks-against-vietnam-and-india"

	strings:
		$1 = {49 20 61 6d 20 41 64 6d 69 6e}
		$2 = {49 20 61 6d 20 55 73 65 72}
		$3 = {52 75 6e 20 69 6e 73 74 61 6c 6c 20 73 75 63 63 65 73 73 21}
		$4 = {53 65 72 76 69 63 65 20 69 6e 73 74 61 6c 6c 20 73 75 63 63 65 73 73 21}
		$5 = {53 6f 6d 65 74 68 69 6e 67 20 45 72 72 6f 72 21}
		$6 = {4e 6f 74 20 43 6f 6e 66 69 67 65 64 2c 20 45 78 69 74 69 6e 67}

	condition:
		all of them
}

rule KeyBoy_Backdoor : hardened
{
	meta:
		Author = "Rapid7 Labs"
		Date = "2013/06/07"
		Description = "Strings inside"
		Reference = "https://community.rapid7.com/community/infosec/blog/2013/06/07/keyboy-targeted-attacks-against-vietnam-and-india"

	strings:
		$1 = {24 6c 6f 67 69 6e 24}
		$2 = {24 73 79 73 69 6e 66 6f 24}
		$3 = {24 73 68 65 6c 6c 24}
		$4 = {24 66 69 6c 65 4d 61 6e 61 67 65 72 24}
		$5 = {24 66 69 6c 65 44 6f 77 6e 6c 6f 61 64 24}
		$6 = {24 66 69 6c 65 55 70 6c 6f 61 64 24}

	condition:
		all of them
}

import "pe"

rule new_keyboy_export : hardened
{
	meta:
		author = "Matt Brooks, @cmatthewbrooks"
		desc = "Matches the new 2016 sample's export"
		date = "2016-08-28"
		md5 = "495adb1b9777002ecfe22aaf52fcee93"

	condition:
		uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 and filesize < 200KB and pe.exports ( "cfsUpdate" )
}

rule new_keyboy_header_codes : hardened limited
{
	meta:
		author = "Matt Brooks, @cmatthewbrooks"
		desc = "Matches the 2016 sample's header codes"
		date = "2016-08-28"
		md5 = "495adb1b9777002ecfe22aaf52fcee93"

	strings:
		$s1 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 2a 00 6c 00 2a 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s2 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 2a 00 61 00 2a 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s3 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 2a 00 73 00 2a 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s4 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 2a 00 64 00 2a 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s5 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 2a 00 66 00 2a 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s6 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 2a 00 67 00 2a 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s7 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 2a 00 68 00 2a 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}

	condition:
		uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 and filesize < 200KB and all of them
}

rule keyboy_commands : hardened limited
{
	meta:
		author = "Matt Brooks, @cmatthewbrooks"
		desc = "Matches the 2016 sample's sent and received commands"
		date = "2016-08-28"
		md5 = "495adb1b9777002ecfe22aaf52fcee93"

	strings:
		$s1 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 55 00 70 00 64 00 61 00 74 00 65 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s2 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 55 00 70 00 64 00 61 00 74 00 65 00 41 00 6e 00 64 00 52 00 75 00 6e 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s3 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 52 00 65 00 66 00 72 00 65 00 73 00 68 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s4 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 4f 00 6e 00 4c 00 69 00 6e 00 65 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s5 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 44 00 69 00 73 00 63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s6 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 50 00 77 00 5f 00 45 00 72 00 72 00 6f 00 72 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s7 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 50 00 77 00 5f 00 4f 00 4b 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s8 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 53 00 79 00 73 00 69 00 6e 00 66 00 6f 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s9 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s10 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 55 00 70 00 6c 00 6f 00 61 00 64 00 46 00 69 00 6c 00 65 00 4f 00 6b 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s11 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 52 00 65 00 6d 00 6f 00 74 00 65 00 52 00 75 00 6e 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s12 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 46 00 69 00 6c 00 65 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}

	condition:
		uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 and filesize < 200KB and 6 of them
}

rule keyboy_errors : hardened
{
	meta:
		author = "Matt Brooks, @cmatthewbrooks"
		desc = "Matches the sample's shell error2 log statements"
		date = "2016-08-28"
		md5 = "495adb1b9777002ecfe22aaf52fcee93"

	strings:
		$error = {((45 72 72 6f 72 32) | (45 00 72 00 72 00 6f 00 72 00 32 00))}
		$s1 = {((43 61 6e 27 74 20 66 69 6e 64 20 5b 25 73 5d 21 43 68 65 63 6b 20 74 68 65 20 66 69 6c 65 20 6e 61 6d 65 20 61 6e 64 20 74 72 79 20 61 67 61 69 6e 21) | (43 00 61 00 6e 00 27 00 74 00 20 00 66 00 69 00 6e 00 64 00 20 00 5b 00 25 00 73 00 5d 00 21 00 43 00 68 00 65 00 63 00 6b 00 20 00 74 00 68 00 65 00 20 00 66 00 69 00 6c 00 65 00 20 00 6e 00 61 00 6d 00 65 00 20 00 61 00 6e 00 64 00 20 00 74 00 72 00 79 00 20 00 61 00 67 00 61 00 69 00 6e 00 21 00))}
		$s2 = {((4f 70 65 6e 20 5b 25 73 5d 20 65 72 72 6f 72 21 20 25 64) | (4f 00 70 00 65 00 6e 00 20 00 5b 00 25 00 73 00 5d 00 20 00 65 00 72 00 72 00 6f 00 72 00 21 00 20 00 25 00 64 00))}
		$s3 = {((54 68 65 20 53 69 7a 65 20 6f 66 20 5b 25 73 5d 20 69 73 20 7a 65 72 6f 21) | (54 00 68 00 65 00 20 00 53 00 69 00 7a 00 65 00 20 00 6f 00 66 00 20 00 5b 00 25 00 73 00 5d 00 20 00 69 00 73 00 20 00 7a 00 65 00 72 00 6f 00 21 00))}
		$s4 = {((43 72 65 61 74 65 54 68 72 65 61 64 20 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 5b 25 73 5d 20 45 72 72 6f 72 21) | (43 00 72 00 65 00 61 00 74 00 65 00 54 00 68 00 72 00 65 00 61 00 64 00 20 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 46 00 69 00 6c 00 65 00 5b 00 25 00 73 00 5d 00 20 00 45 00 72 00 72 00 6f 00 72 00 21 00))}
		$s5 = {((55 70 6c 6f 61 64 46 69 6c 65 20 5b 25 73 5d 20 45 72 72 6f 72 3a 43 6f 6e 6e 65 63 74 20 53 65 72 76 65 72 20 46 61 69 6c 65 64 21) | (55 00 70 00 6c 00 6f 00 61 00 64 00 46 00 69 00 6c 00 65 00 20 00 5b 00 25 00 73 00 5d 00 20 00 45 00 72 00 72 00 6f 00 72 00 3a 00 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 20 00 53 00 65 00 72 00 76 00 65 00 72 00 20 00 46 00 61 00 69 00 6c 00 65 00 64 00 21 00))}
		$s6 = {((52 65 63 65 69 76 65 20 5b 25 73 5d 20 45 72 72 6f 72 28 52 65 63 76 65 64 5b 25 64 5d 20 21 3d 20 53 65 6e 64 5b 25 64 5d 29 21) | (52 00 65 00 63 00 65 00 69 00 76 00 65 00 20 00 5b 00 25 00 73 00 5d 00 20 00 45 00 72 00 72 00 6f 00 72 00 28 00 52 00 65 00 63 00 76 00 65 00 64 00 5b 00 25 00 64 00 5d 00 20 00 21 00 3d 00 20 00 53 00 65 00 6e 00 64 00 5b 00 25 00 64 00 5d 00 29 00 21 00))}
		$s7 = {((52 65 63 65 69 76 65 20 5b 25 73 5d 20 6f 6b 21 20 55 73 65 20 25 32 2e 32 66 20 73 65 63 6f 6e 64 73 2c 20 41 76 65 72 61 67 65 20 73 70 65 65 64 20 25 32 2e 32 66 20 6b 2f 73) | (52 00 65 00 63 00 65 00 69 00 76 00 65 00 20 00 5b 00 25 00 73 00 5d 00 20 00 6f 00 6b 00 21 00 20 00 55 00 73 00 65 00 20 00 25 00 32 00 2e 00 32 00 66 00 20 00 73 00 65 00 63 00 6f 00 6e 00 64 00 73 00 2c 00 20 00 41 00 76 00 65 00 72 00 61 00 67 00 65 00 20 00 73 00 70 00 65 00 65 00 64 00 20 00 25 00 32 00 2e 00 32 00 66 00 20 00 6b 00 2f 00 73 00))}
		$s8 = {((43 72 65 61 74 65 54 68 72 65 61 64 20 55 70 6c 6f 61 64 46 69 6c 65 5b 25 73 5d 20 45 72 72 6f 72 21) | (43 00 72 00 65 00 61 00 74 00 65 00 54 00 68 00 72 00 65 00 61 00 64 00 20 00 55 00 70 00 6c 00 6f 00 61 00 64 00 46 00 69 00 6c 00 65 00 5b 00 25 00 73 00 5d 00 20 00 45 00 72 00 72 00 6f 00 72 00 21 00))}
		$s9 = {((52 65 61 64 79 20 44 6f 77 6e 6c 6f 61 64 20 5b 25 73 5d 20 6f 6b 21) | (52 00 65 00 61 00 64 00 79 00 20 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 20 00 5b 00 25 00 73 00 5d 00 20 00 6f 00 6b 00 21 00))}
		$s10 = {((47 65 74 20 43 6f 6e 74 72 6f 6c 49 6e 66 6f 20 66 72 6f 6d 20 46 69 6c 65 43 6c 69 65 6e 74 20 65 72 72 6f 72 21) | (47 00 65 00 74 00 20 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 49 00 6e 00 66 00 6f 00 20 00 66 00 72 00 6f 00 6d 00 20 00 46 00 69 00 6c 00 65 00 43 00 6c 00 69 00 65 00 6e 00 74 00 20 00 65 00 72 00 72 00 6f 00 72 00 21 00))}
		$s11 = {((46 69 6c 65 43 6c 69 65 6e 74 20 68 61 73 20 61 20 65 72 72 6f 72 21) | (46 00 69 00 6c 00 65 00 43 00 6c 00 69 00 65 00 6e 00 74 00 20 00 68 00 61 00 73 00 20 00 61 00 20 00 65 00 72 00 72 00 6f 00 72 00 21 00))}
		$s12 = {((56 69 72 74 75 61 6c 41 6c 6c 6f 63 20 53 65 6e 64 42 75 66 66 20 45 72 72 6f 72 28 25 64 29) | (56 00 69 00 72 00 74 00 75 00 61 00 6c 00 41 00 6c 00 6c 00 6f 00 63 00 20 00 53 00 65 00 6e 00 64 00 42 00 75 00 66 00 66 00 20 00 45 00 72 00 72 00 6f 00 72 00 28 00 25 00 64 00 29 00))}
		$s13 = {((52 65 61 64 46 69 6c 65 20 5b 25 73 5d 20 45 72 72 6f 72 28 25 64 29 2e 2e 2e) | (52 00 65 00 61 00 64 00 46 00 69 00 6c 00 65 00 20 00 5b 00 25 00 73 00 5d 00 20 00 45 00 72 00 72 00 6f 00 72 00 28 00 25 00 64 00 29 00 2e 00 2e 00 2e 00))}
		$s14 = {((52 65 61 64 46 69 6c 65 20 5b 25 73 5d 20 44 61 74 61 5b 52 65 61 64 65 64 28 25 64 29 20 21 3d 20 46 69 6c 65 53 69 7a 65 28 25 64 29 5d 20 45 72 72 6f 72 2e 2e 2e) | (52 00 65 00 61 00 64 00 46 00 69 00 6c 00 65 00 20 00 5b 00 25 00 73 00 5d 00 20 00 44 00 61 00 74 00 61 00 5b 00 52 00 65 00 61 00 64 00 65 00 64 00 28 00 25 00 64 00 29 00 20 00 21 00 3d 00 20 00 46 00 69 00 6c 00 65 00 53 00 69 00 7a 00 65 00 28 00 25 00 64 00 29 00 5d 00 20 00 45 00 72 00 72 00 6f 00 72 00 2e 00 2e 00 2e 00))}
		$s15 = {((43 72 65 61 74 65 54 68 72 65 61 64 20 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 5b 25 73 5d 20 45 72 72 6f 72 21) | (43 00 72 00 65 00 61 00 74 00 65 00 54 00 68 00 72 00 65 00 61 00 64 00 20 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 46 00 69 00 6c 00 65 00 5b 00 25 00 73 00 5d 00 20 00 45 00 72 00 72 00 6f 00 72 00 21 00))}
		$s16 = {((52 65 63 76 44 61 74 61 20 4d 79 52 65 63 76 5f 49 6e 66 6f 20 53 69 7a 65 20 45 72 72 6f 72 21) | (52 00 65 00 63 00 76 00 44 00 61 00 74 00 61 00 20 00 4d 00 79 00 52 00 65 00 63 00 76 00 5f 00 49 00 6e 00 66 00 6f 00 20 00 53 00 69 00 7a 00 65 00 20 00 45 00 72 00 72 00 6f 00 72 00 21 00))}
		$s17 = {((52 65 63 76 44 61 74 61 20 4d 79 52 65 63 76 5f 49 6e 66 6f 20 54 61 67 20 45 72 72 6f 72 21) | (52 00 65 00 63 00 76 00 44 00 61 00 74 00 61 00 20 00 4d 00 79 00 52 00 65 00 63 00 76 00 5f 00 49 00 6e 00 66 00 6f 00 20 00 54 00 61 00 67 00 20 00 45 00 72 00 72 00 6f 00 72 00 21 00))}
		$s18 = {((53 65 6e 64 44 61 74 61 20 73 7a 43 6f 6e 74 72 6f 6c 49 6e 66 6f 5f 31 20 45 72 72 6f 72 21) | (53 00 65 00 6e 00 64 00 44 00 61 00 74 00 61 00 20 00 73 00 7a 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 49 00 6e 00 66 00 6f 00 5f 00 31 00 20 00 45 00 72 00 72 00 6f 00 72 00 21 00))}
		$s19 = {((53 65 6e 64 44 61 74 61 20 73 7a 43 6f 6e 74 72 6f 6c 49 6e 66 6f 5f 33 20 45 72 72 6f 72 21) | (53 00 65 00 6e 00 64 00 44 00 61 00 74 00 61 00 20 00 73 00 7a 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 49 00 6e 00 66 00 6f 00 5f 00 33 00 20 00 45 00 72 00 72 00 6f 00 72 00 21 00))}
		$s20 = {((56 69 72 74 75 61 6c 41 6c 6c 6f 63 20 52 65 63 76 42 75 66 66 20 45 72 72 6f 72 28 25 64 29) | (56 00 69 00 72 00 74 00 75 00 61 00 6c 00 41 00 6c 00 6c 00 6f 00 63 00 20 00 52 00 65 00 63 00 76 00 42 00 75 00 66 00 66 00 20 00 45 00 72 00 72 00 6f 00 72 00 28 00 25 00 64 00 29 00))}
		$s21 = {((52 65 63 76 44 61 74 61 20 45 72 72 6f 72 21) | (52 00 65 00 63 00 76 00 44 00 61 00 74 00 61 00 20 00 45 00 72 00 72 00 6f 00 72 00 21 00))}
		$s22 = {((57 72 69 74 65 46 69 6c 65 20 5b 25 73 7d 20 45 72 72 6f 72 28 25 64 29 2e 2e 2e) | (57 00 72 00 69 00 74 00 65 00 46 00 69 00 6c 00 65 00 20 00 5b 00 25 00 73 00 7d 00 20 00 45 00 72 00 72 00 6f 00 72 00 28 00 25 00 64 00 29 00 2e 00 2e 00 2e 00))}

	condition:
		uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 and filesize < 200KB and $error and 3 of ( $s* )
}

rule keyboy_systeminfo : hardened
{
	meta:
		author = "Matt Brooks, @cmatthewbrooks"
		desc = "Matches the system information format before sending to C2"
		date = "2016-08-28"
		md5 = "495adb1b9777002ecfe22aaf52fcee93"

	strings:
		$s1 = {((53 79 73 74 65 6d 56 65 72 73 69 6f 6e 3a 20 20 20 20 25 73) | (53 00 79 00 73 00 74 00 65 00 6d 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 3a 00 20 00 20 00 20 00 20 00 25 00 73 00))}
		$s2 = {((50 72 6f 64 75 63 74 20 20 49 44 3a 20 20 20 20 20 20 25 73) | (50 00 72 00 6f 00 64 00 75 00 63 00 74 00 20 00 20 00 49 00 44 00 3a 00 20 00 20 00 20 00 20 00 20 00 20 00 25 00 73 00))}
		$s3 = {((49 6e 73 74 61 6c 6c 50 61 74 68 3a 20 20 20 20 20 20 25 73) | (49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 50 00 61 00 74 00 68 00 3a 00 20 00 20 00 20 00 20 00 20 00 20 00 25 00 73 00))}
		$s4 = {((49 6e 73 74 61 6c 6c 54 69 6d 65 3a 20 20 20 20 20 20 25 64 2d 25 64 2d 25 64 2c 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64) | (49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 54 00 69 00 6d 00 65 00 3a 00 20 00 20 00 20 00 20 00 20 00 20 00 25 00 64 00 2d 00 25 00 64 00 2d 00 25 00 64 00 2c 00 20 00 25 00 30 00 32 00 64 00 3a 00 25 00 30 00 32 00 64 00 3a 00 25 00 30 00 32 00 64 00))}
		$s5 = {((52 65 73 67 69 73 74 65 72 47 72 6f 75 70 3a 20 20 20 25 73) | (52 00 65 00 73 00 67 00 69 00 73 00 74 00 65 00 72 00 47 00 72 00 6f 00 75 00 70 00 3a 00 20 00 20 00 20 00 25 00 73 00))}
		$s6 = {((52 65 67 69 73 74 65 72 55 73 65 72 3a 20 20 20 20 20 25 73) | (52 00 65 00 67 00 69 00 73 00 74 00 65 00 72 00 55 00 73 00 65 00 72 00 3a 00 20 00 20 00 20 00 20 00 20 00 25 00 73 00))}
		$s7 = {((43 6f 6d 70 75 74 65 72 4e 61 6d 65 3a 20 20 20 20 20 25 73) | (43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 4e 00 61 00 6d 00 65 00 3a 00 20 00 20 00 20 00 20 00 20 00 25 00 73 00))}
		$s8 = {((57 69 6e 64 6f 77 73 44 69 72 65 63 74 6f 72 79 3a 20 25 73) | (57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 44 00 69 00 72 00 65 00 63 00 74 00 6f 00 72 00 79 00 3a 00 20 00 25 00 73 00))}
		$s9 = {((53 79 73 74 65 6d 20 44 69 72 65 63 74 6f 72 79 3a 20 25 73) | (53 00 79 00 73 00 74 00 65 00 6d 00 20 00 44 00 69 00 72 00 65 00 63 00 74 00 6f 00 72 00 79 00 3a 00 20 00 25 00 73 00))}
		$s10 = {((4e 75 6d 62 65 72 20 6f 66 20 50 72 6f 63 65 73 73 6f 72 73 3a 20 20 20 20 20 20 20 25 64) | (4e 00 75 00 6d 00 62 00 65 00 72 00 20 00 6f 00 66 00 20 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 6f 00 72 00 73 00 3a 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 25 00 64 00))}
		$s11 = {((43 50 55 5b 25 64 5d 3a 20 20 25 73 3a 20 25 73 4d 48 7a) | (43 00 50 00 55 00 5b 00 25 00 64 00 5d 00 3a 00 20 00 20 00 25 00 73 00 3a 00 20 00 25 00 73 00 4d 00 48 00 7a 00))}
		$s12 = {((52 41 4d 3a 20 20 20 20 20 20 20 20 20 25 64 4d 42 20 54 6f 74 61 6c 2c 20 25 64 4d 42 20 46 72 65 65 2e) | (52 00 41 00 4d 00 3a 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 25 00 64 00 4d 00 42 00 20 00 54 00 6f 00 74 00 61 00 6c 00 2c 00 20 00 25 00 64 00 4d 00 42 00 20 00 46 00 72 00 65 00 65 00 2e 00))}
		$s13 = {((44 69 73 70 6c 61 79 4d 6f 64 65 3a 20 25 64 20 78 20 25 64 2c 20 25 64 48 7a 2c 20 25 64 62 69 74) | (44 00 69 00 73 00 70 00 6c 00 61 00 79 00 4d 00 6f 00 64 00 65 00 3a 00 20 00 25 00 64 00 20 00 78 00 20 00 25 00 64 00 2c 00 20 00 25 00 64 00 48 00 7a 00 2c 00 20 00 25 00 64 00 62 00 69 00 74 00))}
		$s14 = {((55 70 74 69 6d 65 3a 20 20 20 20 20 20 25 64 20 44 61 79 73 20 25 30 32 75 3a 25 30 32 75 3a 25 30 32 75) | (55 00 70 00 74 00 69 00 6d 00 65 00 3a 00 20 00 20 00 20 00 20 00 20 00 20 00 25 00 64 00 20 00 44 00 61 00 79 00 73 00 20 00 25 00 30 00 32 00 75 00 3a 00 25 00 30 00 32 00 75 00 3a 00 25 00 30 00 32 00 75 00))}

	condition:
		uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 and filesize < 200KB and 7 of them
}

import "pe"

rule keyboy_related_exports : hardened
{
	meta:
		author = "Matt Brooks, @cmatthewbrooks"
		desc = "Matches the new 2016 sample's export"
		date = "2016-08-28"
		md5 = "495adb1b9777002ecfe22aaf52fcee93"

	condition:
		uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 and filesize < 200KB and pe.exports ( "Embedding" ) or pe.exports ( "SSSS" ) or pe.exports ( "GetUP" )
}

import "pe"

rule keyboy_init_config_section : hardened
{
	meta:
		author = "Matt Brooks, @cmatthewbrooks"
		desc = "Matches the Init section where the config is stored"
		date = "2016-08-28"

	condition:
		uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 and filesize < 300KB and for any i in ( 0 .. pe.number_of_sections - 1 ) : ( pe.sections [ i ] . name == ".Init" and pe.sections [ i ] . virtual_size % 1024 == 0 )
}

