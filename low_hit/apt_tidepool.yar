rule TidePool_Malware : hardened
{
	meta:
		description = "Detects TidePool malware mentioned in Ke3chang report by Palo Alto Networks"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/m2CXWR"
		date = "2016-05-24"
		hash1 = "9d0a47bdf00f7bd332ddd4cf8d95dd11ebbb945dda3d72aac512512b48ad93ba"
		hash2 = "67c4e8ab0f12fae7b4aeb66f7e59e286bd98d3a77e5a291e8d58b3cfbc1514ed"
		hash3 = "2252dcd1b6afacde3f94d9557811bb769c4f0af3cb7a48ffe068d31bb7c30e18"
		hash4 = "38f2c86041e0446730479cdb9c530298c0c4936722975c4e7446544fd6dcac9f"
		hash5 = "9d0a47bdf00f7bd332ddd4cf8d95dd11ebbb945dda3d72aac512512b48ad93ba"
		id = "eec12fd7-f5f8-5bee-98e0-2111766deb55"

	strings:
		$x1 = {43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65 3d 22 6d 31 2e 6a 70 67 22}
		$x2 = {43 00 3a 00 5c 00 50 00 52 00 4f 00 47 00 52 00 41 00 7e 00 32 00 5c 00 49 00 45 00 48 00 65 00 6c 00 70 00 65 00 72 00 5c 00 6d 00 73 00 68 00 74 00 6d 00 6c 00 2e 00 64 00 6c 00 6c 00}
		$x3 = {43 00 3a 00 5c 00 44 00 4f 00 43 00 55 00 4d 00 45 00 7e 00 31 00 5c 00 41 00 4c 00 4c 00 55 00 53 00 45 00 7e 00 31 00 5c 00 49 00 45 00 48 00 65 00 6c 00 70 00 65 00 72 00 5c 00 6d 00 73 00 68 00 74 00 6d 00 6c 00 2e 00 64 00 6c 00 6c 00}
		$x4 = {49 45 43 6f 6d 44 6c 6c 2e 64 61 74}
		$s1 = {43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 2d 00 54 00 79 00 70 00 65 00 3a 00 20 00 6d 00 75 00 6c 00 74 00 69 00 70 00 61 00 72 00 74 00 2f 00 66 00 6f 00 72 00 6d 00 2d 00 64 00 61 00 74 00 61 00 3b 00 20 00 62 00 6f 00 75 00 6e 00 64 00 61 00 72 00 79 00 3d 00 2d 00 2d 00 2d 00 2d 00 3d 00 5f 00 50 00 61 00 72 00 74 00 5f 00 25 00 78 00}
		$s2 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00}
		$s3 = {6e 65 74 77 6f 72 6b 2e 70 72 6f 78 79 2e 73 6f 63 6b 73 5f 70 6f 72 74 22 2c 20}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 200KB and ( 1 of ( $x* ) ) ) or ( 4 of them )
}

