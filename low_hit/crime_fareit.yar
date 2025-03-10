rule Fareit_Trojan_Oct15 : hardened
{
	meta:
		description = "Detects Fareit Trojan from Sep/Oct 2015 Wave"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/5VYtlU"
		date = "2015-10-18"
		score = 80
		super_rule = 1
		hash1 = "230ca0beba8ae712cfe578d2b8ec9581ce149a62486bef209b04eb11d8c088c3"
		hash2 = "3477d6bfd8313d37fedbd3d6ba74681dd7cb59040cabc2991655bdce95a2a997"
		hash3 = "408fa0bd4d44de2940605986b554e8dab42f5d28a6a525b4bc41285e37ab488d"
		hash4 = "76669cbe6a6aac4aa52dbe9d2e027ba184bf3f0b425f478e8c049637624b5dae"
		hash5 = "9486b73eac92497e703615479d52c85cfb772b4ca6c846ef317729910e7c545f"
		hash6 = "c3300c648aebac7bf1d90f58ea75660c78604410ca0fa705d3b8ec1e0a45cdd9"
		hash7 = "ff83e9fcfdec4ffc748e0095391f84a8064ac958a274b9684a771058c04cb0fa"
		id = "725abb2a-7675-51b5-aed8-594e4826a6b4"

	strings:
		$s1 = {65 00 62 00 61 00 69 00 2e 00 65 00 78 00 65 00}
		$s2 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00}

	condition:
		uint16( 0 ) == 0x5a4d and $s1 in ( 0 .. 30000 ) and $s2 in ( 0 .. 30000 )
}

