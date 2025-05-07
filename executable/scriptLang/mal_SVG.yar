rule malicious_SVG_1 : hardened
{
	meta:
		author = "OPSWAT"
		description = "Identify malicious JavaScript on SVG files"
		score = 75

	strings:
		$tag_xml_header = {3c 3f 78 6d 6c 20 76 65 72 73 69 6f 6e 3d}
		$tag_svg_start = {3c 73 76 67}
		$tag_svg_end = {3c 2f 73 76 67 3e}
		$tag_script_start = {3c 73 63 72 69 70 74}
		$tag_script_end = {3c 2f 73 63 72 69 70 74}
		$st1_cdata = {3c 21 5b 43 44 41 54 41 5b}
		$st2_atob = {61 74 6f 62 28}
		$st2_charcode = {63 68 61 72 43 6f 64 65 41 74 28}
		$st2_split = {2e 73 70 6c 69 74 28}
		$st2_map = {2e 6d 61 70 28}

	condition:
		all of ( $tag* ) and $st1_cdata and all of ( $st2* ) and for all of ( $st* ) : ( @ > @tag_script_start and @ < @tag_script_end )
}

rule malicious_SVG_2 : hardened
{
	meta:
		author = "OPSWAT"
		description = "Identify malicious JavaScript on SVG files"
		score = 75

	strings:
		$tag_xml_header = {3c 3f 78 6d 6c 20 76 65 72 73 69 6f 6e 3d}
		$tag_svg_start = {3c 73 76 67}
		$tag_svg_end = {3c 2f 73 76 67 3e}
		$tag_script_start = {3c 73 63 72 69 70 74}
		$tag_script_end = {3c 2f 73 63 72 69 70 74}
		$st1_cdata = {3c 21 5b 43 44 41 54 41 5b}
		$st2_atob = {61 74 6f 62 28}
		$st2_charcode = {63 68 61 72 43 6f 64 65 41 74 28}
		$st2_map = {2e 6d 61 70 28}

	condition:
		all of ( $tag* ) and $st1_cdata and not malicious_SVG_1 and all of ( $st2* ) and for all of ( $st* ) : ( @ > @tag_script_start and @ < @tag_script_end )
}

rule malicious_SVG_3 : hardened
{
	meta:
		author = "OPSWAT"
		description = "Identify malicious JavaScript on SVG files"
		score = 75

	strings:
		$tag_svg_start = {3c 73 76 67}
		$tag_svg_end = {3c 2f 73 76 67 3e}
		$tag_script_start = {3c 73 63 72 69 70 74}
		$tag_script_end = {3c 2f 73 63 72 69 70 74}
		$st1_cdata = {3c 21 5b 43 44 41 54 41 5b}
		$st2_try = {74 72 79 20 7b}
		$st2_number_array = /= \[((\"|\')\d(\"|\'), ?){10}/
		$st2_window_location = {77 69 6e 64 6f 77 2e 6c 6f 63 61 74 69 6f 6e 2e 68 72 65 66 20 3d 20}

	condition:
		all of ( $tag* ) and $st1_cdata and not malicious_SVG_1 and not malicious_SVG_2 and all of ( $st2* ) and for all of ( $st* ) : ( @ > @tag_script_start and @ < @tag_script_end )
}

