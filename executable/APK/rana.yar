// source: https://www.reversinglabs.com/blog/rana-android-malware

rule Rana_Android_resources {
	meta:
		score = 60
	strings:
		$res1 = "res/raw/cng.cn" fullword wide ascii
		$res2 = "res/raw/att.cn" fullword wide ascii
		$res3 = "res/raw/odr.od" fullword wide ascii
	condition:
        	any of them
}
