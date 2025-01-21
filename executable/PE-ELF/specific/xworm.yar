// source: https://github.com/jeFF0Falltrades/rat_king_parser/blob/master/src/rat_king_parser/yara_utils/rules.yar
// source: https://github.com/RussianPanda95/Yara-Rules/blob/main/XWorm/win_mal_XWorm.yar

rule win_mal_XWorm {
    meta:
        author = "RussianPanda"
        description = "Detects XWorm RAT"
        vetted_family = "xworm"
        score = 75
        date = "3/11/2024"
        hash = "fc422800144383ef6e2e0eee37e7d6ba"
    strings:
        $s1 = {4D 00 6F 00 64 00 69 00 66 00 69 00 65 00 64 00 20 00 73 00 75 00 63 00 63 00 65 00 73 00 73 00 66 00 75 00 6C 00 6C 00 79 00 21}
        $s2 = {50 00 6C 00 75 00 67 00 69 00 6E 00 73 00 20 00 52 00 65 00 6D 00 6F 00 76 00 65 00 64 00 21}
        $s3 = {73 00 65 00 6E 00 64 00 50 00 6C 00 75 00 67 00 69 00 6E}
        $s4 = {4D 00 6F 00 64 00 69 00 66 00 69 00 65 00 64 00 20 00 73 00 75 00 63 00 63 00 65 00 73 00 73 00 66 00 75 00 6C 00 6C 00 79 00 21}
        $s5 = "_CorExeMain"
    condition:
        uint16(0) == 0x5A4D and all of them
}


rule xworm : refined {
    meta:
        author = "jeFF0Falltrades"
        vetted_family = "xworm"
        score = 75
    strings:
        $str_xworm = "xworm" wide ascii nocase
        $str_xwormmm = "Xwormmm" wide ascii
        $str_xclient = "XClient" wide ascii
        $str_xlogger = "XLogger" wide ascii
        $str_xchat = "Xchat" wide ascii
        $str_default_log = "\\Log.tmp" wide ascii
        $str_create_proc = "/create /f /RL HIGHEST /sc minute /mo 1 /t" wide ascii 
        $str_ddos_start = "StartDDos" wide ascii 
        $str_ddos_stop = "StopDDos" wide ascii
        $str_timeout = "timeout 3 > NUL" wide ascii
        $byte_md5_hash = { 7e [3] 04 28 [3] 06 6f }
        $patt_config = { 72 [3] 70 80 [3] 04 }

    condition:
        uint16(0) == 0x5A4D and 5 of them and #patt_config >= 5
 }
