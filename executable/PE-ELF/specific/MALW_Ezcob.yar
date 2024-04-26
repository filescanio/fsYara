//source: https://github.com/Yara-Rules/rules/blob/0f93570194a80d2f2032869055808b0ddcdfb360/malware/MALW_Ezcob.yar
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule EzcobStrings : Ezcob Family
{
    meta:
        description = "Ezcob Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-23"

    strings:
        $ = "\x12F\x12F\x129\x12E\x12A\x12E\x12B\x12A\x12-\x127\x127\x128\x123\x12"
        $ = "\x121\x12D\x128\x123\x12B\x122\x12E\x128\x12-\x12B\x122\x123\x12D\x12"
        $ = "Ezcob" wide ascii
        $ = "l\x12i\x12u\x122\x120\x121\x123\x120\x124\x121\x126"
        $ = "20110113144935"

    condition:
       2 of them
}

//rule Ezcob : Family
//{
//    meta:
//        description = "Ezcob"
//        author = "Seth Hardy"
//        last_modified = "2014-06-23"
//
//    condition:
//        EzcobStrings
//}
