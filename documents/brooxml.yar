// src: https://github.com/EmergingThreats/threatresearch/blob/master/yara/brooxml.yar

rule Brooxml_Phishing {
    meta:
        description = "Detects PDF and OOXML files leading to AiTM phishing"
        author = "Proofpoint"
        category = "phishing"
        date = "2024-11-27"
        score = 65
        reference = "https://x.com/threatinsight/status/1861817946508763480"
    strings:
        $hex1 = { 21 20 03 20 c3 be c3 bf 09 20 [0-1] 06 20 20 20 20 20 20 20 20 20 20 20 01 20 20 20 06 20 20 20 20 20 20 20 20 10 20 20 05 20 20 20 01 20 20 20 c3 be c3 bf c3 bf c3 bf }
        $docx = { 50 4b }
        $pdf = { 25 50 44 46 2d }
    condition:
        all of ($hex*) and (($docx at 0) or ($pdf at 0))
}
