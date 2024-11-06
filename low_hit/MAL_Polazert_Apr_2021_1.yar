rule MAL_Polazert_Apr_2021_1
{
    meta:
        description = "Detect Polazert stealer"
        author = "Arkbird_SOLG"
        date = "2021-04-11"
        reference = "https://twitter.com/JAMESWT_MHT/status/1380773157615902720"
        hash = "https://bazaar.abuse.ch/browse/tag/Polazert/"
    strings:
        $seq1 = { 73 ?? 00 00 0a 13 ?? 11 ?? 72 [2] 00 70 6f ?? 00 00 0a 00 11 ?? 72 [2] 00 70 11 ?? 72 [2] 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 ?? 17 6f ?? 00 00 0a 00 11 ?? 28 ?? 00 00 0a 26 }
        $seq2 = { 1b 8d 0e 00 00 01 13 ?? 11 ?? 16 72 a1 03 00 70 a2 11 ?? 17 08 a2 11 ?? 18 72 53 03 00 70 a2 11 ?? 19 11 ?? a2 11 ?? 1a 72 e7 03 00 70 a2 11 ?? 28 47 00 00 0a 13 0a }
        $seq3 = { 02 73 ?? 00 00 0a 28 ?? 00 00 0a 74 2a 00 00 01 [2-4] 72 65 01 00 70 6f ?? 00 00 0a 00 [1-2] 72 65 01 00 70 6f ?? 00 00 0a 00 [1-2] 72 87 01 00 70 6f ?? 00 00 0a 00 03 [1-2] 73 ?? 00 00 0a 13 }          
        $seq4 = { 1f 0f 8d ?? 00 00 01 13 ?? 11 ?? 16 72 ?? ?? 00 70 a2 11 ?? 17 [1-2] a2 11 ?? 18 72 [2] 00 70 a2 11 ?? 19 28 ?? 00 00 06 a2 11 ?? 1a 72 ?? ?? 00 70 a2 11 ?? 1b 28 ?? 00 00 06 a2 11 ?? 1c 72 ?? ?? 00 70 a2 11 ?? 1d 28 ?? 00 00 06 2d 07 72 ?? ?? 00 70 2b 05 72 ?? ?? 00 70 a2 11 ?? 1e 72 ?? ?? 00 70 a2 11 ?? 1f 09 28 ?? 00 00 06 2d 07 72 ?? ?? 00 70 2b 05 72 ?? ?? 00 70 a2 11 ?? 1f 0a 72 [2] 00 70 a2 11 ?? 1f 0b [1-2] 7b 01 00 00 04 a2 11 ?? 1f 0c 72 [2] 00 70 a2 11 ?? 1f 0d 28 ?? 00 00 06 a2 11 ?? 1f 0e 72 [2] 00 70 a2 11 ?? 28 ?? 00 00 0a 13 }
        $seq5 = { 1f ?? 8d ?? 00 00 01 13 ?? 11 ?? 16 72 91 01 00 70 a2 11 ?? 17 1a 8d ?? 00 00 01 13 ?? 11 ?? 16 1f 68 9d 11 ?? 17 1f 77 9d 11 ?? 18 1f 69 9d 11 ?? 19 1f 64 9d 11 ?? 28 ?? 00 00 06 a2 11 ?? 18 72 b7 01 00 70 a2 11 ?? 19 ?? [0-1] a2 11 ?? 1a 72 bf 01 00 70 a2 11 ?? 1b 28 ?? 00 00 06 a2 11 ?? 1c 72 db 01 00 70 a2 11 ?? 1d 28 ?? 00 00 06 a2 11 ?? 1e 72 f7 01 00 70 a2 11 ?? 1f 09 28 ?? 00 00 06 2d 07 72 0d 02 00 70 2b 05 72 15 02 00 70 a2 11 ?? 1f 0a 72 1d 02 00 70 a2 11 ?? 1f 0b 28 ?? 00 00 06 2d 07 72 37 02 00 70 2b 05 72 41 02 00 70 a2 11 ?? 1f 0c 72 4d 02 00 70 a2 11 ?? 1f 0d ?? 7b ?? 00 00 04 a2 11 ?? 1f 0e 72 69 02 00 70 a2 11 ?? 1f 0f 1f 09 8d ?? 00 00 01 13 ?? 11 ?? 16 1f 77 9d 11 ?? 17 1f 6f 9d 11 ?? 18 1f 72 9d 11 ?? 19 1f 6b 9d 11 ?? 1a 1f 67 9d 11 ?? 1b 1f 72 9d 11 ?? 1c 1f 6f 9d 11 ?? 1d 1f 75 9d 11 ?? 1e 1f 70 9d 11 ?? 28 ?? 00 00 06 a2 11 ?? 1f 10 72 b7 01 00 70 a2 11 ?? 1f 11 28 ?? 00 00 06 a2 11 ?? 1f 12 72 71 02 00 70 a2 11 ?? 1f 13 1f 14 8d ?? 00 00 01 13 ?? 11 ?? 16 1f 77 9d 11 ?? 17 1f 69 9d 11 ?? 18 1f 6e 9d 11 ?? 19 1f 33 9d 11 ?? 1a 1f 32 9d 11 ?? 1b 1f 5f 9d 11 ?? 1c 1f 63 9d 11 ?? 1d 1f 6f 9d 11 ?? 1e 1f 6d 9d 11 ?? 1f 09 1f 70 9d 11 ?? 1f 0a 1f 75 9d 11 ?? 1f 0b 1f 74 9d 11 ?? 1f 0c 1f 65 9d 11 ?? 1f 0d 1f 72 9d 11 ?? 1f 0e 1f 73 9d 11 ?? 1f 0f 1f 79 9d 11 ?? 1f 10 1f 73 9d 11 ?? 1f 11 1f 74 9d 11 ?? 1f 12 1f 65 9d 11 ?? 1f 13 1f 6d 9d 11 ?? 28 ?? 00 00 06 1c 8d ?? 00 00 01 13 ?? 11 ?? 16 1f 64 9d 11 ?? 17 1f 6f 9d 11 ?? 18 1f 6d 9d 11 ?? 19 1f 61 9d 11 ?? 1a 1f 69 9d 11 ?? 1b 1f 6e 9d 11 ?? 28 ?? 00 00 06 28 ?? 00 00 06 a2 11 ?? 1f 14 72 69 02 00 70 a2 11 ?? 1f 15 19 8d ?? 00 00 01 13 ?? 11 ?? 16 1f 64 9d 11 ?? 17 1f 6e 9d 11 ?? 18 1f 73 9d 11 ?? 28 ?? 00 00 06 a2 11 ?? 1f 16 72 79 02 00 70 a2 11 ?? 1f 17 1f 14 8d ?? 00 00 01 13 ?? 11 ?? 16 1f 77 9d 11 ?? 17 1f 69 9d 11 ?? 18 1f 6e 9d 11 ?? 19 1f 33 9d 11 ?? 1a 1f 32 9d 11 ?? 1b 1f 5f 9d 11 ?? 1c 1f 63 9d 11 ?? 1d 1f 6f 9d 11 ?? 1e 1f 6d 9d 11 ?? 1f 09 1f 70 9d 11 ?? 1f 0a 1f 75 9d 11 ?? 1f 0b 1f 74 9d 11 ?? 1f 0c 1f 65 9d 11 ?? 1f 0d 1f 72 9d 11 ?? 1f 0e 1f 73 9d 11 ?? 1f 0f 1f 79 9d 11 ?? 1f 10 1f 73 9d 11 ?? 1f 11 1f 74 9d 11 ?? 1f 12 1f 65 9d 11 ?? 1f 13 1f 6d 9d 11 ?? 28 ?? 00 00 06 1f 0c 8d ?? 00 00 01 13 ?? 11 ?? 16 1f 70 9d 11 ?? 17 1f 61 9d 11 ?? 18 1f 72 9d 11 ?? 19 1f 74 9d 11 ?? 1a 1f 6f 9d 11 ?? 1b 1f 66 9d 11 ?? 1c 1f 64 9d 11 ?? 1d 1f 6f 9d 11 ?? 1e 1f 6d 9d 11 ?? 1f 09 1f 61 9d 11 ?? 1f 0a 1f 69 9d 11 ?? 1f 0b 1f 6e 9d 11 ?? 28 ?? 00 00 06 28 ?? 00 00 06 6f ?? 00 00 0a 72 7f 02 00 70 28 ?? 00 00 0a 2d 07 72 8b 02 00 70 2b 05 72 8f 02 00 70 a2 11 ?? 1f 18 }
        $seq6 = { 13 30 02 00 2d 00 00 00 ?? 00 00 11 00 72 ?? ?? 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 73 ?? 00 00 0a 0a 06 72 ?? ?? 00 70 6f ?? 00 00 0a 0b 07 6f ?? 00 00 0a }
        $seq7 = { 8d ?? 00 00 01 13 ?? 11 ?? 16 72 [2] 00 70 a2 11 ?? 17 [1-2] a2 11 ?? 18 72 [2] 00 70 a2 11 ?? 19 [2] a2 11 ?? 1a 72 [2] 00 70 a2 11 }
        $seq8 = { 12 ?? 28 ?? 00 00 06 0f 00 28 ?? 00 00 06 d0 ?? 00 00 1b 28 ?? 00 00 0a 28 ?? 00 00 0a a5 ?? 00 00 1b [1-2] 2b 00 [1-2] 2a }
        $seq9 = { 1f 10 8d ?? 00 00 01 13 ?? 11 ?? 16 1f 47 9d 11 ?? 17 1f 65 9d 11 ?? 18 1f 74 9d 11 ?? 19 1f 54 9d 11 ?? 1a 1f 68 9d 11 ?? 1b 1f 72 9d 11 ?? 1c 1f 65 9d 11 ?? 1d 1f 61 9d 11 ?? 1e 1f 64 9d 11 ?? 1f 09 1f 43 9d 11 ?? 1f 0a 1f 6f 9d 11 ?? 1f 0b 1f 6e 9d 11 ?? 1f 0c 1f 74 9d 11 ?? 1f 0d 1f 65 9d 11 ?? 1f 0e 1f 78 9d 11 ?? 1f 0f 1f 74 9d 11 ?? 28 97 00 00 06 28 09 00 00 2b 13 }
    condition:
        uint16(0) == 0x5a4d and filesize > 15KB and 3 of them
}