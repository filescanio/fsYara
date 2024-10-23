// ref: https://harfanglab.io/insidethelab/reverse-engineering-ida-pro-aot-net/
import "pe"
rule NET_AOT {
    meta:
        description = "Detects .NET binaries compiled ahead of time (AOT)"
        author = "HarfangLab"
        distribution = "TLP:WHITE"
        version = "1.0"
        last_modified = "2024-01-08"
        hash = "5b922fc7e8d308a15631650549bdb00c"
        score = 50
    condition:
        pe.is_pe and pe.number_of_exports == 1 and
        pe.exports("DotNetRuntimeDebugHeader") and
        pe.section_index(".managed") >= 0
}