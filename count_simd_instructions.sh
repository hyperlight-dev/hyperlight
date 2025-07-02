#!/bin/bash

# Script to count SIMD instructions in an ELF binary
# Usage: ./count_simd_instructions.sh <binary_file>

if [ $# -eq 0 ]; then
    echo "Usage: $0 <binary_file>"
    exit 1
fi

BINARY="$1"

if [ ! -f "$BINARY" ]; then
    echo "Error: File '$BINARY' not found"
    exit 1
fi

echo "Analyzing SIMD instructions in: $BINARY"
echo "========================================"

# Disassemble the binary
DISASM=$(objdump -d "$BINARY" 2>/dev/null)

if [ $? -ne 0 ]; then
    echo "Error: Failed to disassemble binary. Make sure it's a valid ELF file."
    exit 1
fi

# Count different instruction sets
SSE_COUNT=$(echo "$DISASM" | grep -i -E "\b(movss|movsd|addss|addsd|subss|subsd|mulss|mulsd|divss|divsd|sqrtss|sqrtsd|maxss|maxsd|minss|minsd|cmpss|cmpsd|ucomiss|ucomisd|comiss|comisd)\b" | wc -l)

SSE2_COUNT=$(echo "$DISASM" | grep -i -E "\b(movdqa|movdqu|movq|movd|paddb|paddw|paddd|paddq|psubb|psubw|psubd|psubq|pmullw|pmuludq|pand|pandn|por|pxor|psllw|pslld|psllq|psrlw|psrld|psrlq|psraw|psrad|packsswb|packssdw|packuswb|punpckhbw|punpckhwd|punpckhdq|punpckhqdq|punpcklbw|punpcklwd|punpckldq|punpcklqdq|pcmpeqb|pcmpeqw|pcmpeqd|pcmpgtb|pcmpgtw|pcmpgtd|pmaxub|pmaxsw|pminub|pminsw|psadbw|pavgb|pavgw)\b" | wc -l)

SSE3_COUNT=$(echo "$DISASM" | grep -i -E "\b(addsubpd|addsubps|haddpd|haddps|hsubpd|hsubps|movddup|movshdup|movsldup|lddqu)\b" | wc -l)

SSSE3_COUNT=$(echo "$DISASM" | grep -i -E "\b(pabsb|pabsw|pabsd|palignr|phaddb|phaddw|phaddd|phaddsw|phsubb|phsubw|phsubd|phsubsw|pmaddubsw|pmulhrsw|pshufb|psignb|psignw|psignd)\b" | wc -l)

SSE41_COUNT=$(echo "$DISASM" | grep -i -E "\b(blendpd|blendps|blendvpd|blendvps|dppd|dpps|extractps|insertps|movntdqa|mpsadbw|packusdw|pblendvb|pblendw|pcmpeqq|pextrb|pextrd|pextrq|pextrw|phminposuw|pinsrb|pinsrd|pinsrq|pmaxsb|pmaxsd|pmaxud|pmaxuw|pminsb|pminsd|pminud|pminuw|pmovsxbw|pmovsxbd|pmovsxbq|pmovsxwd|pmovsxwq|pmovsxdq|pmovzxbw|pmovzxbd|pmovzxbq|pmovzxwd|pmovzxwq|pmovzxdq|pmuldq|pmulld|ptest|roundpd|roundps|roundsd|roundss)\b" | wc -l)

SSE42_COUNT=$(echo "$DISASM" | grep -i -E "\b(crc32|pcmpestri|pcmpestrm|pcmpistri|pcmpistrm|pcmpgtq)\b" | wc -l)

AVX_COUNT=$(echo "$DISASM" | grep -i -E "\bv(movss|movsd|addss|addsd|subss|subsd|mulss|mulsd|divss|divsd|sqrtss|sqrtsd|maxss|maxsd|minss|minsd|cmpss|cmpsd|ucomiss|ucomisd|comiss|comisd|movaps|movapd|movups|movupd|movlps|movlpd|movhps|movhpd|movlhps|movhlps|unpcklps|unpcklpd|unpckhps|unpckhpd|addps|addpd|subps|subpd|mulps|mulpd|divps|divpd|sqrtps|sqrtpd|maxps|maxpd|minps|minpd|cmpps|cmppd|andps|andpd|andnps|andnpd|orps|orpd|xorps|xorpd|shufps|shufpd|blendps|blendpd|blendvps|blendvpd|dpps|dppd|roundps|roundpd|roundss|roundsd|insertf128|extractf128|broadcast|permute|maskload|maskstore|testc|testz|testnzc)\b" | wc -l)

AVX2_COUNT=$(echo "$DISASM" | grep -i -E "\bv(pabs|padd|psub|pmul|pand|pandn|por|pxor|psll|psrl|psra|ppack|punpck|pcmp|pmax|pmin|psad|pavg|pblend|pbroadcast|perm|pgather|pinsert|pextract|pmovsx|pmovzx|psign|pshuf|palign|pmadd|pmaddubs|phsub|phadd)\b" | wc -l)

AVX512_COUNT=$(echo "$DISASM" | grep -i -E "\b(evex|zmm|k[0-7])\b|\bv.*\{.*\}\b" | wc -l)

echo "SSE instructions:     $SSE_COUNT"
echo "SSE2 instructions:    $SSE2_COUNT"
echo "SSE3 instructions:    $SSE3_COUNT"
echo "SSSE3 instructions:   $SSSE3_COUNT"
echo "SSE4.1 instructions:  $SSE41_COUNT"
echo "SSE4.2 instructions:  $SSE42_COUNT"  
echo "AVX instructions:     $AVX_COUNT"
echo "AVX2 instructions:    $AVX2_COUNT"
echo "AVX-512 instructions: $AVX512_COUNT"
echo "========================================"

TOTAL=$((SSE_COUNT + SSE2_COUNT + SSE3_COUNT + SSSE3_COUNT + SSE41_COUNT + SSE42_COUNT + AVX_COUNT + AVX2_COUNT + AVX512_COUNT))
echo "Total SIMD instructions: $TOTAL"
