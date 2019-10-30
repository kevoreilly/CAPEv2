# Written by @JamesHabben
# https://github.com/JamesHabben/MalwareStuff

# 2015-01-27 Slight modifications from Philippe Lagadec (PL) to use it from olevba

from __future__ import absolute_import
import sys

def DridexUrlDecode (inputText) :
    work = inputText[4:-4]
    strKeyEnc = StripCharsWithZero(work[(len(work) / 2) - 2: (len(work) / 2)])
    strKeySize = StripCharsWithZero(work[(len(work) / 2): (len(work) / 2) + 2])
    nCharSize = strKeySize - strKeyEnc
    work = work[:(len(work) / 2) - 2] + work[(len(work) / 2) + 2:]
    strKeyEnc2 = StripChars(work[(len(work) / 2) - (nCharSize/2): (len(work) / 2) + (nCharSize/2)])
    work = work[:(len(work) / 2) - (nCharSize/2)] + work[(len(work) / 2) + (nCharSize/2):]
    work_split = [work[i:i+nCharSize] for i in range(0, len(work), nCharSize)]
    decoded = ''
    for group in work_split:
        # sys.stdout.write(chr(StripChars(group)/strKeyEnc2))
        decoded += chr(StripChars(group)/strKeyEnc2)
    return decoded

def StripChars (input) :
    result = ''
    for c in input :
        if c.isdigit() :
            result += c
    return int(result)

def StripCharsWithZero (input) :
    result = ''
    for c in input :
        if c.isdigit() :
            result += c
        else:
            result += '0'
    return int(result)
