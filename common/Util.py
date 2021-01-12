import base64

def kbase64(input_data,isencode):
    if isencode:
        res = base64.b64encode(input_data.encode("utf-8"))
        return res.decode("utf-8")
    else:
        try:
            res = base64.b64decode(input_data.encode("utf-8"))
            outdata=res.decode("utf-8")
        except:
            return ""
        return outdata

def curtomBase64(bkey,input):
    input_bytes = bytes(input, "utf-8")
    output = ""
    cnt = len(input)
    precnt = cnt - 2
    cnt1 = cnt
    v6 = 0
    v7 = 0
    while True:
        if v7 >= precnt:
            break
        v9 = v7
        v6 += 4
        output += bkey[input_bytes[v7] >> 2]
        v10 = input_bytes[v7 + 1]
        v11 = input_bytes[v7]
        v7 += 3
        output += bkey[(v10 >> 4) & 0xFFFFFFCF | 16 * (v11 & 3)]
        output += bkey[((input_bytes[v9 + 2] >> 0x6) & 0xFFFFFFC3) | (4 * (input_bytes[v9 + 1] & 0xF))]
        output += bkey[input_bytes[v9 + 2] & 0x3F]
    if v7 < cnt1:
        output += bkey[input_bytes[v7] >> 2]
        v12 = 16 * input_bytes[v7] & 0x30
        if cnt1 - 1 == v7:
            v13 = '='
            output += bkey[v12]

        else:
            output += bkey[v12 | (input_bytes[v7 + 1] >> 4)]
            v13 = bkey[4 * (input_bytes[v7 + 1] & 0xF)]
        output += v13
        output += '='
    return output



