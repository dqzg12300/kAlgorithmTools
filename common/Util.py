import base64
import re,struct


def StrToHexSplit(input):
    buf = bytes(0)
    lines = re.split(r'[\r\n ]',input)
    for code in lines:
        if len (code) <= 0:
            continue

        num = int(code,16)
        bnum = struct.pack('B',num)
        buf += bnum
    return buf

def kbase64(input_data,isencode):
    if isencode:
        if type(input_data) is str:
            buff=input_data.encode("utf-8")
        elif type(input_data) is bytes:
            buff=input_data
        res = base64.b64encode(buff)
        return res.decode("utf-8")
    else:
        try:
            res = base64.b64decode(input_data.encode("utf-8"))  #res是2进制数据 如果不能utf-8显示。我们就直接显示16进制
            outdata=res.decode("utf-8")
        except Exception as ex:
            if "invalid continuation byte" in str(ex):
                outdata=""
                for mych in res:
                    outdata+="%02x"%mych+" "
                return outdata
            return ""
        return outdata

#密钥,加密的数据,编码还是解码,是否显示为16进制
def newBase64(bkey,input,isencode,ishex):
    if type(input) is str:
        buff = input.encode("utf-8")
    elif type(input) is bytes:
        buff = input
    if isencode:
        res = My_base64_encode(bkey, buff)
    else:
        try:
            res = My_base64_decode(bkey, input)
            outdata = res.decode("utf-8")
            return outdata
        except Exception as ex:
            if "invalid continuation byte" in str(ex):
                outdata=""
                for mych in res:
                    outdata+="%02x"%mych+" "
                return outdata
            return ""
    if ishex:
        outdata = ""
        for mych in res:
            outdata += "%02x" % mych + " "
        return outdata
    return res


def My_base64_encode(bkey,inputs):
    # 将字符串转化为2进制
    bin_str = []
    for i in inputs:
        x = str(bin(i)).replace('0b', '')
        bin_str.append('{:0>8}'.format(x))
    # print(bin_str)
    # 输出的字符串
    outputs = ""
    # 不够三倍数，需补齐的次数
    nums = 0
    while bin_str:
        # 每次取三个字符的二进制
        temp_list = bin_str[:3]
        if (len(temp_list) != 3):
            nums = 3 - len(temp_list)
            while len(temp_list) < 3:
                temp_list += ['0' * 8]
        temp_str = "".join(temp_list)
        # print(temp_str)
        # 将三个8字节的二进制转换为4个十进制
        temp_str_list = []
        for i in range(0, 4):
            temp_str_list.append(int(temp_str[i * 6:(i + 1) * 6], 2))
        # print(temp_str_list)
        if nums:
            temp_str_list = temp_str_list[0:4 - nums]

        for i in temp_str_list:
            outputs += bkey[i]
        bin_str = bin_str[3:]
    outputs += nums * '='
    return outputs


def My_base64_decode(bkey,inputs):
    # 将字符串转化为2进制
    bin_str = []
    for i in inputs:
        if i != '=':
            x = str(bin(bkey.index(i))).replace('0b', '')
            bin_str.append('{:0>6}'.format(x))
    # print(bin_str)
    # 输出的字符串
    outputs = bytes(0)
    nums = inputs.count('=')
    while bin_str:
        temp_list = bin_str[:4]
        temp_str = "".join(temp_list)
        # print(temp_str)
        # 补足8位字节
        if (len(temp_str) % 8 != 0):
            temp_str = temp_str[0:-1 * nums * 2]
        # 将四个6字节的二进制转换为三个字符
        for i in range(0, int(len(temp_str) / 8)):
            outputs += struct.pack("B",int(temp_str[i * 8:(i + 1) * 8], 2))
        bin_str = bin_str[4:]
    return outputs

def curtomBase64(bkey,input_bytes):
    output = bytes(0)
    cnt = len(input_bytes)
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



