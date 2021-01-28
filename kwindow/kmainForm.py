import datetime
import sys

from Crypto.Cipher import ARC2
from PyQt5.QtWidgets import QMainWindow, QApplication, QFileDialog

from common import Util, AsmUtil, Enums, CryptoUtil
from kwindow.kmain import Ui_MainWindow
import urllib.parse
import platform
import os,re,zlib,hashlib,hmac


class kmainForm(QMainWindow,Ui_MainWindow):

    def __init__(self, parent=None):
        super(kmainForm,self).__init__(parent)
        self.setupUi(self)
        self.setWindowOpacity(0.93)
        self.platform=platform.system()
        if self.iswin()==False:
            os.system("chmod +x ../script/linux/*")
            os.system("chmod +x ../script/mac/*")
            os.system("chmod +x ../exec/linux/protoc")


    def iswin(self):
        return self.platform=="Windows"

    #base64的计算按钮事件
    def base64_calc_encode(self):
        base64_input = self.txtbase64_input.toPlainText()
        res=Util.newBase64(self.txtbase64_key.text(),base64_input,True)
        self.txtbase64_output.setPlainText(res)
        if self.chkHexOutput.isChecked():
            self.hex_toggled()

    def base64_calc_decode(self):
        base64_input = self.txtbase64_input.toPlainText()
        res = Util.newBase64(self.txtbase64_key.text(), base64_input, False)
        self.txtbase64_output.setPlainText(res)
        if self.chkHexOutput.isChecked():
            self.hex_toggled()

    #base64的选择文件进行编解码
    def select_file(self):
        filename= QFileDialog.getOpenFileName()[0]
        if len(filename)<=0:
            return
        self.txtbase64file.setText(filename)
        with open(filename,"rb") as myfile:
            mydata= myfile.read()
            res = Util.newBase64(self.txtbase64_key.text(),mydata, self.rdobase64_encode.isChecked())
            if self.chkIsHex.isChecked():
                outres = ""
                for mych in res:
                    outres += "%02x " % mych
                res = outres
            self.txtbase64_output.setPlainText(res)

    #base64的保存输出结果到文件
    def save_file(self):
        output=self.txtbase64_output.toPlainText()
        if len(output)<=2:
            self.appendLog("错误的输出结果.无法保存")
            return
        savefile= QFileDialog.getSaveFileName()[0]
        if len(savefile)<=0:
            self.appendLog("取消选择文件")
            return

        res=Util.StrToHexSplit(output)
        #开始保存
        with open(savefile,"wb") as myfile:
            myfile.write(res)
            self.appendLog("保存成功到:"+savefile)

    #base64结果是否显示为16进制
    def hex_toggled(self):
        output= self.txtbase64_output.toPlainText()
        if self.chkHexOutput.isChecked():
            outres = ""
            for mych in output:
                outres += "%02x " % ord(mych)
            output = outres
        else:
            outres = ""
            for mych in output.split(" "):
                if len(mych)<=0:
                    continue
                outres+=chr(int(mych,16))
            output = outres
        self.txtbase64_output.setPlainText(output)

    #打印输出日志
    def appendLog(self,logstr):
        datestr = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S   ')
        self.txtLog.appendPlainText(datestr+logstr)

    #url编解码
    def url_calc_encode(self):
        input=self.txturl_input.toPlainText()
        self.txturl_output.setPlainText(urllib.parse.quote(input))

    def url_calc_decode(self):
        input = self.txturl_input.toPlainText()
        self.txturl_output.setPlainText(urllib.parse.unquote(input))

    #安装环境
    def reinstall_android(self):
        if self.iswin():
            Util.execScript("reinstall_android",self.platform)
        else:
            rootpath=Util.getProjectPath()
            Util.execScriptReplace("reinstall_android",self.platform,"#path",rootpath)

    #启动frida脚本
    def start_frida32(self):
        Util.execScript("frida32", self.platform)

    #启动frida64脚本
    def start_frida64(self):
        Util.execScript("frida64", self.platform)

    # 启动ida32 server脚本
    def start_ida32(self):
        Util.execScript("ida32", self.platform)

    # 启动ida64 server脚本
    def start_ida64(self):
        Util.execScript("ida64", self.platform)

    # 启动gdb32 server脚本
    def start_gdb32(self):
        if len(self.txtPid.text())<=0:
            self.appendLog("未填写pid无法启动gdb。")
            return
        Util.execScriptReplace("gdb32", self.platform,"#pid",self.txtPid.text())

    # 启动gdb64 server脚本
    def start_gdb64(self):
        if len(self.txtPid.text())<=0:
            self.appendLog("未填写pid无法启动gdb。")
            return
        Util.execScriptReplace("gdb64", self.platform,"#pid",self.txtPid.text())
    #关掉调试的进程
    def kill_debug(self):
        Util.execScript("kill_debug", self.platform)

    #字符串转16进制和字节转字符串
    def binformat_calc_bytes(self):
        inputdata=self.txtbinformat_input.toPlainText()
        try:
            res = Util.str2hex(inputdata)
            self.txtbinformat_output.setPlainText(Util.b2hexSpace(res))
            cnt = len(res)
            self.lbbinformat_cnt.setText("<span style=' color:#ff0000;'>[{}]</span>".format(cnt))
        except Exception as ex:
            self.appendLog("转换异常:" + str(ex))
            return

    def binformat_calc_str(self):
        inputdata = self.txtbinformat_input.toPlainText()
        try:
            buff = Util.StrToHexSplit(inputdata)
            res = Util.hex2str(buff)
            self.txtbinformat_output.setPlainText(res)
        except Exception as ex:
            self.appendLog("转换异常:" + str(ex))
            return

    def binformat_input_change(self):
        self.binformat_calc()

    def hexdump_calc(self):
        inputdata=self.txthexdump_input.toPlainText()
        try:
            if "  " in inputdata:
                res=Util.HexdumpReplaceLeftRight(inputdata)
                self.txthexdump_output.setPlainText(res)
            else:
                res=Util.ByteToHexStr(inputdata)
                self.txthexdump_output.setPlainText(res)
            cmbidx=self.cmbhexdump.currentIndex()
            if cmbidx>=1 and cmbidx<=2:
                res=Util.hexSplit(self.txthexdump_output.toPlainText(),cmbidx)
                self.txthexdump_output.setPlainText(res)
        except:
            self.txthexdump_output.setPlainText("")

    def hexdump_input_change(self):
        self.hexdump_calc()

    def hexdump_cmb_change(self):
        self.hexdump_calc()

    #zlib的加密和解密
    def zlib_calc(self):
        inputdata=Util.getBuff(self.txtzlib_input.toPlainText(),self.chkzlib_ishex.isChecked())
        try:
            res=Util.zlib_compress(inputdata)
            self.txtzlib_output.setPlainText(res)
        except Exception as ex:
            self.appendLog(str(ex))
            self.txtzlib_output.setPlainText("")
            return

    def zlib_calc_unzlib(self):
        inputdata =Util.getBuff(self.txtzlib_input.toPlainText(),True)
        try:
            res = Util.zlib_decompress(inputdata)
            self.txtzlib_output.setPlainText(res)
        except Exception as ex:
            self.appendLog(str(ex))
            self.txtzlib_output.setPlainText("")
            return

    def varint_calc_encode(self):
        inputdata=self.txtvarint_input.toPlainText()
        try:
            if "0x" in inputdata:
                inputdata=inputdata.replace("0x","")
                inputNum=int(inputdata,16)
                res = Util.varint_encode(inputNum)
                self.txtvarint_output.setPlainText(Util.b2hexSpace(res))
                return
            else:
                inputNum = int(inputdata, 10)
                res = Util.varint_encode(inputNum)
                self.txtvarint_output.setPlainText(Util.b2hexSpace(res))
        except:
            self.txtvarint_output.setPlainText("")

    def varint_calc_decode(self):
        inputdata = self.txtvarint_input.toPlainText()
        if len(inputdata)<=0:
            self.appendLog("varint input为空")
            return
        if " " not in inputdata:
            inputdata=Util.ByteToHexStr(inputdata)
        buff = Util.StrToHexSplit(inputdata)
        res = Util.varint_decode(buff)
        self.txtvarint_output.setPlainText(str(res))


    #八进制转中文字符(Octal)  ####\345\276\256\344\277\241
    def oct_calc(self):
        inputdata=self.txtoct_input.toPlainText()
        try:
            nstr = eval("'{}'".format(inputdata))
            mybuff = bytes(0)
            for mychar in nstr:
                mybuff += bytes([ord(mychar)])
            res = mybuff.decode(encoding="utf-8")
            self.txtoct_output.setPlainText(res)
        except:
            self.txtoct_output.setText('')

    def oct_input_change(self):
        self.oct_calc()

    def protoc_calc(self):
        inputdata=self.txtprotoc_input.toPlainText()
        try:
            if "  " in inputdata:
                data=Util.HexdumpReplaceLeftRight(inputdata)
            elif " " not in inputdata:
                data = Util.ByteToHexStr(inputdata)
            data=Util.StrToHexSplit(data)
            if self.iswin():
                res=Util.execProcess("../exec/win/protoc.exe","--decode_raw",data)
                self.txtprotoc_output.setPlainText(res.decode("utf-8"))
            else:
                res = Util.execProcess("..\exec\linux\protoc", "--decode_raw", data)
                self.txtprotoc_output.setPlainText(res.decode("utf-8"))
        except:
            self.txtprotoc_output.setPlainText("")

    def protoc_input_change(self):
        self.protoc_calc()

    def asm_calc(self):
        inputdata = self.txtasm_input.toPlainText()
        try:
            outdata=""
            for data in inputdata.split("\n"):
                if len(data)<=0:
                    continue
                outdata+=AsmUtil.asm(self.cmbasm.currentIndex(),data)+"\n"
            self.txtasm_output.setPlainText(outdata)
        except Exception as ex:
            self.appendLog("解析异常.请检查数据和模式是否正确."+str(ex))
            self.txtasm_output.setPlainText("")

    def asm_calc_disasm(self):
        inputdata = self.txtasm_input.toPlainText()
        try:
            buff=Util.StrToHexSplit(inputdata)
            res=AsmUtil.disasm(self.cmbasm.currentIndex(),buff)
            self.txtasm_output.setPlainText(res)
        except Exception as ex:
            self.appendLog("解析异常.请检查数据和模式是否正确."+str(ex))
            self.txtasm_output.setPlainText("")

    def crc32_calc(self):
        buff=Util.getBuff(self.txtcrc32_input.toPlainText(),self.chkcrc32_ishex.isChecked())
        if len(buff) <= 0:
            self.appendLog("crc32 input未输入正确数据")
            return
        try:
            res=zlib.crc32(buff)
            self.txtcrc32_output.setPlainText(str(res))
        except:
            self.txtcrc32_output.setPlainText("")

    def crc32_input_change(self):
        self.crc32_calc()

    def adler32_calc(self):
        buff = Util.getBuff(self.txtadler32_input.toPlainText(),self.chkadler32_ishex.isChecked())
        if len(buff) <= 0:
            self.appendLog("adler32 input未输入正确数据")
            return
        try:
            res = zlib.adler32(buff)
            self.txtadler32_output.setPlainText(str(res))
        except:
            self.txtadler32_output.setPlainText("")

    def adler32_input_change(self):
        self.adler32_calc()

    def md5_calc(self):
        buff =Util.getBuff(self.txtmd5_input.toPlainText(),self.chkmd5_ishex.isChecked())
        if len(buff) <= 0:
            self.appendLog("md5 input未输入正确数据")
            return
        m= hashlib.md5()
        m.update(buff)
        res = m.hexdigest()
        self.txtmd5_output.setPlainText(res)

    def md5_input_change(self):
        self.md5_calc()

    def sha_calc(self):
        buff =Util.getBuff(self.txtsha_input.toPlainText(),self.chksha_ishex.isChecked())
        if len(buff) <= 0:
            self.appendLog("sha input未输入正确数据")
            return
        cmbidx=self.cmbsha.currentIndex()
        if cmbidx==1:
            m = hashlib.sha1()
        elif cmbidx==2:
            m = hashlib.sha224()
        elif cmbidx==3:
            m = hashlib.sha512()
        else:
            m = hashlib.sha256()
        m.update(buff)
        res = m.hexdigest()
        self.txtsha_output.setPlainText(res)

    def sha_input_change(self):
        self.sha_calc()

    def hmac_calc(self):
        buff = Util.getBuff(self.txthmac_input.toPlainText(),self.chkhmac_ishex.isChecked())
        if len(buff) <= 0:
            self.appendLog("hmac input未输入正确数据")
            return
        buff_key=Util.getBuff(self.txthmac_key.text(),self.chkhmac_key_ishex.isChecked())
        if self.chkhmac_key_ishex.isChecked():
            self.txthmac_key.setText(Util.b2hexSpace(buff_key))
        cmbidx = self.cmbhmac.currentIndex()
        if cmbidx == 1:
            m = hashlib.sha1
        elif cmbidx == 2:
            m = hashlib.sha224
        elif cmbidx == 3:
            m = hashlib.sha256
        elif cmbidx == 4:
            m = hashlib.sha512
        else:
            m = hashlib.md5
        h = hmac.new(buff_key,buff,digestmod=m)
        self.txthmac_output.setPlainText(h.hexdigest())

    def hmac_input_change(self):
        self.hmac_calc()

    #aes加密
    def aes_calc(self):
        buff=Util.getBuff(self.txtaes_input.toPlainText(),self.chkaes_ishex.isChecked())
        if len(buff)<=0:
            self.appendLog("aes input未输入正确数据")
            return
        buffkey=Util.getBuff(self.txtaes_key.text(),self.chkaes_key_ishex.isChecked())
        buffiv=Util.getBuff(self.txtaes_iv.text(),self.chkaes_iv_ishex.isChecked())
        try:
            if self.cmbaes_mode.currentIndex()==Enums.AES_MODE.CBC.value:
                res=CryptoUtil.aes_cbc_encrypt(buffkey,buffiv,buff)
                self.txtaes_output.setPlainText(Util.b2hex(res))
            elif self.cmbaes_mode.currentIndex()==Enums.AES_MODE.ECB.value:
                res=CryptoUtil.aes_ecb_encrypt(buffkey,buff)
                self.txtaes_output.setPlainText(Util.b2hex(res))
            elif self.cmbaes_mode.currentIndex()==Enums.AES_MODE.GCM.value:
                buff_nonce=Util.getBuff(self.txtaes_nonce.text(),self.chkaes_nonce_ishex.isChecked())
                res,tag=CryptoUtil.aes_gcm_encrypt(buffkey,buffiv,buff_nonce,buff)
                self.txtaes_tag.setText(Util.b2hex(tag))
                self.txtaes_output.setPlainText(Util.b2hex(res))
        except Exception as ex:
            print(ex)
            self.txtaes_output.setPlainText("")

    def aes_calc_decrypt(self):
        buff = Util.getBuff(self.txtaes_input.toPlainText(), True)
        if len(buff) <= 0:
            self.appendLog("aes input未输入正确数据")
            return
        buffkey = Util.getBuff(self.txtaes_key.text(), self.chkaes_key_ishex.isChecked())
        buffiv = Util.getBuff(self.txtaes_iv.text(), self.chkaes_iv_ishex.isChecked())
        try:
            if self.cmbaes_mode.currentIndex() == Enums.AES_MODE.CBC.value:
                res = CryptoUtil.aes_cbc_decrypt(buffkey, buffiv, buff)
                self.txtaes_output.setPlainText(Util.b2hex(res))
            elif self.cmbaes_mode.currentIndex() == Enums.AES_MODE.ECB.value:
                res = CryptoUtil.aes_ecb_decrypt(buffkey, buff)
                self.txtaes_output.setPlainText(Util.b2hex(res))
            elif self.cmbaes_mode.currentIndex() == Enums.AES_MODE.GCM.value:
                buff_nonce = Util.getBuff(self.txtaes_nonce.text(), self.chkaes_nonce_ishex.isChecked())
                bufftag = Util.getBuff(self.txtaes_tag.text(), self.chkaes_tag_ishex.isChecked())
                res = CryptoUtil.aes_gcm_decrypt(buffkey, buffiv, buff_nonce, buff, bufftag)
                self.txtaes_output.setPlainText(Util.b2hex(res))
        except Exception as ex:
            self.appendLog(str(ex))
            self.txtaes_output.setPlainText("")

    def aes_mode_change(self):
        if self.cmbaes_mode.currentIndex() == Enums.AES_MODE.GCM.value:
            self.txtaes_tag.setEnabled(True)
            self.txtaes_nonce.setEnabled(True)
        else:
            self.txtaes_tag.setEnabled(False)
            self.txtaes_nonce.setEnabled(False)

    def aes_input_change(self):
        self.aes_calc()

    def rc2_calc_encrypt(self):
        inputdata=Util.getBuff(self.txtrc2_input.toPlainText(),self.chkrc2_ishex.isChecked())
        if len(inputdata)<=0:
            self.appendLog("rc2 input为空")
            return
        try:
            buff_key=Util.getBuff(self.txtrc2_key.text(),self.chkrc2_key_ishex.isChecked())
            buff_iv = Util.getBuff(self.txtrc2_iv.text(), self.chkrc2_iv_ishex.isChecked())
            mode = ARC2.MODE_CBC
            if self.cmbrc2_mode.currentIndex()==1:
                res=CryptoUtil.rc2_ebc_encrypt(buff_key,inputdata)
            else:
                res = CryptoUtil.rc2_cbc_encrypt(buff_key,buff_iv,inputdata)
            self.txtrc2_output.setPlainText(Util.b2hex(res))
        except Exception as ex:
            self.appendLog(str(ex))


    def rc2_calc_decrypt(self):
        inputdata = Util.getBuff(self.txtrc2_input.toPlainText(), self.chkrc2_ishex.isChecked())
        if len(inputdata) <= 0:
            self.appendLog("rc2 input为空")
            return
        try:
            buff_key = Util.getBuff(self.txtrc2_key.text(), True)
            buff_iv = Util.getBuff(self.txtrc2_iv.text(), self.chkrc2_iv_ishex.isChecked())
            if self.cmbrc2_mode.currentIndex() == 1:
                res = CryptoUtil.rc2_ebc_decrypt(buff_key, inputdata)
            else:
                res = CryptoUtil.rc2_cbc_decrypt(buff_key, buff_iv, inputdata)
            self.txtrc2_output.setPlainText(res)
        except Exception as ex:
            self.appendLog(str(ex))

    def rsa_gen(self):
        pubkey,prikey=CryptoUtil.generateKey()
        self.txtrsa_pubkey.setPlainText(pubkey.decode("utf-8"))
        self.txtrsa_prikey.setPlainText(prikey.decode("utf-8"))

    def rsa_encrypt(self):
        res= CryptoUtil.rsa_encrypt(self.txtrsa_pubkey.toPlainText(),self.txtrsa_input.toPlainText())
        self.txtrsa_output.setPlainText(res.decode("utf-8"))
    def rsa_decrypt(self):
        res=CryptoUtil.rsa_decrypt(self.txtrsa_prikey.toPlainText(),self.txtrsa_input.toPlainText())
        self.txtrsa_output.setPlainText(res.decode("utf-8"))

    def des_calc_encrypt(self):
        pass

    def des_calc_decrypt(self):
        pass

if __name__=="__main__":
    app=QApplication(sys.argv)
    kmain = kmainForm()
    kmain.show()
    sys.exit(app.exec_())

