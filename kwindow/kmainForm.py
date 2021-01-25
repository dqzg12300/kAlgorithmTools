import datetime
import sys
from PyQt5.QtWidgets import QMainWindow, QApplication, QFileDialog

from common import Util
from kwindow.kmain import Ui_MainWindow
import urllib.parse
import platform
import os,re


class kmainForm(QMainWindow,Ui_MainWindow):

    def __init__(self, parent=None):
        super(kmainForm,self).__init__(parent)
        self.setupUi(self)
        self.setWindowOpacity(0.93)
        self.platform=platform.system()

    #base64的计算按钮事件
    def base64_calc(self):
        base64_input = self.txtbase64_input.toPlainText()
        res=Util.newBase64(self.txtbase64_key.text(),base64_input,self.rdobase64_encode.isChecked())
        # res=Util.kbase64(base64_input,self.rdobase64_encode.isChecked())
        self.txtbase64_output.setPlainText(res)
        if self.chkIsHex.isChecked():
            self.hex_toggled()

    #base64的输入框内容修改事件
    def base64_input_change(self):
        base64_input = self.txtbase64_input.toPlainText()
        res = Util.newBase64(self.txtbase64_key.text(),base64_input, self.rdobase64_encode.isChecked())
        # res = Util.kbase64(base64_input, self.rdobase64_encode.isChecked())
        self.txtbase64_output.setPlainText(res)
        if self.chkIsHex.isChecked():
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
        if self.chkIsHex.isChecked():
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
    def url_calc(self):
        input=self.txturl_input.toPlainText()
        if self.rdourl_encode.isChecked():
            self.txturl_output.setPlainText(urllib.parse.quote(input))
        else:
            self.txturl_output.setPlainText(urllib.parse.unquote(input))

    #url输入框修改的事件
    def url_input_change(self):
        self.url_calc()

    #安装环境
    def reinstall_android(self):
        Util.execScript("reinstall_android",self.platform)

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
        Util.execScriptPid("gdb32", self.platform,self.txtPid.text())

    # 启动gdb64 server脚本
    def start_gdb64(self):
        if len(self.txtPid.text())<=0:
            self.appendLog("未填写pid无法启动gdb。")
            return
        Util.execScriptPid("gdb64", self.platform,self.txtPid.text())
    #关掉调试的进程
    def kill_debug(self):
        Util.execScript("kill_debug", self.platform)

    #字符串转16进制和字节转字符串
    def binformat_calc(self):
        mystr=self.txtbinformat_input.toPlainText()
        if self.rdostr2hex.isChecked():
            try:
                res = Util.str2hex(mystr)
                self.txtbinformat_output.setPlainText(Util.b2hexSpace(res))
                cnt = len(res)
                self.lbbinformat_cnt.setText("<span style=' color:#ff0000;'>[{}]</span>".format(cnt))
            except Exception as ex:
                self.appendLog("转换异常:"+str(ex))
                return
        else:
            try:
                buff=Util.StrToHexSplit(mystr)
                res = Util.hex2str(buff)
                self.txtbinformat_output.setPlainText(res)
            except Exception as ex:
                self.appendLog("转换异常:"+str(ex))
                return

    def binformat_input_change(self):
        self.binformat_calc()

    def hexdump_calc(self):
        inputdata=self.txthexdump_input.toPlainText()
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

    def hexdump_input_change(self):
        self.hexdump_calc()

    def hexdump_cmb_change(self):
        self.hexdump_calc()

    #zlib的加密和解密
    def zlib_calc(self):
        inputdata=self.txtzlib_input.toPlainText()
        try:
            if self.rdozlib.isChecked():
                res=Util.zlib_compress(inputdata,self.chkzlib_ishex.isChecked())
            else:
                res = Util.zlib_decompress(inputdata)
        except:
            self.txtzlib_output.setPlainText("")
            return
        self.txtzlib_output.setPlainText(res)

    def zlib_input_change(self):
        self.zlib_calc()

    def varint_calc(self):
        inputdata=self.txtvarint_input.toPlainText()
        try:
            if "0x" in inputdata:
                inputdata=inputdata.replace("0x","")
                inputNum=int(inputdata,16)
                res = Util.varint_encode(inputNum)
                self.txtvarint_output.setPlainText(Util.b2hexSpace(res))
                return
            if " " in inputdata:
                buff=Util.StrToHexSplit(inputdata)
                res = Util.varint_decode(buff)
                self.txtvarint_output.setPlainText(str(res))
            else:
                inputNum = int(inputdata, 10)
                res = Util.varint_encode(inputNum)
                self.txtvarint_output.setPlainText(Util.b2hexSpace(res))
        except:
            self.txtvarint_output.setPlainText("")

    def varint_input_change(self):
        self.varint_calc()

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
            if self.platform=="Windows":
                res=Util.execProcess("../exec/win/protoc.exe","--decode_raw",data)
                self.txtprotoc_output.setPlainText(res.decode("utf-8"))
            else:
                res = Util.execProcess("../exec/linux/protoc", "--decode_raw", data)
                self.txtprotoc_output.setPlainText(res.decode("utf-8"))
        except:
            self.txtprotoc_output.setPlainText("")

    def protoc_input_change(self):
        self.protoc_calc()

if __name__=="__main__":
    app=QApplication(sys.argv)
    kmain = kmainForm()
    kmain.show()
    sys.exit(app.exec_())

