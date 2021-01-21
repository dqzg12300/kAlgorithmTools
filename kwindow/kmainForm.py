import datetime
import sys
from PyQt5.QtWidgets import QMainWindow, QApplication, QFileDialog

from common import Util
from kwindow.kmain import Ui_MainWindow
import urllib.parse
import platform
import os


class kmainForm(QMainWindow,Ui_MainWindow):

    def __init__(self, parent=None):
        super(kmainForm,self).__init__(parent)
        self.setupUi(self)
        self.setWindowOpacity(0.93)
        self.platform=platform.system()

    def base64_calc(self):
        base64_input = self.txtbase64_input.toPlainText()
        res=Util.newBase64(self.txtbase64_key.text(),base64_input,self.rdobase64_encode.isChecked())
        # res=Util.kbase64(base64_input,self.rdobase64_encode.isChecked())
        self.txtbase64_output.setPlainText(res)
        if self.chkIsHex.isChecked():
            self.hex_toggled()

    def base64_input_change(self):
        base64_input = self.txtbase64_input.toPlainText()
        res = Util.newBase64(self.txtbase64_key.text(),base64_input, self.rdobase64_encode.isChecked())
        # res = Util.kbase64(base64_input, self.rdobase64_encode.isChecked())
        self.txtbase64_output.setPlainText(res)
        if self.chkIsHex.isChecked():
            self.hex_toggled()


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

    def appendLog(self,logstr):
        datestr = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S   ')
        self.txtLog.appendPlainText(datestr+logstr)

    def url_calc(self):
        input=self.txturl_input.toPlainText()
        if self.rdourl_encode.isChecked():
            self.txturl_output.setPlainText(urllib.parse.quote(input))
        else:
            self.txturl_output.setPlainText(urllib.parse.unquote(input))

    def url_input_change(self):
        self.url_calc()

    def reinstall_android(self):
        mainpath=str(__file__)
        pathsplit= mainpath.split("kwindow")
        rootpath=pathsplit[0]
        if self.platform=="Windows":
            shellpath=rootpath+r"/script/bat/reinstall_android.bat"
        else:
            shellpath=rootpath+r"/script/shell/reinstall_android.sh"
        os.system("start "+shellpath)

if __name__=="__main__":
    app=QApplication(sys.argv)
    kmain = kmainForm()
    kmain.show()
    sys.exit(app.exec_())

