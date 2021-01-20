import datetime
import sys
from PyQt5.QtWidgets import QMainWindow, QApplication, QFileDialog

from common import Util
from kwindow.kmain import Ui_MainWindow


class kmainForm(QMainWindow,Ui_MainWindow):
    def __init__(self, parent=None):
        super(kmainForm,self).__init__(parent)
        self.setupUi(self)

    def base64_calc(self):
        base64_input = self.txtbase64_input.toPlainText()
        res=Util.newBase64(self.txtbase64_key.text(),base64_input,self.rdobase64_encode.isChecked(),self.chkIsHex.isChecked())
        # res=Util.kbase64(base64_input,self.rdobase64_encode.isChecked())
        self.txtbase64_output.setPlainText(res)

    def base64_input_change(self):
        base64_input = self.txtbase64_input.toPlainText()
        res = Util.newBase64(self.txtbase64_key.text(),base64_input, self.rdobase64_encode.isChecked(),self.chkIsHex.isChecked())
        # res = Util.kbase64(base64_input, self.rdobase64_encode.isChecked())
        self.txtbase64_output.setPlainText(res)

    def select_file(self):
        filename= QFileDialog.getOpenFileName()[0]
        if len(filename)<=0:
            return
        self.txtbase64file.setText(filename)
        with open(filename,"rb") as myfile:
            mydata= myfile.read()
            res = Util.newBase64(self.txtbase64_key.text(),mydata, self.rdobase64_encode.isChecked(),self.chkIsHex.isChecked())
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

    def appendLog(self,logstr):
        datestr = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S   ')
        self.txtLog.appendPlainText(datestr+logstr)

if __name__=="__main__":
    app=QApplication(sys.argv)
    kmain = kmainForm()
    kmain.show()
    sys.exit(app.exec_())

