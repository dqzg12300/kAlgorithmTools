import sys
from PyQt5.QtWidgets import QMainWindow, QApplication

from common import Util
from kwindow.kmain import Ui_MainWindow


class kmainForm(QMainWindow,Ui_MainWindow):
    def __init__(self, parent=None):
        super(kmainForm,self).__init__(parent)
        self.setupUi(self)

    def base64_calc(self):
        base64_input = self.txtbase64_input.toPlainText()
        res=Util.kbase64(base64_input,self.rdobase64_encode.isChecked())
        self.txtbase64_output.setPlainText(res)

    def base64_input_change(self):
        base64_input = self.txtbase64_input.toPlainText()
        res = Util.kbase64(base64_input, self.rdobase64_encode.isChecked())
        self.txtbase64_output.setPlainText(res)

if __name__=="__main__":
    app=QApplication(sys.argv)
    kmain = kmainForm()
    kmain.show()
    sys.exit(app.exec_())