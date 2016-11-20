# -*- coding: utf-8 -*-

"""
Module implementing table.
"""

from PyQt5.QtCore import pyqtSlot
from PyQt5.QtWidgets import QDialog

from .Ui_main import Ui_snifferUI


class table(QDialog, Ui_snifferUI):
    """
    Class documentation goes here.
    """
    def __init__(self, parent=None):
        """
        Constructor
        
        @param parent reference to the parent widget
        @type QWidget
        """
        super(table, self).__init__(parent)
        self.setupUi(self)
    
    @pyqtSlot(QTableWidgetItem*)
    def on_package_info_itemDoubleClicked(self, item):
        """
        Slot documentation goes here.
        
        @param item DESCRIPTION
        @type QTableWidgetItem*
        """
        # TODO: not implemented yet
        raise NotImplementedError
