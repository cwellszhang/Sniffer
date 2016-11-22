# -*- coding: utf-8 -*-

"""
Module implementing temptable.py.
"""

from PyQt5.QtCore import pyqtSlot
from PyQt5.QtWidgets import QDialog

from .Ui_main import Ui_snifferUI


class temptable.py(QDialog, Ui_snifferUI):
    """
    Class documentation goes here.
    """
    def __init__(self, parent=None):
        """
        Constructor
        
        @param parent reference to the parent widget
        @type QWidget
        """
        super(temptable.py, self).__init__(parent)
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
    
    @pyqtSlot(int, int)
    def on_package_info_cellClicked(self, row, column):
        """
        Slot documentation goes here.
        
        @param row DESCRIPTION
        @type int
        @param column DESCRIPTION
        @type int
        """
        # TODO: not implemented yet
        raise NotImplementedError
    
    @pyqtSlot(int, int)
    def on_package_info_cellDoubleClicked(self, row, column):
        """
        Slot documentation goes here.
        
        @param row DESCRIPTION
        @type int
        @param column DESCRIPTION
        @type int
        """
        # TODO: not implemented yet
        raise NotImplementedError
