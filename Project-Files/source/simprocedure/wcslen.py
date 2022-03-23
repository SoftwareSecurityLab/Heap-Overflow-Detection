#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""

Created on Sat Feb 13 22:07:00 2021

@authors: Ali Kamali 
	  Sara Baradaran 
	  Mahdi Heidari

"""

import angr

class wcslen(angr.SimProcedure): 
    def run(self, s): 
        print('in wcslen')
        f=angr.SIM_PROCEDURES['libc']['strlen'] 
        self.state.globals['iswchar']=True
        re = self.inline_call(f,s,wchar=True).ret_expr 
        return re
