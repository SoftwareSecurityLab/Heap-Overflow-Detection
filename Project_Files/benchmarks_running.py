#!/usr/bin/env python3

import argparse
import claripy,angr,monkeyhex
from source.analysis import CFGPartAnalysis
from source.constraintTree import _VTree
from source.VulAnalyzer import VulAnalyzer
	
import sys, os
sys.setrecursionlimit(2000)


for i in range(1, 91):
    print('===================')
    print("| Program No.: " + str(i))
    print('===================')
    proj=angr.Project('./samples/' + str(i),load_options={'auto_load_libs':False})
    angr.AnalysesHub.register_default('CFGPartAnalysis',CFGPartAnalysis)
    angr.AnalysesHub.register_default('VTree',_VTree)
    angr.AnalysesHub.register_default('VulAnalyzer',VulAnalyzer)
    cfg_an=proj.analyses.CFGPartAnalysis()
    an=proj.analyses.VulAnalyzer(cfg_an, False)
    u = an.propUnits()
	
    for unit in u:
        print("Test Unit : <{}>".format(unit))
        proj=angr.Project('./samples/' + str(i),load_options={'auto_load_libs':False})
        angr.AnalysesHub.register_default('CFGPartAnalysis',CFGPartAnalysis)
        angr.AnalysesHub.register_default('VTree',_VTree)
        angr.AnalysesHub.register_default('VulAnalyzer',VulAnalyzer)
        cfg_an=proj.analyses.CFGPartAnalysis()
        an=proj.analyses.VulAnalyzer(cfg_an, False)
        if i in [12, 14, 15, 31, 33, 35, 51, 53, 55, 87, 89, 90]:
            prototype = 'void ' + unit + '(char*, char*)'
            size = [0,100]
        else:
            prototype = 'void ' + unit + '(char*)'
            size = [100]
        an.analyze(prototype,args_index=[1],arg_sizes=size)
        print('\n\n')


