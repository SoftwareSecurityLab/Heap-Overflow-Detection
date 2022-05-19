#!/usr/bin/env python3

import argparse
import claripy,angr,monkeyhex
from source.analysis import CFGPartAnalysis
from source.constraintTree import _VTree
from source.VulAnalyzer import VulAnalyzer
	
import sys, os
sys.setrecursionlimit(2000)


proj=angr.Project('./program', load_options={'auto_load_libs':False})
angr.AnalysesHub.register_default('CFGPartAnalysis',CFGPartAnalysis)
angr.AnalysesHub.register_default('VTree',_VTree)
angr.AnalysesHub.register_default('VulAnalyzer',VulAnalyzer)
cfg_an=proj.analyses.CFGPartAnalysis()
an=proj.analyses.VulAnalyzer(cfg_an, True)
u = an.propUnits()
	
for unit in u:
    print("Test Unit : <{}>".format(unit))
    proj=angr.Project('./program', load_options={'auto_load_libs':False})
    angr.AnalysesHub.register_default('CFGPartAnalysis',CFGPartAnalysis)
    angr.AnalysesHub.register_default('VTree',_VTree)
    angr.AnalysesHub.register_default('VulAnalyzer',VulAnalyzer)
    cfg_an=proj.analyses.CFGPartAnalysis()
    an=proj.analyses.VulAnalyzer(cfg_an, True)
    prototype = 'void ' + unit + '(char*, char*)'
    size = [100,100]
    if unit == 'check' or unit == 'authentication':
        index = [1,2]
    else:
        index = []
    an.analyze(prototype,args_index=index,arg_sizes=size)
    print('\n\n')


