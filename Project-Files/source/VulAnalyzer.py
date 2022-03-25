#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Nov 30 22:47:00 2020

@author: ali
"""

from .MCSimulation import MCSimulation
from .simprocedure.ExtractParams import SimExtractParams
from .simprocedure.vul_strcpy import _strcpy_vul
from .learning.Tar3 import runTAR3,_correctInputs,_seperateValues
import angr,claripy,networkx as nx
from .analysis import Units 
from .learning import Cover
from .TypeUtils import *
import time


class VulAnalyzer(angr.Analysis):
    def __init__(self,cfg_an):
        self._tstart = time.time()
        self._cfgAnlyzer = cfg_an
        self._tree = self.project.analyses.VTree(self._cfgAnlyzer ) 

        
        
        self._unit_spec=Units(self._cfgAnlyzer)
        wrpoint_res=self._unit_spec.getUnitForHeapBufferOverFlow()
        self._malloc_args=self._unit_spec._getMallocPosOnArgs()
        if wrpoint_res is not None:
            self._wrpoints=wrpoint_res
            

            
    def propUnits(self):
        units=set()
        for addr,func,props in self._wrpoints:
            units.add(func)
        
        print('-'*80)
        reportVul("\Oops, You Didn't Specify The Unit Prototype. Use -p Option to Set The Desired Unit Prototye.")
        reportBold('-|Critical Units Are : ')
        for unit in units:
            reportBlue('-'*22+"|{}",unit)
            reportBlue('-'*25+"|{}","You Can Reach It Through This Chains :")
            for chain in self._cfgAnlyzer.getCallChain(unit):
                value=chain.replace('-' , '  \u2192 ')
                reportBlue('-'*30+"|{}",value)
        return units
        
        
    def analyze(self,unit_protoType,args_index=[],arg_sizes=[]):
        self._prototypes, self.unit=self._setUpFunctionPrototypes(unit_protoType)
        if self._cfgAnlyzer.isReachableFromMain(self.unit) == False:
            raise ValueError('Can\'t Reach The Target Unit ...')
        
        print('-'*80)
        reportBold('\nSteps')
        
        malloc_boundry=self.getMallocsBoundries()
        argStatus=self._prototypes[self.unit]
        wr_points=self._getWritePointAt(self.unit) 
        reportBlack('[1] Extracting Constraint Tree')
        self._tree.sefValsp(wr_points)
        self._tree.setMallocBoundry(malloc_boundry)
        mc=MCSimulation('NFACTOR_MC.cfg',nfactor=True)
        if len(args_index) > 0:
            argv={}
            for idx in args_index:
                size=mc.getVarTypes(idx-1)
                argv[idx]=int(size[1])
            self._tree.setupArgv(argv)
        
        if self._malloc_args and self.unit in self._malloc_args.keys():
            self._tree.setMallocArgs(self._malloc_args[self.unit])
        
        malloc_relativeAddr=self._unit_spec.searchInMaps(self.unit)
        self._tree.setUpMallocRelativeAddr(malloc_relativeAddr)
        pointer_idx,var=self._getBitVectorsAndPonterIdx(self.unit,malloc_boundry,arg_sizes)
        unit_func=self._cfgAnlyzer.resolveAddrByFunction(self._cfgAnlyzer.getFuncAddress(self.unit))
        st=time.time()
        self._tree.generateForCallable(unit_func,*var)
        ed=time.time()

        mallocArgsSz=self._getMallocSzForUnit(malloc_boundry,self.unit)
        

        
        reportBlack('[2] Applying Cover Algorithm')
        coverstartTime=time.time()
        self.cover=Cover(mc,self.project,self._cfgAnlyzer,self._tree,unit_func,unitArgsStatus=argStatus,mallocArgSz=mallocArgsSz)
        result=self.cover.cover(1,pointer_indexes=pointer_idx,args_index=args_index)
        coverendTime=time.time()
        
        
        
        
        self._tend = time.time()
        if result == -1:
            reportBold("\nCover Algorithm Did not Appplied")
        else :
            reportBold('\nCover Algorithm Takes {} Seconds to Finish'.format(round(coverendTime-coverstartTime)))
        reportBold('\nAnalysis Takes {} Seconds to Finish'.format(round(self._tend - self._tstart)))
        
        
        if len(self._tree._generetedVulConst)>0:
            reportBlack('\nGenerated Vulnerability Constraints : ')
            for inode,vul_const in self._tree._generetedVulConst.items():
                reportBlue('-| for node ' + str(inode) , ' ...  ' )
                reportVul('-'*20+'| {}',vul_const)
                
        reportBlack('\nTotal Generated Vulnerability Constraints : {}\n',self._tree._vulConstNumb )    
        
        if len(self._tree._vulReports)==0 and (result and (result == -1 or len(result) == 0)):
            reportBold("Analysis Doesn't Found Any Vulnerability")
            return result
        

        if len(self._tree._vulReports) > 0:
            reportBold('\n--|Dicovered Vulnerabilities in Functions with Concrete Arguments')
            for report in set(self._tree._vulReports):
                reportVul("---|{}",report)
            if result == -1 :
                return 
        
        
        if result and ( len(result) >0 or len(self.cover._unsats)>0):
            reportBold('Nodes Status :')
            
            nodes=list(self._tree._graph.nodes)
            if len(result) > 0 :
                for inode,inputs in result.items():
                    node=self._tree.getNodeByInode(inode)
                    if len(inputs) > 0:
                        reportBold('\n-|Node with Inode {} : \n ',inode)
                        
                        reportBold('Number of Constraints for This Node : {} ',len(node.constraints))
                        reportBold('Number of Vulnerability Constraints : {}\n',len(node._extra_vul_const))
                        
                        for msg in nodes[inode]._vulMsg:
                            reportVul('--|{}',msg)
                        reportBlack('\n\-|You Can Reach It with These Inputs : ')
                        for inp in inputs:
                            #reportVul('--|{}',open("Inputs/in{}.bin".format(inode), mode='rb').read())
                            reportVul('--|{}',inp)
                            
            if len(self.cover._unsats) > 0:
                reportBold('-|Unsat Nodes :')
                for msg,node_index in self.cover._unsats:
                    node=self._tree.getNodeByInode(node_index)
                    reportBlue('--|{}',msg)
                    reportBlue('----|Number of Constraints for This Node {} ',len(node.constraints))
                
        return result
                
       
                
    def getMallocsBoundries(self):
        result={}
        for addr , func in self._cfgAnlyzer.getAddressOfFunctionCall('malloc'):
            b=self._cfgAnlyzer.getBlockRelatedToAddr(addr) 
            sz=self._cfgAnlyzer.getMallocSize(b.vex,func.name)
            if sz:
                result[addr]=sz
                
        return result
    
    def _getBitVectorsAndPonterIdx(self,unit,malloc_boundry,arg_sizes):
        var=[]
        pointer_index=[]
        pointers=self._prototypes[unit]
        for numb,tp in pointers.items():
            var_name='var_{}'.format(numb)
            sz=None
            if tp == 'charPointer' or tp=='struct':
                sz=arg_sizes[numb-1]
            bit=getSymbolicBV(var_name,tp,size=sz)
            var.append(bit)
            pointer_index.append(numb-1)

        return (pointer_index,var)
        
    def _getWritePointAt(self,callee):
        result=[]
        for malloc_addr,func_name,wr_list in self._wrpoints:
            if func_name == callee:
                result.append((malloc_addr,wr_list))
                
        return result
        
            
    
    def _setUpFunctionPrototypes(self,protoType):
        pointers={}
        name=protoType[protoType.index(' '):protoType.index('(')]
        protoType=protoType.replace(name,' ')
        name=name.strip()
        tmp_res=angr.types.parse_type(protoType)
        pointers[name]={}
        numb=1
        for arg in  tmp_res.args:
            arg_name=str(arg)
            if '*' in arg_name:
                arg_name=arg_name.replace('*','Pointer')
            pointers.get(name)[numb]=arg_name
            numb=numb+1
        return pointers, name
    
    def _getMallocSzForUnit(self,malloc_boundry,unit):
        if self._malloc_args and unit in self._malloc_args:
            unitArgMallocSize=self._malloc_args[unit]
            res={}
            for arg_numb,m_addr in unitArgMallocSize.items():
                res[arg_numb]=malloc_boundry.get(m_addr)
            return res









 
