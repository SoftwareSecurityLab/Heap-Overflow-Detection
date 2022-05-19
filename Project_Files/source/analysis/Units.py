#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""

Created on Mon Jul 13 16:59:10 2020

@authors: Ali Kamali 
	  Sara Baradaran 
	  Mahdi Heidari

"""


class Units:
    
    def __init__(self,valAnalysis):
        self._analysis=valAnalysis
        self._maps={}
        
        
    def getUnitForHeapBufferOverFlow(self):
        result=[]
        for addr , func in self._analysis.getCaller('malloc'):
            begin=func.startpoint.addr
            end=self._analysis.getEndPoint(func.name)
            
            malloc_pro=dict()
            for i in self._analysis.getRetStoreLocOnStackOfFunction('malloc',func.name):
                for addr,value in i.items():
                    if value is None: continue
                    malloc_pro[addr]=value
                        
            for addr,argcc in malloc_pro.items():
                if addr not in self._maps.keys():
                    self._maps[addr]=[(func.name,argcc)]
                    self._applyCopiesPositions(addr,func.name,argcc)
                        
                
            #TODO : check free is called in callee function or in functions called
            
            funcs=self._analysis.remvoeSTLFunctionInList(self._analysis.getFunctionCalledBetweenBoundry(func.name,begin,end))
            for f_addr,f_name in funcs:
                for callblock in self._analysis.getBlockOFFuctionCall(f_name,func.name):
                    new_malloc=self._refinedMallocFromMaps(func.name)
                    refined_malloc=self._getRefinedMallocProForFunc(callblock,func.name,new_malloc)
                    self._setUpMap(func.name,f_name,refined_malloc)

                            
             
            #here must be do it 
            for m_addr,props in malloc_pro.items():
                end_p=self._analysis.isMallocReterned(props[1].con.value,func)
                if end_p:
                    i=0
                    myTmpVar = [func.name]
                    while i < len(myTmpVar):
                        for func_Addr,c_func in self._analysis.getCaller(myTmpVar[i]):
                            caller_malloc_pro={}
                            value=tuple(self._analysis.getRetStoreLocOnStackOfFunction(myTmpVar[i], c_func.name)[0].values())
                            if value[0]:
                                myTmpVar.append(c_func.name)
                                caller_malloc_pro[m_addr]=[value[0]]
                                self._maps[m_addr].append((c_func.name,value[0]))
                                self._applyCopiesPositions(m_addr,c_func.name,value[0])

                                begin=c_func.startpoint.addr
                                end=self._analysis.getEndPoint(c_func.name)
                                funcs=self._analysis.remvoeSTLFunctionInList(self._analysis.getFunctionCalledBetweenBoundry(c_func.name,begin,end))
                                for f_addr,f_name in funcs:
                                    for callblock in self._analysis.getBlockOFFuctionCall(f_name,c_func.name):
                                        refined_malloc=self._getRefinedMallocProForFunc(callblock,c_func.name,caller_malloc_pro)
                                        self._setUpMap(c_func.name,f_name,refined_malloc)
                        i+=1

        for item in self._checkForWrits():
            if item not in result:    
                result.append(item) 
        return result
    
    
    
    def _applyCopiesPositions(self,addr,func_name,props):
        tmp_res={}
        for new_props in self._analysis.getAllCopiesSites(func_name,props[1].con.value):
            if addr not in tmp_res.keys():
                tmp_res[addr]=[]
            tmp_res[addr].append((func_name,new_props))

        for addr,wr_list in tmp_res.items():
            for item in wr_list:
                self._maps[addr].append(item)
                
                
    def _setUpMap(self,caller,callee_name,malloc_pro):
        #getting malloc addresses
        if len(malloc_pro) ==0 : 
            return malloc_pro
        
            
        call_chains=self._getCallChain(callee_name)
        for addr,argc in malloc_pro.items():
                for res in self._analysis._mapRegccInCalleeAndCaller(caller,callee_name,[argc]):
                    if len(res[1])>0 :
                        for tmp_res in res[1]:
                            if self._isINMap(addr,callee_name,tmp_res) == False:
                                self._maps[addr].append((callee_name,tmp_res))
                                self._applyCopiesPositions(addr,callee_name,tmp_res)
                        
        

        for chain in call_chains:
            chain_caller,chain_callee=chain
            for callblock in self._analysis.getBlockOFFuctionCall(chain_callee,chain_caller):
                    new_malloc=self._refinedMallocFromMaps(chain_caller)
                    refined_malloc=self._getRefinedMallocProForFunc(callblock,chain_caller,new_malloc)
                    for addr,argc in refined_malloc.items():
                        for res in self._analysis._mapRegccInCalleeAndCaller(chain_caller,chain_callee,[argc]):
                            if len(res[1])>0 :
                                for tmp_res in res[1]:
                                    if self._isINMap(addr,chain_callee,tmp_res) == False:
                                        self._maps[addr].append((chain_callee,tmp_res))
                                        self._applyCopiesPositions(addr,chain_callee,tmp_res)

    
    def _getRefinedMallocProForFunc(self,callblock,caller,old_malloc):
        new_malloc={}
        for addr , values in old_malloc.items():
            for value in values:
                if self._isValidAddress(callblock,caller,value):
                    new_malloc[addr]=value
        return new_malloc
    
    def _refinedMallocFromMaps(self,target_name):
        new_malloc={}
        for addr,argc in self.searchInMaps(target_name):
            if addr not in new_malloc.keys():
                new_malloc[addr]=[]
            new_malloc[addr].append(argc)
        return new_malloc
    
    
    def _checkForWrits(self):
        unit_list=list()
        for addr,items in self._maps.items():
            for func_name,argcc in items:
                if argcc[0] == 'static':
                    res=self._checkWriteForStatic(addr,func_name,argcc)
                    if len(res)>0:
                        unit_list.extend(res)
                else:
                    res=self._analysis.trackWriteIntoARGCCINCallee(func_name,argcc)
                    tmp_res=self._checkForDengrouseFunction(func_name,argcc)
                    for item in tmp_res:
                        if len(item)>0:
                            unit_list.append((addr,func_name,item))
                    if len(res)>0:
                        unit_list.append((addr,func_name,res))
        return unit_list
           

    def _checkWriteForStatic(self,m_addr,func_name,argcc):
        tp,mem_addr,begin=argcc
        unit_list=[]
        wr_res=self._analysis.trackWritesIntoStaticVars(func_name,mem_addr)
        if len(wr_res) > 0:
            unit_list.append((m_addr,func_name,wr_res))
        
        tmp_res=self._checkForDengrouseFunction(func_name,argcc)
        for item in tmp_res:
            if len(item)>0:
                unit_list.append((m_addr,func_name,item))
                
        end=self._analysis.getEndPoint(func_name)
        funcs=self._analysis.remvoeSTLFunctionInList(self._analysis.getFunctionCalledBetweenBoundry(func_name,begin,end))
        
        for begin_addr , func in self._analysis.getCaller(func_name):
            end_addr=end=self._analysis.getEndPoint(func.name)
            funcs.extend(self._analysis.remvoeSTLFunctionInList(self._analysis.getFunctionCalledBetweenBoundry(func.name,begin_addr,end_addr)))
            
        
        for f_addr,f_name in funcs:
            for new_props in self._analysis.getAllCopiesSites(f_name,argcc[1]):
                    self._maps[m_addr].append((f_name,new_props))    
        
        for f_addr,f_name in funcs:
            wr_res=self._analysis.trackWritesIntoStaticVars(f_name,mem_addr)
            if len(wr_res) > 0:
                unit_list.append((m_addr,f_name,wr_res))
            
            tmp_res=self._checkForDengrouseFunction(f_name,argcc)
            for item in tmp_res:
                if len(item)>0:
                    unit_list.append((m_addr,func_name,item))   
                
            
        return unit_list
    

    
    
    def  _isINMap(self,addr,callee_name,argc):
        target=self._maps[addr]
        for func_name,t_argc in target:
            if func_name == callee_name:
                if argc[0] == t_argc[0] and argc[1].con.value == t_argc[1].con.value and argc[2] == t_argc[2]:
                        return True
        return False
            
            
            
    def _checkForDengrouseFunction(self,caller,argcaller):
        dgrFunctions=['strcpy','strcat','memcpy','memset','memmove','sprintf']
        result=[]
        tmp_res=self._checkForStrFuncs('strcpy',caller,argcaller)
        if tmp_res is not None:
            result.extend(tmp_res)
            
        tmp_res=self._checkForStrFuncs('strcat',caller,argcaller)
        if tmp_res is not None:
            result.extend(tmp_res)
        
        tmp_res=self._checkForMEMStrFuncs('memcpy',caller,argcaller)
        if tmp_res is not None:
            result.extend(tmp_res)
            
        tmp_res=self._checkForMEMStrFuncs('memmove',caller,argcaller)
        if tmp_res is not None:
            result.extend(tmp_res)
        
        tmp_res=self._checkForMEMStrFuncs('memset',caller,argcaller)
        if tmp_res is not None:
            result.extend(tmp_res)
            
        tmp_res=self._checkForSprintf('sprintf',caller,argcaller)
        if tmp_res is not None:
            result.extend(tmp_res)
            
        return result
        
    
    
    def _checkForSprintf(self,func_name,caller,argcaller):
        func_callblock=self._analysis.getBlockOFFuctionCall(func_name,caller)
        if func_callblock is None:
            return 
        
        result=[]
        dst_argc=self._analysis.project.factory.cc().ARG_REGS[0]
        
        if argcaller[0] == 'static':
            for callblock in func_callblock:
                if self._analysis._isAddressLoadIntoReg(callblock.vex,argcaller[1],self._analysis.getRegOffset(callblock.vex,dst_argc)):
                    result.append((func_name,callblock.instruction_addrs[-1],'dst') )
        else:
            for callblock in func_callblock:
                for argc in self._analysis.getArgsCC(callblock.vex,self._analysis.getFuncAddress(func_name)):
                    if argc[1].con.value == argcaller[1].con.value and argc[0] == dst_argc:
                        result.append((func_name,callblock.instruction_addrs[-1],'dst') )
                    
        return result
    
    
    
    
    def _checkForMEMStrFuncs(self,func_name,caller,argcaller):
        func_callblock=self._analysis.getBlockOFFuctionCall(func_name,caller)
        if func_callblock is None:
            return 

        result=[]
        dst_argc=self._analysis.project.factory.cc().ARG_REGS[0]
        src_argc=self._analysis.project.factory.cc().ARG_REGS[1]
        len_argc=self._analysis.project.factory.cc().ARG_REGS[2]
        
        if argcaller[0] == 'static':
            for callblock in func_callblock:
                if self._analysis._isAddressLoadIntoReg(callblock.vex,argcaller[1],self._analysis.getRegOffset(callblock.vex,dst_argc)):
                    result.append((func_name,callblock.instruction_addrs[-1],'dst') )
                if self._analysis._isAddressLoadIntoReg(callblock.vex,argcaller[1],self._analysis.getRegOffset(callblock.vex,src_argc)):
                    result.append((func_name,callblock.instruction_addrs[-1],'src') )
                if self._analysis._isAddressLoadIntoReg(callblock.vex,argcaller[1],self._analysis.getRegOffset(callblock.vex,len_argc)):
                    result.append((func_name,callblock.instruction_addrs[-1],'copy_len') )
        else:
            for callblock in func_callblock:
                for argc in self._analysis.getArgsCC(callblock.vex,self._analysis.getFuncAddress(func_name)):
                    if argc[1].con.value == argcaller[1].con.value and argc[0] == dst_argc:
                        result.append((func_name,callblock.instruction_addrs[-1],'dst') )
                    if argc[1].con.value == argcaller[1].con.value and argc[0] == src_argc:
                        result.append((func_name,callblock.instruction_addrs[-1],'src') )
                    if argc[1].con.value == argcaller[1].con.value and argc[0] == len_argc:
                        result.append((func_name,callblock.instruction_addrs[-1],'copy_len') )
                    
        return result
    
    
    def _checkForStrFuncs(self,func_name,caller,argcaller):
        func_callblocks=self._analysis.getBlockOFFuctionCall(func_name,caller)
        if func_callblocks is None:
            return 
        
        result=[]
        dst_argc=self._analysis.project.factory.cc().ARG_REGS[0]
        src_argc=self._analysis.project.factory.cc().ARG_REGS[1]
        if argcaller[0] == 'static':
            for callblock in func_callblocks:
                if self._analysis._isAddressLoadIntoReg(callblock.vex,argcaller[1],self._analysis.getRegOffset(callblock.vex,dst_argc)):
                    result.append((func_name,callblock.instruction_addrs[-1],'dst') )
                if self._analysis._isAddressLoadIntoReg(callblock.vex,argcaller[1],self._analysis.getRegOffset(callblock.vex,src_argc)):
                    result.append((func_name,callblock.instruction_addrs[-1],'src') )
        else:
            for callblock in func_callblocks:
                for argc in self._analysis.getArgsCC(callblock.vex,self._analysis.getFuncAddress(func_name)):
                    if argc[1].con.value == argcaller[1].con.value and argc[0] == dst_argc:
                        result.append((func_name,callblock.instruction_addrs[-1],'dst') )
                    if argc[1].con.value == argcaller[1].con.value and argc[0] == src_argc:
                        result.append((func_name,callblock.instruction_addrs[-1],'src') )
        return result

    
            
    def _isValidAddress(self,callback,caller,value):
        callee=None
        if callback.vex.jumpkind == 'Ijk_Call':
            if len(callback.vex.constant_jump_targets) > 0:
                callee_addr=callback.vex.constant_jump_targets.copy().pop()
            else:
                callee_addr=self._analysis._tryToResolveJump(caller,callback.vex)
            if callee_addr:
                callee=self._analysis.resolveAddrByFunction(callee_addr).name
        if callee is None:
            raise ValueError('Not Valid Callblock')
        
        if self._analysis.targetValueCopyToArgCC(callback.vex,callee,value):
                return True
        return False
        
    def _getCallChain(self,caller):
        result=[]
        uncheckedList=[]

        
        while True:
            main_func=self._analysis.resolveAddrByFunction(self._analysis.getFuncAddress(caller))
            begin=main_func.startpoint.addr
            end=self._analysis.getEndPoint(caller)
            funcs=self._analysis.remvoeSTLFunctionInList(self._analysis.getFunctionCalledBetweenBoundry(caller,begin,end))
            
            for func in funcs:
                tmp_res=(caller,func[1])
                if tmp_res not in result:
                    result.append(tmp_res)
                    uncheckedList.append(func[1])
            
            if len(uncheckedList) == 0:
                break
            caller=uncheckedList.pop()
             
      
        return result
    
    
    def searchInMaps(self,target_name):
        res=[]
        for addr,items in self._maps.items():
            for name,_argcc in items:
                if _argcc[0] == 'static':continue
                if name==target_name:
                    res.append((addr,_argcc))
        return res

    
    
    
    def _checkIsWriteInTargetFunction(self,caller,malloc_pro,target_name=None,target_func=None):
        wr_points=[]
        if target_name is not None:
            if caller  == target_name:
                for addr ,argcc in malloc_pro.items(): 
                    tmp_wr=self._analysis.trackWriteIntoARGCCINCallee(caller,argcc)
                    if len(tmp_wr) > 0 :
                        #tmp_res=(target_name,tmp_wr,addr)
                        tmp_res=(addr,target_name,tmp_wr)
                        wr_points.append(tmp_res)
                
        else:            
                
            if target_func is not None:
                name=target_func[1]
            else:
                name=target_name
            
                    
            for begin ,items in malloc_pro.items(): 
                Addrs=self._analysis._mapAddrOfMallocInCallerAndCalle(name,caller,whole=True)
                for i in Addrs:
                    tmp_wr=self._analysis.trackWriteIntoARGCCINCallee(name,i)
                    if len(tmp_wr) > 0 :
                        tmp_res=(begin,name,tmp_wr)
                        wr_points.append(tmp_res)
                    
                    
    
        return wr_points
    
    
    def _getMallocPosOnArgs(self):
        malloc_args={}
        for addr,specs in self._maps.items():
            for func_name,props in specs:
                if props[0] == 'static': continue
                if func_name != 'main':
                    if 'rbp' not in props[0]:
                        if func_name not in malloc_args.keys():
                            malloc_args[func_name]={}
                            malloc_args[func_name][self._analysis.project.factory.cc().ARG_REGS.index(props[0])+1]=addr
                        else:
                            malloc_args[func_name][self._analysis.project.factory.cc().ARG_REGS.index(props[0])+1]=addr
        return malloc_args
