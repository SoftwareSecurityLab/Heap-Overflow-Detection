import angr,claripy

class ExeFunc(angr.SimProcedure):
    def run(*argv):
        pass
        #return claripy.BVS('UNConstrainRetValue',8)
