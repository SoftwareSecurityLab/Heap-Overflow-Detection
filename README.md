# Heap-Overflow-Detection

This tool attempts to improve the efficiency of the symbolic execution technique and use it to discover heap overflow vulnerabilities in binary programs. Instead of applying symbolic execution to the whole program, this tool initially determines a unit of the program probably containing vulnerability using static analysis based on the specification of heap overflow vulnerability. Then the constraint tree of the program unit is extracted using symbolic execution such that every constraint tree node contains the desired path and vulnerability constraints. Finally, using the curve fitting technique and treatment learning, the system inputs are estimated proportional to these constraints. Thus, new inputs are generated that reach the vulnerable instructions in the desired unit from the beginning of the program and cause heap overflow in that instructions.

Analysis Steps 
------------
* Static Analysis on x64 Binary Codes for Finding Possibly Vulnerable Units
* Symbolic Execution on Test Units
* Monte Carlo Simulation and Curve Fitting
* Discovering Heap Overflow Vulnerability and Generating Proper Inputs for Vulnerability Activation

## Requirements
- Python3
- angr Framework ([Installation](https://angr.io))

Get Started
------------


## Known Issues


