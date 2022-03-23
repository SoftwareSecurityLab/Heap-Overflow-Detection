# Heap-Overflow-Detection

This tool attempts to improve the efficiency of symbolic execution technique and use it to detect heap overflow vulnerability in binary programs. Instead of applying symbolic execution to the whole program, this tool initially determines a program test unit probably containing vulnerability using static analysis and based on the specification of heap overflow vulnerability. Then the constraint tree of the program unit is extracted using symbolic execution such that every node in this constraint tree contains the desired path and vulnerability constraints. Finally, using the curve fitting technique and treatment learning, the system inputs are estimated consistent with these constraints. Thus, new inputs are generated that reach the vulnerable instructions in the desired unit from the beginning of the program and cause heap overflow in those instructions.

Analysis Steps 
------------
* Static Analysis on x64 Binary Codes for Finding Possibly Vulnerable Units
* Symbolic Execution on Test Units
* Monte Carlo Simulation and Curve Fitting
* Detecting Heap Overflow Vulnerability and Generating Appropriate Inputs for Vulnerability Activation

## Requirements
- Python3
- angr Framework ([Installation](https://angr.io))

Get Started
------------
### Step 1: Creating Virtual Environment
Create and activate a virtual environment:
```
pip install virtualenv
virtualenv -p /usr/bin/python3 env
source env/bin/activate
```
### Step 2: Cloning Files to Use Heap Overflow Detection Tool
```
git clone https://github.com/SoftwareSecurityLab/Heap-Overflow-Detection
cd Heap-Overflow-Detection
```
### Step 3: Installing Requirements
Now install project requirements using `requirements.txt` file:
```
pip install -r requirements.txt
```
### Step 4: Testing Executable Code Using Heap Overflow Detection Tool
Everything is completed. Now you can test your desired code using our tool. We put some test cases from the NIST SARD benchmark vulnerable programs to this repository which you can use these test cases.
```
./run.py -b program -p 'void bad(char*)' -s 100 -a 1
```
We wish you happy testing!
## Known Issues


