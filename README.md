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
sudo apt-get install virtualenv
virtualenv -p /usr/bin/python3 env
source env/bin/activate
```
### Step 2: Cloning Files to Use Heap Overflow Detection Tool
```
git clone https://github.com/SoftwareSecurityLab/Heap-Overflow-Detection
cd Heap-Overflow-Detection/
```
### Step 3: Installing Requirements
Now install project requirements using `requirements.txt` file:
```
pip install -r requirements.txt
```
Running The Tests
------------
Everything is completed. Now you can test your desired code using our tool. We put some test cases from the NIST SARD benchmark vulnerable programs to this repository which you can use these test cases.
### Options
```
-h or --help        HELP
-b or --binary      BINARY       [The Name of Binary File You Want to Analyze]
-p or --prototype   PROTOTYPE    [The Prototype of Test Unit You Want to Analyze]
-s or --sizes       SIZES        [The Size of Test Unit Arguments]
-a or --args        ARGS         [The Indexes of Argv Passed to The Test Unit As Function Arguments]
```
### Testing Executable Code Using Heap Overflow Detection Tool
You can see possibly vulnerable units in binary program which are need to be analyzed:
```
./run.py -b program
```
We wish you happy testing!😄
## Authors
* **Ali Kamali** - [alikmli](https://github.com/alikmli)
* **Sara Baradaran** - [SaraBaradaran](https://github.com/SaraBaradaran)
* **Mahdi Heidari** - [mheidari98](https://github.com/mheidari98/)
## License
This project is licensed under the Apache License 2.0 - see the [LICENSE.md](LICENSE.md) file for details


