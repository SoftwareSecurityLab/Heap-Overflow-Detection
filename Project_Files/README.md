Our Evaluation
------------
To reproduce the ressults of NIST SARD benchmarks, you can use the [`benchmarks_running.py`](https://github.com/SoftwareSecurityLab/Heap-Overflow-Detection/blob/main/Project_Files/benchmarks_running.py) file.

### Analyzing NIST SARD Programs 
Note that our implemented tool uses x64 binary code for analyzing C programs. Compile benchmark programs using below command:
```
cd samples; chmod +x executable.sh; ./executable.sh
```
Run shellscript:
```
cd .. ; chmod +x benchmarks_running.py; ./benchmarks_running.py
```
### Analyzing A Designed Program
```
gcc ./samples/program.c -o program
```
Run shellscript:
```
chmod +x complex_program_running.py; ./complex_program_running.py
```
Known Issues
------------
It may you get the error: 

<i> PermissionError: [Errno 13] Permission denied: '~/Heap-Overflow-Detection/Project_Files/source/learning/./tar3/source/tar3/tar3' </i>

You can fix it by granting the execution permission to [`tar3`](https://github.com/SoftwareSecurityLab/Heap-Overflow-Detection/blob/main/Project_Files/source/learning/tar3/source/tar3/tar3) file.
