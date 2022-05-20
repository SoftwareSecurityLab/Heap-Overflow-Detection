Our Evaluation
------------
To reproduce the ressults of NIST SARD benchmarks, you can use the [`benchmarks_running.py`](https://github.com/SoftwareSecurityLab/Heap-Overflow-Detection/blob/main/Project_Files/benchmarks_running.py) file.

Running The Tests
------------
Note that our implemented tool uses x64 binary code for analyzing C programs. Compile benchmark programs using below command:
```
cd samples; chmod +x executable_generator.sh; ./executable_generator.sh
```
Run shellscript:
```
cd .. ; chmod +x benchmarks_running.py; ./benchmarks_running.py
```
