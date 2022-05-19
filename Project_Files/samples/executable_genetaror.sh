#!/bin/bash

cp includes/std_testcase.h CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_strcpy
cp includes/std_testcase_io.h CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_strcpy
cp includes/testcases.h CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_strcpy

k=1
for ((i = 1; i <= 44; i++ ));
do
	FILE="CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_strcpy/CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_cpy_$(printf "%02d" $i).c"
	if [ -f $FILE ]; then
		gcc $FILE includes/io.c -o $k
		k=$((k+1))
	fi
done
gcc CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_strcpy/CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_cpy_67a.c CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_strcpy/CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_cpy_67b.c includes/io.c -o $k

k=$((k+1))

rm CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_strcpy/std_testcase.h
rm CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_strcpy/std_testcase_io.h
rm CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_strcpy/testcases.h 

cp includes/std_testcase.h CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memcpy
cp includes/std_testcase_io.h CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memcpy
cp includes/testcases.h CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memcpy

for ((i = 1; i <= 45; i++ ));
do
        FILE="CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memcpy/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memcpy_$(printf "%02d" $i).c"
        if [ -f $FILE ]; then
                gcc $FILE includes/io.c -o $k
                k=$((k+1))
        fi
done

gcc CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memcpy/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memcpy_67a.c CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memcpy/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memcpy_67b.c includes/io.c -o $k

k=$((k+1))

rm CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memcpy/std_testcase.h
rm CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memcpy/std_testcase_io.h
rm CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memcpy/testcases.h

cp includes/std_testcase.h CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove
cp includes/std_testcase_io.h CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove
cp includes/testcases.h CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove

for ((i = 1; i <= 45; i++ ));
do
        FILE="CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove_$(printf "%02d" $i).c"
        if [ -f $FILE ]; then
                gcc $FILE includes/io.c -o $k
                k=$((k+1))
        fi
done

gcc CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove_67a.c CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove_67b.c includes/io.c -o $k

k=$((k+1))

rm CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove/std_testcase.h
rm CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove/std_testcase_io.h
rm CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove/testcases.h

cp includes/std_testcase.h CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memcpy
cp includes/std_testcase_io.h CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memcpy
cp includes/testcases.h CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memcpy

for ((i = 1; i <= 45; i++ ));
do
        FILE="CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memcpy/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memcpy_$(printf "%02d" $i).c"
        if [ -f $FILE ]; then
                gcc $FILE includes/io.c -o $k
                k=$((k+1))
        fi
done

rm CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memcpy/std_testcase.h
rm CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memcpy/std_testcase_io.h
rm CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memcpy/testcases.h

cp includes/std_testcase.h CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memmove
cp includes/std_testcase_io.h CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memmove
cp includes/testcases.h CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memmove

for ((i = 1; i <= 45; i++ ));
do
        FILE="CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memmove/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memmove_$(printf "%02d" $i).c"
        if [ -f $FILE ]; then
                gcc $FILE includes/io.c -o $k
                k=$((k+1))
        fi
done

rm CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memmove/std_testcase.h
rm CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memmove/std_testcase_io.h
rm CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memmove/testcases.h

cp includes/std_testcase.h CWE122_Heap_Based_Buffer_Overflow__c_dest_char_strcat
cp includes/std_testcase_io.h CWE122_Heap_Based_Buffer_Overflow__c_dest_char_strcat
cp includes/testcases.h CWE122_Heap_Based_Buffer_Overflow__c_dest_char_strcat

for ((i = 1; i <= 44; i++ ));
do
        FILE="CWE122_Heap_Based_Buffer_Overflow__c_dest_char_strcat/CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cat_$(printf "%02d" $i).c"
        if [ -f $FILE ]; then
                gcc $FILE includes/io.c -o $k
                k=$((k+1))
        fi
done

gcc CWE122_Heap_Based_Buffer_Overflow__c_dest_char_strcat/CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cat_67a.c CWE122_Heap_Based_Buffer_Overflow__c_dest_char_strcat/CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cat_67b.c includes/io.c -o $k

k=$((k+1))

rm CWE122_Heap_Based_Buffer_Overflow__c_dest_char_strcat/std_testcase.h
rm CWE122_Heap_Based_Buffer_Overflow__c_dest_char_strcat/std_testcase_io.h
rm CWE122_Heap_Based_Buffer_Overflow__c_dest_char_strcat/testcases.h

