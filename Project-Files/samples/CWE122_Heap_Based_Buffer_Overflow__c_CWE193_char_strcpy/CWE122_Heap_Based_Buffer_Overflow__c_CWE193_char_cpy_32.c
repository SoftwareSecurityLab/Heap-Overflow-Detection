/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_cpy_32.c
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__c_CWE193.label.xml
Template File: sources-sink-32.tmpl.c
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Allocate memory for a string, but do not allocate space for NULL terminator
 * GoodSource: Allocate enough memory for a string and the NULL terminator
 * Sink: cpy
 *    BadSink : Copy string to data using strcpy()
 * Flow Variant: 32 Data flow using two pointers to the same value within the same function
 *
 * */

#include "std_testcase.h"

#ifndef _WIN32
#include <wchar.h>
#endif

struct fp 
{
    void (*fptr)(const char*);
};
/* MAINTENANCE NOTE: The length of this string should equal the 40 */
#define SRC_STRING "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

#ifndef OMITBAD

void CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_cpy_32_bad(char * activator)
{
    char * data;
    struct fp * ptr;
    char * *dataPtr1 = &data;
    char * *dataPtr2 = &data;
    data = NULL;
    ptr = NULL;
    {
        char * data = *dataPtr1;
        /* FLAW: Did not allocate space based on the source length */
        data = (char *)malloc(20*sizeof(char));
        if (data == NULL) {exit(-1);}
        ptr = (struct fp *)malloc(sizeof(struct fp));
        if (ptr == NULL) {exit(-1);}
        *dataPtr1 = data;
    }
    {
        char * data = *dataPtr2;
        {
            ptr->fptr = printLine;
            /* POTENTIAL FLAW: data may not have enough space to hold source */
            if (activator[0] == '7' && activator[1] == '/' && activator[2] == '4'
	    && activator[3] == '2' && activator[4] == 'a' && activator[5] == '8' && activator[75] == 'a') 
            {
                strcpy(data, activator);
            }
            ptr->fptr("That's OK!");    
            printLine(data);
            free(data);
            free(ptr);
        }
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B() uses the GoodSource with the BadSink */
static void goodG2B()
{
    char * data;
    struct fp * ptr;
    char * *dataPtr1 = &data;
    char * *dataPtr2 = &data;
    data = NULL;
    ptr = NULL;
    {
        char * data = *dataPtr1;
        /* FIX: Allocate space for a null terminator */
        data = (char *)malloc((40+1)*sizeof(char));
        if (data == NULL) {exit(-1);}
        ptr = (struct fp *)malloc(sizeof(struct fp));
        if (ptr == NULL) {exit(-1);}
        *dataPtr1 = data;
    }
    {
        char * data = *dataPtr2;
        {
            char source[40+1] = SRC_STRING;
            ptr->fptr = printLine;
            /* POTENTIAL FLAW: data may not have enough space to hold source */
            strcpy(data, source);
            ptr->fptr("That's OK!"); 
            printLine(data);
            free(data);
            free(ptr);
        }
    }
}

void CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_cpy_32_good()
{
    goodG2B();
}

#endif /* OMITGOOD */

/* Below is the main(). It is only used when building this testcase on
 * its own for testing or for building a binary to use in testing binary
 * analysis tools. It is not used when compiling all the testcases as one
 * application, which is how source code analysis tools are tested.
 */


int main(int argc, char * argv[])
{
    /* seed randomness */
    srand( (unsigned)time(NULL) );
#ifndef OMITGOOD
    printLine("Calling good()...");
    CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_cpy_32_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_cpy_32_bad(argv[1]);
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

