#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdbool.h>
#define def_user "admin"
#define def_pass "password"
// The function "signup" as a vulnerable unit
void signup(char *username, char *password)
{
    if((username[1] >= '0' && username[1] <= '9') && !strncmp(password, "passW0rd", 8))
    { 
        // FLAW: Did not allocate space based on the username length
        char *tmp_user = (char *)(malloc(50*sizeof(char)));
        // FLAW: Did not allocate space based on the password length
        char *tmp_pass = (char *)(malloc(50*sizeof(char)));
        /* POTENTIAL FLAW:
        data may not have enough space to hold source */
        memcpy(tmp_user, username, strlen(username));
        /* POTENTIAL FLAW:
        data may not have enough space to hold source */
        memcpy(tmp_pass, password, strlen(password));
        if(strlen(tmp_pass) < 12)
        {
            printf("The selected password is too weak\n");
            return;
        }
        int fd = open(tmp_user, O_WRONLY|O_CREAT, 0777);
        if(fd < 0)
        {
            printf("An unexpected problem occurred!\n"); 
            return;
        }
        write(fd,tmp_pass, sizeof(tmp_pass));
        printf("%s your registration was successful\n", tmp_user);
    }
    else if(!(username[1] >= '0' && username[1] <= '9'))
        printf("The second letter of username must be a number\n");
    else
        printf("The password must start with the word <passW0rd>\n");
}
// The function "check" as a vulnerable unit
bool check(char *username, char *password)
{
    // FLAW: Did not allocate space based on the username length
    char *tmp_user = (char *)(malloc(50*sizeof(char)));
    // FLAW: Did not allocate space based on the password length
    char *tmp_pass = (char *)(malloc(50*sizeof(char)));
    if((username[0] >= 'A' && username[0] <= 'Z') && (username[1] >= '0' && username[1] <= '9'))
    {
        /* POTENTIAL FLAW:
        data may not have enough space to hold source */	    
        strcpy(tmp_user, username);
        /* POTENTIAL FLAW:
        data may not have enough space to hold source */	    
        strcpy(tmp_pass, password);
        if(!strcmp(tmp_user, def_user) && !strcmp(tmp_pass, def_pass))
            return true;
        else
        {
            char passwd[50];
            int fd = open(tmp_user, O_RDONLY);
            if(fd < 0)
            {
                printf("An unexpected problem occurred!\n"); 
                return false;
            }
            read(fd, passwd, sizeof(passwd));
            if(!strcmp(passwd, tmp_pass))
                return true;
        }
    }
    return false;
}
// The function "signin" without any vulnerable statement
bool signin(char *username, char *password)
{
    if(check(username, password))
    {
        printf("%s you logged in successfully\n", username);
        return true;
    }
    else
    {
        printf("The username or password is wrong\n");
        return false;
    }
}
// The function "authentication" as a vulnerable unit
void authentication(char *username, char *password)
{
    // FLAW: Did not allocate space based on the username length
    char *tmp_user = (char *)(malloc(80*(sizeof(char))));
    // FLAW: Did not allocate space based on the password length
    char *tmp_pass = (char *)(malloc(80*(sizeof(char))));
    /* POTENTIAL FLAW:
    data may not have enough space to hold source */
    memcpy(tmp_user, username, strlen(username));
    /* POTENTIAL FLAW:
    data may not have enough space to hold source */
    memcpy(tmp_pass, password, strlen(password));
    int loginCnt = 0;
    for(; loginCnt < 3; loginCnt++)
    {
        bool signin_res = signin(tmp_user, tmp_pass);
        if(signin_res)
            break;
        printf("The username or password is invalid, try again :");
        printf("(%d from %d)\n",(loginCnt+1),3);
        printf("Enter username : ");
        scanf("%s",tmp_user);
        printf("Enter password : ");
        scanf("%s",tmp_pass);	
    }
	if(loginCnt == 3)
        printf("Please try later\n");
}
int main (int argc, char *argv[])
{
	char *username = (char *)(malloc(100*(sizeof(char))));
	char *password = (char *)(malloc(100*(sizeof(char))));
	if(argc >= 3)
        authentication(argv[1], argv[2]);
	else
	{
        printf("Register new user\n");
        printf("Enter username :");
        scanf("%s", username);
        printf("Enter password :");
        scanf("%s", password);
        if(username[0] >= 'A' && username[0] <= 'Z')
            signup(username, password);
        else
            printf("The selected username is not valid, it must start with an uppercase letter");
	}
}
