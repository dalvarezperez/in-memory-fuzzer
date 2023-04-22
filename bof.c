#include <stdio.h>

int bof(char *str)
{
   char buffer[24];
   strcpy(buffer, str);
   return 1;
}
int check_magic_value(char *str)
{
   char buffer[4];
   strcpy(buffer, str);
   return 1;
}

int main(int argc,char *argv[])
{
   char* str = argv[0];
   bof(str);
   if(strcmp(str),"magicvalue"){
   	   check_magic_value(str);
   }
}
