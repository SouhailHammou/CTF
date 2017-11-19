/*
Souhail Hammou
HXP CTF 2017 - Fibonacci 100 pts
Writeup : 
*/
#include <stdio.h>
#include <stdlib.h>

#define _BYTE  unsigned char
#define BYTEn(x, n)   (*((_BYTE*)&(x)+n))
#define BYTE1(x)   BYTEn(x,  1)
unsigned int saved_res_for_v[264][2];
unsigned int v_index;

unsigned int fibonacci_solve(int number, _BYTE *pbool);
int main()
{
    unsigned int i,j;
    unsigned char barray[] = {0x49,0x7E,0x07,0xE2,0x9C,0xCC,0xC9,0x2B,0xFC,0x34,0x04,0x6F,0x4E,0x12,0x00,0x50,0xA9,0x02,0x3A,0xBA,0xC2,0x8E,0x41,0x99,0x98,0xF5,0x8D,0x51,0x4D,0xA6,0xC6,0x43,0x12};
    unsigned char flag_char;
    unsigned int counter = 0; //RBX
    for ( i = 0; i < sizeof(barray) ; i++)
    {
        flag_char = barray[i];
        for ( j = 0 ; j < 8 ; j++)
        {
            _BYTE b = 0;
            unsigned int fibo = fibonacci_solve(counter+j,&b);
            //save data for this value
            saved_res_for_v[counter+j][0] = b; //save bit
            saved_res_for_v[counter+j][1] = fibo; //save fibonacci result
            flag_char ^= b << j;
        }
        counter += 8;
        printf("%c",flag_char);
    }
}


unsigned int fibonacci_solve(int number, _BYTE *pbool)
{
  _BYTE *v2;
  unsigned int v3;
  unsigned int result;
  unsigned int v5;
  unsigned int v6;
  unsigned int v7;
  unsigned int xor_res;

  v2 = pbool;
  if ( number )
  {
    if ( number == 1 )
    {
      result = fibonacci_solve(0, pbool);
      v5 = result - ((result >> 1) & 0x55555555);
      v6 = ((result - ((result >> 1) & 0x55555555)) >> 2) & 0x33333333;
    }
    else
    {
      
      //if (number - 2) is saved
      if ( saved_res_for_v[number-2][1] != 0 )
      {
          //update b to reflect the value
          *pbool ^= saved_res_for_v[number-2][0];
          //don't recalculate, load the fibo value
          v3 = saved_res_for_v[number-2][1];
      }
      else
      {
          //calculate the value normally
          v3 = fibonacci_solve(number - 2, pbool);
      }

      //if number-1 is saved
      if ( saved_res_for_v[number-1][1] != 0 )
      {
          //update b to reflect the value
          *pbool ^= saved_res_for_v[number-1][0];
          //don't recalculate, load the fibo value
          result = v3 + saved_res_for_v[number-1][1];
      }
      else
      {
          //calculate the value normally
          result = v3 + fibonacci_solve(number - 1, pbool);
      }
      v5 = result - ((result >> 1) & 0x55555555);
      v6 = ((result - ((result >> 1) & 0x55555555)) >> 2) & 0x33333333;
    }
    v7 = v6 + (v5 & 0x33333333) + ((v6 + (v5 & 0x33333333)) >> 4);
    *v2 ^= ((BYTE1(v7) & 0xF) + (v7 & 0xF) + (unsigned __int8)((((v7 >> 8) & 0xF0F0F) + (v7 & 0xF0F0F0F)) >> 16)) & 1;
  }
  else
  {
    *pbool ^= 1u;
    result = 1;
  }
  return result;
}
