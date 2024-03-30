using System;
using System.Collections.Generic;
using System.Linq;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        Char[] alphabet = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
        public string Encrypt(string plainText, int key)
        {
            string new_plainText = plainText.ToUpper();
            string cipher = "";
            for(int i = 0; i < new_plainText.Length; i++)
            {
                for (int j = 0; j < alphabet.Length; j++)
                {
                    if (new_plainText[i]== alphabet[j])
                    {
                        cipher += alphabet[(j + key) % 26];
                    }
                }
                
            }
            return cipher;

        }

        public string Decrypt(string cipherText, int key)
        {
            Char[] alphabet = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
            string new_cipherText = cipherText.ToUpper();
            string plaintext = "";
            for (int i = 0; i < new_cipherText.Length; i++)
            {
                for(int j = 0; j< alphabet.Length; j++)
                {
                    if(new_cipherText[i]== alphabet[j])
                    {
                        plaintext += alphabet[((j - key)+ 26) % 26];
                    }
                }
            }


            return plaintext;
        }

        public int Analyse(string plainText, string cipherText)
        {
            int key = 0;
            plainText = plainText.ToUpper();
            cipherText = cipherText.ToUpper();
            int index_c = (int)cipherText[0] - 65;
            int index_p = (int)plainText[0] - 65;
            key = (index_c - index_p) % 26;
            if (key >= 0)
                return key;
            else
                return key + 26;
            //yarab akon sah
        }
    }
}