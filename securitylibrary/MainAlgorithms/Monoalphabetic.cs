using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            if(String.IsNullOrEmpty(cipherText) || String.IsNullOrEmpty(plainText)) { return null; }
            int CheckUpr = 0;
            if(char.IsUpper(plainText[0])) { CheckUpr = 1; }
            char[] KeyChar = new char[26];
            int[] ValidIndices = new int[plainText.Length];
            for(int i = 0; i < plainText.Length; i++)
            {
                int PlainIndex = char.ToUpper(plainText[i]) - 65;
                if(CheckUpr == 0) { KeyChar[PlainIndex] = char.ToLower(cipherText[i]); }
                else { KeyChar[PlainIndex] = char.ToUpper(cipherText[i]); }
                ValidIndices[i] = PlainIndex;
            }
            for(int i = 0; i < 26; i++)
            {
                bool contains = ValidIndices.Contains(i);
                if(!ValidIndices.Contains(i))
                {
                    for(int j = 0; j < 26; j++)
                    {
                        if(!KeyChar.Contains(char.ToLower(Convert.ToChar((j) + 65))) && !KeyChar.Contains(char.ToUpper(Convert.ToChar((j) + 65))))
                        {
                            if(CheckUpr == 0) { KeyChar[i] = char.ToLower(Convert.ToChar((j) + 65)); }
                            else { KeyChar[i] = char.ToUpper(Convert.ToChar((j) + 65)); }
                        }
                    }
                }
            }
            string Key = new string(KeyChar);
            return Key;
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            if(String.IsNullOrEmpty(cipherText) || String.IsNullOrEmpty(key)) { return null; }
            int CheckUpr = 0;
            if(char.IsUpper(key[0])) { CheckUpr = 1; }
            char[] PlainTextChar = new char[cipherText.Length];
            for(int i = 0; i < cipherText.Length; i++)
            {
                char CipherLetter = char.ToLower(cipherText[i]);
                if (CheckUpr == 1) { CipherLetter = char.ToUpper(cipherText[i]); }
                int KeyIndex = key.IndexOf(CipherLetter);
                PlainTextChar[i] = Convert.ToChar(KeyIndex + 65);
            }
            string PlainText = new string(PlainTextChar);
            return PlainText;
        }

        public string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }







        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	=
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        /// 

        public string AnalyseUsingCharFrequency(string cipher)
        {

            throw new NotImplementedException();


        }
    }
}
