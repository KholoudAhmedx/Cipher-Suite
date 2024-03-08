using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        { 
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();

            string alphabets = "abcdefghijklmnopqrstuvwxyz";

            int[] alpaMappings = new int[26];
            char[] rankingAlpha = new char[26];

            for (int i = 0; i < alphabets.Length; i++)
            {
                alpaMappings[alphabets[i] - 'a'] = i;
                rankingAlpha[i] = alphabets[i];
            }

            StringBuilder analysedKey = new StringBuilder();

            int index = 0;
            for (int i = 0; i < cipherText.Length; i++)
            {
                int counter = alpaMappings[plainText[i] - 'a'];

                for (int j = 0; j < alphabets.Length; j++)
                {
                    if (alphabets[counter % 26] != cipherText[i])
                        counter++;
                    else
                    {
                        index = j;
                        break;
                    }
                }

                analysedKey.Append(rankingAlpha[index]);
            }

            int finalKeyIndex = 0;
            string allKey = analysedKey.ToString();
            string originalKey;
            originalKey = allKey.Substring(0, 3);

            for (int i = 3; i < allKey.Length; i++)
            {
                originalKey += allKey[i];
                int subStringIndex = allKey.IndexOf(originalKey, i);

                if (subStringIndex > i)
                {
                    if (finalKeyIndex == subStringIndex)
                        break;
                    else
                        finalKeyIndex = subStringIndex;
                }
            }

            return (allKey.Substring(0, finalKeyIndex));
        }


        public string Decrypt(string cipherText, string key)
        {
            
            cipherText = cipherText.ToLower();
            int size = cipherText.Length - key.Length;

            string alphabets = "abcdefghijklmnopqrstuvwxyz";

            int[] alphaMappings = new int[26];
            char[] rankingAlpha = new char[26];

            for (int i = 0; i < alphabets.Length; i++)
            {
                alphaMappings[alphabets[i] - 'a'] = i;
                rankingAlpha[i] = alphabets[i];
            }

            if (key.Length < cipherText.Length)
            {
                for (int i = 0; i < size; i++)
                    key += key[i];
            }

            StringBuilder decryptedText = new StringBuilder();

            for (int i = 0; i < cipherText.Length; i++)
            {
                int cipherIndex = alphaMappings[cipherText[i] - 'a'];
                int keyIndex = alphaMappings[key[i] - 'a'];
                int plainIndex = (cipherIndex - keyIndex + 26) % 26; 

                decryptedText.Append(rankingAlpha[plainIndex]);
            }

            return decryptedText.ToString();
        }

        public string Encrypt(string plainText, string key)
        {
            plainText = plainText.ToLower();
            int size = (plainText.Length - key.Length);

            string alphabets = "abcdefghijklmnopqrstuvwxyz";

            int[] alphaMappings = new int[26];
            char[] rankingAlpha = new char[26];

            for (int i = 0; i < alphabets.Length; i++)
            {
                alphaMappings[alphabets[i] - 'a'] = i;
                rankingAlpha[i] = alphabets[i];
            }

            if (key.Length < plainText.Length)
            {
                for (int i = 0; i < size; i++)
                {
                    key += key[i];
                }
            }

            StringBuilder encryptedText = new StringBuilder();
            int index = 0;
            for (int i = 0; i < plainText.Length; i++)
            {
                index = (alphaMappings[plainText[i] - 'a'] + alphaMappings[key[i] - 'a']) % 26;
                encryptedText.Append(rankingAlpha[index]);
            }

            return encryptedText.ToString().ToUpper();
        }
    }
}

