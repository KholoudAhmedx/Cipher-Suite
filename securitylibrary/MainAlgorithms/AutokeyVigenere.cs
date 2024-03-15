using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            // Convert both texts to lowercase
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();

            string alphabets = "abcdefghijklmnopqrstuvwxyz";
            int[] alpaMappings = new int[26];
            char[] rankingAlpha = new char[26];

            // Populate the arrays
            for (int i = 0; i < alphabets.Length; i++)
            {
                alpaMappings[alphabets[i] - 'a'] = i;
                rankingAlpha[i] = alphabets[i];
            }

            StringBuilder analysedKey = new StringBuilder();
            int index = 0;

            // Analyze the cipher text to extract the key
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

            string keystream = analysedKey.ToString();
            int counterr = 0;

            // Determine the length of the key
            for (int j = 0; j < keystream.Length; j++)
            {
                if (plainText[0] != keystream[j])
                {
                    counterr++;
                }
                else
                {
                    break;
                }
            }

            // Extract the key
            string rightkey = keystream.Substring(0, counterr);
            return rightkey;
        }



        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            key = key.ToLower();

            string alphabets = "abcdefghijklmnopqrstuvwxyz";

            int[] alphaMappings = new int[26];
            char[] rankingAlpha = new char[26];

            for (int i = 0; i < alphabets.Length; i++)
            {
                alphaMappings[alphabets[i] - 'a'] = i;
                rankingAlpha[i] = alphabets[i];
            }

            StringBuilder extendedKey = new StringBuilder(key);
            for (int i = 0; i < cipherText.Length - key.Length; i++)
            {
                char decryptedChar = DecryptChar(cipherText[i], extendedKey[i]);
                extendedKey.Append(decryptedChar);
            }

            StringBuilder decryptedText = new StringBuilder();

            for (int i = 0; i < cipherText.Length; i++)
            {
                int cipherIndex = alphaMappings[cipherText[i] - 'a'];
                int keyIndex = alphaMappings[extendedKey[i] - 'a'];
                int plainIndex = (cipherIndex - keyIndex + 26) % 26;

                decryptedText.Append(rankingAlpha[plainIndex]);
            }

            return decryptedText.ToString();
        }

        private char DecryptChar(char encryptedChar, char keyChar)
        {
            int diff = (encryptedChar - keyChar + 26) % 26;
            return (char)('a' + diff);
        }


        public string Encrypt(string plainText, string key)
        {
            plainText = plainText.ToLower();
            key = key.ToLower();

            string alphabets = "abcdefghijklmnopqrstuvwxyz";

            int[] alphaMappings = new int[26];
            char[] rankingAlpha = new char[26];

            for (int i = 0; i < alphabets.Length; i++)
            {
                alphaMappings[alphabets[i] - 'a'] = i;
                rankingAlpha[i] = alphabets[i];
            }

            StringBuilder extendedKey = new StringBuilder(key);
            for (int i = 0; i < plainText.Length - key.Length; i++)
            {
                extendedKey.Append(plainText[i]);
            }

            StringBuilder encryptedText = new StringBuilder();
            for (int i = 0; i < plainText.Length; i++)
            {
                int index = (alphaMappings[plainText[i] - 'a'] + alphaMappings[extendedKey[i] - 'a']) % 26;
                encryptedText.Append(rankingAlpha[index]);
            }

            return encryptedText.ToString().ToUpper();
        }

    }
}
