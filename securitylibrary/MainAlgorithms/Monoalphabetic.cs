
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            
            if (String.IsNullOrEmpty(cipherText) || String.IsNullOrEmpty(plainText)) 
                return null; 

            int CheckUpr = 0;
            if (char.IsUpper(plainText[0])) { CheckUpr = 1; }
            char[] KeyChar = new char[26];
            int[] ValidIndices = new int[plainText.Length];
            for (int i = 0; i < plainText.Length; i++)
            {
                int PlainIndex = char.ToUpper(plainText[i]) - 65;
                if (CheckUpr == 0) { KeyChar[PlainIndex] = char.ToLower(cipherText[i]); }
                else { KeyChar[PlainIndex] = char.ToUpper(cipherText[i]); }
                ValidIndices[i] = PlainIndex;
            }
            for (int i = 0; i < 26; i++)
            {
                bool contains = ValidIndices.Contains(i);
                if (!ValidIndices.Contains(i))
                {
                    for (int j = 0; j < 26; j++)
                    {
                        if (!KeyChar.Contains(char.ToLower(Convert.ToChar((j) + 65))) && !KeyChar.Contains(char.ToUpper(Convert.ToChar((j) + 65))))
                        {
                            if (CheckUpr == 0) { KeyChar[i] = char.ToLower(Convert.ToChar((j) + 65)); }
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
            if (String.IsNullOrEmpty(cipherText) || String.IsNullOrEmpty(key))
                return null;
            

            string alphabet = "abcdefghijklmnopqrstuvwxyz";
            Dictionary<char, char> decryptionMap = new Dictionary<char, char>();

            for (int i = 0; i < alphabet.Length; i++)
            {
                decryptionMap[key[i]] = alphabet[i];
            }

            cipherText = cipherText.ToLower();

            StringBuilder pT = new StringBuilder();
            foreach (char c in cipherText)
            {
                if (decryptionMap.ContainsKey(c))
                {
                    pT.Append(decryptionMap[c]);
                }
                else
                {
                    pT.Append(c);
                }
            }

            return pT.ToString();
        }

        public string Encrypt(string plainText, string key)
        {
            if (string.IsNullOrEmpty(plainText) || string.IsNullOrEmpty(key))
                return null;

            string alphabet = "abcdefghijklmnopqrstuvwxyz";
            Dictionary<char, char> encryptionM = new Dictionary<char, char>();

            for (int i = 0; i < alphabet.Length; i++)
            {
                encryptionM[alphabet[i]] = key[i];
            }

            StringBuilder cipherText = new StringBuilder();
            foreach (char c in plainText.ToLower())
            {
                if (encryptionM.ContainsKey(c))
                    cipherText.Append(encryptionM[c]);
                else
                    cipherText.Append(c);
            }

            return cipherText.ToString();
        }

        public string AnalyseUsingCharFrequency(string cipher)
        {
            if (String.IsNullOrEmpty(cipher))
                return null;
            
            else
            {
                Dictionary<char, int> freqMap = new Dictionary<char, int>();
                cipher = cipher.ToLower();
                foreach (char c in cipher)
                {
                    if (char.IsLetter(c))
                    {
                        if (freqMap.ContainsKey(c))
                            freqMap[c]++;
                        else
                            freqMap[c] = 1;
                    }
                }

                var freq = from entry in freqMap orderby entry.Value descending select entry;

                string freqLetters = "etaoinsrhldcumfpgwybvkxjqz";
                string alphabet = "abcdefghijklmnopqrstuvwxyz";

                Dictionary<char, char> mapping = new Dictionary<char, char>();
                StringBuilder newKey = new StringBuilder();
                foreach (var entry in freq)
                {
                    newKey.Append(entry.Key);
                }

                for (int i = 0; i < Math.Min(freqLetters.Length, newKey.Length); i++)
                {
                    mapping[freqLetters[i]] = newKey[i];
                }

                StringBuilder keyHere = new StringBuilder();
                foreach (char c in alphabet)
                {
                    if (mapping.ContainsKey(c))
                        keyHere.Append(mapping[c]);
                    else
                        keyHere.Append(c);
                }

                Monoalphabetic monoalphabetic = new Monoalphabetic();
                return monoalphabetic.Decrypt(cipher, keyHere.ToString());
            }
        }
    }
}
