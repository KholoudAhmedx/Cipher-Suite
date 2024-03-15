using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            if (String.IsNullOrEmpty(cipherText) || String.IsNullOrEmpty(plainText)) { return 0; }
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();
            int Index1 = plainText.IndexOf(cipherText[1]);
            int Index2 = plainText.IndexOf(cipherText[2]);
            if (Index1 == (Index2 - Index1)) { return Index1; }
            else
            {
                Index1 = plainText.IndexOf(cipherText[1], plainText.IndexOf(cipherText[1]) + 1);
                if (Index1 == (Index2 - Index1)) { return Index1; }
                else
                {
                    Index2 = plainText.IndexOf(cipherText[2], plainText.IndexOf(cipherText[2]) + 1);
                    return Index2 - Index1;
                }
            }

        }

        public string Decrypt(string cipherText, int key)
        {
            //throw new NotImplementedException();
            if (String.IsNullOrEmpty(cipherText) || key == 0) { return null; }
            int column = cipherText.Length / key;
            if (cipherText.Length % key != 0) { column += 1; }
            char[,] MatrixPlain = new char[key, column];
            char[] PlainTextChar = new char[cipherText.Length];
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < column; j++)
                {
                    if ((j + (i * column)) > (cipherText.Length - 1)) { MatrixPlain[i, j] = '$'; }
                    else { MatrixPlain[i, j] = cipherText[(j + (i * column))]; }
                }
            }
            for (int j = 0; j < column * key; j+=key)
            {
                for (int i = 0; i < key; i++)
                {
                    if ((j + i) > (cipherText.Length - 1)) { break; }
                    else { PlainTextChar[j + i] = MatrixPlain[i, (j / key)]; }
                }
            }
            string PlainText = new string(PlainTextChar);
            return PlainText;
        }

        public string Encrypt(string plainText, int key)
        {
            //throw new NotImplementedException();
            if (String.IsNullOrEmpty(plainText) || key == 0) { return null; }
            int column = plainText.Length / key;
            if (plainText.Length % key != 0) { column += 1; }
            char[,] MatrixCipher = new char[key, column];
            char[] CipherTextChar = new char[plainText.Length];
            for (int j = 0; j < column * key; j += key)
            {
                if (column * key > plainText.Length)
                {
                    if ((j + key) >= (column * key))
                    {
                        for (int i = 0; i < key; i++)
                        {
                            if ((j + i) > (plainText.Length - 1)) { MatrixCipher[i, (j / key)] = '$'; }
                            else { MatrixCipher[i, (j / key)] = plainText[j + i]; }
                        }
                    }
                    else { for (int i = 0; i < key; i++) { MatrixCipher[i, (j / key)] = plainText[j + i]; } }
                }
                else { for (int i = 0; i < key; i++) { MatrixCipher[i, (j / key)] = plainText[j + i]; } }
            }
            int k = 0;
            for (int i = 0; i < key; i++)
            {
                if (column * key > plainText.Length)
                {
                    for (int j = 0; j < column; j++)
                    {
                        if (j == column - 1)
                        {
                            if (MatrixCipher[i, j] == '$') { k += 1; }
                            else { CipherTextChar[(j + (i * column)) - k] = MatrixCipher[i, j]; }
                        }
                        else { CipherTextChar[(j + (i * column)) - k] = MatrixCipher[i, j]; }
                    }
                }
                else { for (int j = 0; j < column; j++) { CipherTextChar[(j + (i * column)) - k] = MatrixCipher[i, j]; } }
            }
            string CipherText = new string(CipherTextChar);
            return CipherText;
        }
    }
}
