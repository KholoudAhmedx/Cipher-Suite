using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        int[,] pc1 =
{
    {57, 49, 41, 33, 25, 17, 9},
    {1, 58, 50, 42, 34, 26, 18},
    {10, 2, 59, 51, 43, 35, 27},
    {19, 11, 3, 60, 52, 44, 36},
    {63, 55, 47, 39, 31, 23, 15},
    {7, 62, 54, 46, 38, 30, 22},
    {14, 6, 61, 53, 45, 37, 29},
    {21, 13, 5, 28, 20, 12, 4}
};
        int[,] pc2 =
        {
    {14, 17, 11, 24, 1, 5},
    {3, 28, 15, 6, 21, 10},
    {23, 19, 12, 4, 26, 8},
    {16, 7, 27, 20, 13, 2},
    {41, 52, 31, 37, 47, 55},
    {30, 40, 51, 45, 33, 48},
    {44, 49, 39, 56, 34, 53},
    {46, 42, 50, 36, 29, 32}
};
        int[,] ip =
        {
    {58,50,42,34,26,18,10,2},
    {60,52,44,36,28,20,12,4},
    {62,54,46,38,30,22,14,6},
    {64,56,48,40,32,24,16,8},
    {57,49,41,33,25,17,9,1},
    {59,51,43,35,27,19,11,3},
    {61,53,45,37,29,21,13,5},
    {63,55,47,39,31,23,15,7}
};
        int[,] s1 = {
            {14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7},
            { 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8},
            { 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
            {15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13}
        };
        int[,] s2 = {
            {15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10},
            { 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
            { 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
            {13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9}
        };
        int[,] s3 = {
            {10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8},
            {13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1},
            {13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7},
            { 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12}
        };
        int[,] s4 = {
            { 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15},
            {13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9},
            {10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4},
            { 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14}
        };
        int[,] s5 = {
            { 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9},
            {14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6},
            { 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14},
            {11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3}
        };
        int[,] s6 = {
            {12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11},
            {10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8},
            { 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6},
            { 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13}
        };
        int[,] s7 = {
            { 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1},
            {13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6},
            { 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2},
            { 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12}
        };
        int[,] s8 = {
            {13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7},
            { 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2},
            { 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8},
            { 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11}
        };
        int[,] p = {
            {16, 7, 20, 21, 29, 12, 28, 17},
            {1, 15, 23, 26, 5, 18, 31, 10},
            {2, 8, 24, 14, 32, 27, 3, 9},
            {19, 13, 30, 6, 22, 11, 4, 25}
        };
        int[,] inp ={
    { 40, 8, 48, 16, 56, 24, 64, 32 },
    { 39, 7, 47, 15, 55, 23, 63, 31 },
    { 38, 6, 46, 14, 54, 22, 62, 30 },
    { 37, 5, 45, 13, 53, 21, 61, 29 },
    { 36, 4, 44, 12, 52, 20, 60, 28 },
    { 35, 3, 43, 11, 51, 19, 59, 27 },
    { 34, 2, 42, 10, 50, 18, 58, 26 },
    { 33, 1, 41, 9, 49, 17, 57, 25 }
};
        public override string Decrypt(string cipherText, string key)
        {
            string leftPart, rightPart;
            string keybin = convertToBinary(key);
            string st1 = permutationChoice1(keybin);
            List<string> keys = keySchedule(st1);
            keys.Reverse();
            string bin = convertToBinary(cipherText);
            string st = intialPermutation(bin);
            (leftPart, rightPart) = splitToLeftAndRight(st);
            for (int i = 0; i < 16; i++)
            {
                string keyy = permutationChoice2(keys[i]);
                char[,] mat = expansionPermutation(rightPart);
                char[,] xormatrix = xor(mat, keyy);
                string sboxmatrix = S_BOX(xormatrix);
                string pp = permutation(sboxmatrix);
                string xorstring = xorStrings(pp, leftPart);
                leftPart = rightPart;
                rightPart = xorstring;
            }
            string cipherbin = inversePermutation(rightPart + leftPart);
            (leftPart, rightPart) = splitToLeftAndRight(cipherbin);

            int decimalValue = Convert.ToInt32(leftPart, 2);
            string hexValuel = decimalValue.ToString("X");
            if (hexValuel.Length != 8)
            {
                for (int i = 0; i < 8 - hexValuel.Length; i++)
                {
                    hexValuel = "0" + hexValuel;
                }
            }
            decimalValue = Convert.ToInt32(rightPart, 2);
            string hexValuer = decimalValue.ToString("X");
            if (hexValuer.Length != 8)
            {
                for (int i = 0; i < 8 - hexValuer.Length; i++)
                {
                    hexValuer = "0" + hexValuer;
                }
            }
            string plain = "0x" + hexValuel + hexValuer;
            return plain;
        }

        public override string Encrypt(string plainText, string key)
        {
            string leftPart, rightPart;
            string keybin = convertToBinary(key);
            string st1 = permutationChoice1(keybin);
            List<string> keys = keySchedule(st1);
            string bin = convertToBinary(plainText);
            string st = intialPermutation(bin);
            (leftPart, rightPart) = splitToLeftAndRight(st);
            for (int i = 0; i < 16; i++)
            {
                string keyy = permutationChoice2(keys[i]);
                char[,] mat = expansionPermutation(rightPart);
                char[,] xormatrix = xor(mat, keyy);
                string sboxmatrix = S_BOX(xormatrix);
                string pp = permutation(sboxmatrix);
                string xorstring = xorStrings(pp, leftPart);
                leftPart = rightPart;
                rightPart = xorstring;
            }
            string cipherbin = inversePermutation(rightPart + leftPart);
            (leftPart, rightPart) = splitToLeftAndRight(cipherbin);

            int decimalValue = Convert.ToInt32(leftPart, 2);
            string hexValuel = decimalValue.ToString("X");
            if (hexValuel.Length != 8)
            {
                for (int i = 0; i < 8 - hexValuel.Length; i++)
                {
                    hexValuel = "0" + hexValuel;
                }
            }
            decimalValue = Convert.ToInt32(rightPart, 2);
            string hexValuer = decimalValue.ToString("X");
            if (hexValuer.Length != 8)
            {
                for (int i = 0; i < 8 - hexValuer.Length; i++)
                {
                    hexValuer = "0" + hexValuer;
                }
            }
            string cipher = "0x" + hexValuel + hexValuer;
            return cipher;
        }
        string convertToBinary(string plain)
        {
            string left, right, leftbinary, rightbinary, plainbinary;

            plain = plain.Substring(2);
            left = plain.Substring(0, 8);
            right = plain.Substring(8);
            leftbinary = Convert.ToString(Convert.ToInt32(left, 16), 2);
            string x = leftbinary;
            if (leftbinary.Length != 32)
            {
                for (int i = 0; i < 32 - leftbinary.Length; i++)
                {
                    x = "0" + x;
                }
            }
            leftbinary = x;

            rightbinary = Convert.ToString(Convert.ToInt32(right, 16), 2);
            x = rightbinary;
            if (rightbinary.Length != 32)
            {
                for (int i = 0; i < 32 - rightbinary.Length; i++)
                {
                    x = "0" + x;
                }
            }
            rightbinary = x;
            plainbinary = leftbinary + rightbinary;
            return plainbinary;
        }
        string permutationChoice1(string key)
        {
            string afterip = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 7; j++)
                {
                    afterip += key[pc1[i, j] - 1];
                }
            }
            return afterip;
        }
        List<string> keySchedule(string key)
        {
            List<string> keys = new List<string>();
            string left = key.Substring(0, 28);
            string right = key.Substring(28);

            for (int i = 1; i <= 16; i++)
            {
                if (i == 1 || i == 2 || i == 9 || i == 16)
                {
                    left = left.Substring(1) + left[0];
                    right = right.Substring(1) + right[0];
                    keys.Add(left + right);
                }
                else
                {
                    left = left.Substring(2) + left[0] + left[1];
                    right = right.Substring(2) + right[0] + right[1];
                    keys.Add(left + right);
                }
            }
            return keys;
        }
        string intialPermutation(string plain)
        {
            string afterip = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    afterip += plain[ip[i, j] - 1];
                }
            }
            return afterip;
        }
        (string, string) splitToLeftAndRight(string text)
        {
            string left;
            string right;
            left = text.Substring(0, 32);
            right = text.Substring(32);
            return (left, right);
        }
        string permutationChoice2(string key)
        {
            string afterip = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 6; j++)
                {
                    afterip += key[pc2[i, j] - 1];
                }
            }
            return afterip;
        }
        char[,] expansionPermutation(string right)
        {
            char[,] matrix = new char[8, 6];
            int counter = 0;
            for (int i = 0; i < 8; i++)
            {
                for (int j = 1; j < 5; j++)
                {
                    matrix[i, j] = right[counter];
                    counter++;
                }
            }
            matrix[0, 0] = right[31];
            for (int i = 1; i < 8; i++)
            {
                matrix[i, 0] = matrix[i - 1, 4];
            }
            matrix[0, 5] = matrix[1, 1];
            for (int i = 1; i < 8; i++)
            {
                matrix[i, 5] = matrix[(i + 1) % 8, 1];
            }
            return matrix;
        }
        char[,] xor(char[,] matrix, string key)
        {
            int counter = 0;
            int x, y, z;
            for (int i = 0; i < matrix.GetLength(0); i++)
            {
                for (int j = 0; j < matrix.GetLength(1); j++)
                {
                    x = (int)matrix[i, j] - '0';
                    y = (int)key[counter] - '0';
                    z = x ^ y;
                    matrix[i, j] = (char)(z + '0');
                    counter++;
                }
            }
            return matrix;
        }
        string S_BOX(char[,] matrix)
        {
            List<string> save = new List<string>();
            for (int i = 0; i < 8; i++)
            {
                string row = matrix[i, 0].ToString() + matrix[i, 5].ToString();
                string column = matrix[i, 1].ToString() + matrix[i, 2].ToString() + matrix[i, 3].ToString() + matrix[i, 4].ToString();
                int ro = Convert.ToInt32(row, 2);
                int col = Convert.ToInt32(column, 2);
                if (i == 0)
                {
                    save.Add(Convert.ToString(s1[ro, col], 2));
                }
                else if (i == 1)
                {
                    save.Add(Convert.ToString(s2[ro, col], 2));
                }
                else if (i == 2)
                {
                    save.Add(Convert.ToString(s3[ro, col], 2));
                }
                else if (i == 3)
                {
                    save.Add(Convert.ToString(s4[ro, col], 2));
                }
                else if (i == 4)
                {
                    save.Add(Convert.ToString(s5[ro, col], 2));
                }
                else if (i == 5)
                {
                    save.Add(Convert.ToString(s6[ro, col], 2));
                }
                else if (i == 6)
                {
                    save.Add(Convert.ToString(s7[ro, col], 2));
                }
                else if (i == 7)
                {
                    save.Add(Convert.ToString(s8[ro, col], 2));
                }
            }
            string s;
            for (int i = 0; i < save.Count; i++)
            {
                if (save[i].Length != 4)
                {
                    s = save[i];
                    for (int j = 0; j < (4 - save[i].Length); j++)
                    {
                        s = "0" + s;
                    }
                    save[i] = s;
                }
            }
            char[,] sboxmatrix = new char[8, 4];
            string output = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    sboxmatrix[i, j] = save[i][j];
                    output += sboxmatrix[i, j];
                }
            }
            return output;
        }
        string permutation(string plain)
        {
            string afterp = "";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    afterp += plain[p[i, j] - 1];
                }
            }
            return afterp;
        }
        string xorStrings(string s1, string s2)
        {
            int x, y, z;
            string outputstring = "";
            for (int i = 0; i < 32; i++)
            {
                x = (int)s1[i] - '0';
                y = (int)s2[i] - '0';
                z = x ^ y;
                outputstring += (char)(z + '0');
            }
            return outputstring;
        }
        string inversePermutation(string text)
        {
            string afterip = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    afterip += text[inp[i, j] - 1];
                }
            }
            return afterip;
        }
    }
}
