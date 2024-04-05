using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        int[,] S_BOX = new int[17, 17]
        {
            {0x20,  0x0 , 0x1 , 0x2 , 0x3 , 0x4 , 0x5 , 0x6, 0x7 , 0x8 , 0x9 ,0xA , 0xB , 0xC , 0xD , 0xE , 0xF },
            {0x0 ,0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
            {0x1 ,0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
            {0x2 ,0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
            {0x3 ,0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
            {0x4 ,0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
            {0x5 ,0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
            {0x6 ,0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
            {0x7 ,0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
            {0x8 ,0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
            {0x9 ,0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
            {0xA ,0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
            {0xB ,0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
            {0xC ,0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
            {0xD ,0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
            {0xE ,0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
            {0xF ,0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}
        };
        int[,] RCON = new int[4, 10]
        {
        {0x01 , 0x02 , 0x04 , 0x08 , 0x10 , 0x20 , 0x40 , 0x80 , 0x1b , 0x36},
        {0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00},
        {0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00},
        {0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00}
        };

        public override string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public override string Encrypt(string plainText, string key)
        {
            List<string> duos1 = new List<string>();
            List<string> duos2 = new List<string>();
            String[,] plaintextmatrix = new String[4, 4];
            String[,] keymatrix = new String[4, 4];
            String[,] subbytes = new String[4, 4];
            String[,] shiftrows = new String[4, 4];
            String[,] mixcolumns = new String[4, 4];

            for (int i = 2; i <= 32; i += 2)
            {
                String duo1 = plainText.Substring(i, 2);
                String duo2 = key.Substring(i, 2);
                duos1.Add(duo1);
                duos2.Add(duo2);
            }
            int counter = 0;
            for (int j = 0; j < 4; j++)
            {
                for (int i = 0; i < 4; i++)
                {
                    plaintextmatrix[i, j] = duos1[counter];
                    keymatrix[i, j] = duos2[counter];
                    counter++;
                }
            }
            string[,] beforeround = AddRoundKey(plaintextmatrix, keymatrix);
            for (int A = 0; A < 10; A++)
            {
                if (A != 9)
                {
                    subbytes = subBytes(beforeround, S_BOX);
                    shiftrows = ShiftRows(subbytes);
                    mixcolumns = mixColumns(shiftrows);
                    keymatrix = keySchedule(keymatrix, S_BOX, RCON, A);
                    beforeround = AddRoundKey(mixcolumns, keymatrix);
                }
                if (A == 9)
                {
                    subbytes = subBytes(beforeround, S_BOX);
                    shiftrows = ShiftRows(subbytes);
                    keymatrix = keySchedule(keymatrix, S_BOX, RCON, A);
                    beforeround = AddRoundKey(shiftrows, keymatrix);
                }
            }
            string cypherkey = "0x";
            for (int j = 0; j < 4; j++)
            {
                for (int i = 0; i < 4; i++)
                {
                    if (beforeround[i, j].Length == 1)
                    {
                        beforeround[i, j] = "0" + beforeround[i, j];
                    }
                    cypherkey += beforeround[i, j];
                }
            }
            return cypherkey;
            //throw new NotImplementedException();
        }
        string[,] AddRoundKey(string[,] plainText, string[,] key)
        {
            int intValue1, intValue2;
            string[,] outputkey = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    intValue1 = Convert.ToInt32(plainText[i, j], 16);
                    intValue2 = Convert.ToInt32(key[i, j], 16);
                    outputkey[i, j] = (intValue1 ^ intValue2).ToString("X");
                }
            }
            return outputkey;
        }
        string[,] subBytes(string[,] matrix, int[,] sub_Box)
        {
            string value;
            string x1, x2;
            int y1, y2;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    value = matrix[i, j];
                    if (value.Length == 1)
                    {
                        x1 = "0x0";
                        x2 = "0x" + value[0];
                    }
                    else
                    {
                        x1 = "0x" + value[0];
                        x2 = "0x" + value[1];
                    }
                    y1 = Convert.ToInt32(x1, 16);
                    y2 = Convert.ToInt32(x2, 16);
                    matrix[i, j] = S_BOX[y1 + 1, y2 + 1].ToString("X"); ;
                }
            }
            return matrix;
        }
        string[,] ShiftRows(string[,] plainText)
        {
            string temp = plainText[1, 0];
            plainText[1, 0] = plainText[1, 1];
            plainText[1, 1] = plainText[1, 2];
            plainText[1, 2] = plainText[1, 3];
            plainText[1, 3] = temp;

            temp = plainText[2, 0];
            string temp2 = plainText[2, 1];
            plainText[2, 0] = plainText[2, 2];
            plainText[2, 1] = plainText[2, 3];
            plainText[2, 2] = temp;
            plainText[2, 3] = temp2;

            temp = plainText[3, 0];
            temp2 = plainText[3, 1];
            string temp3 = plainText[3, 2];
            plainText[3, 0] = plainText[3, 3];
            plainText[3, 1] = temp;
            plainText[3, 2] = temp2;
            plainText[3, 3] = temp3;
            return plainText;

        }
        string[,] mixColumns(string[,] matrix2)
        {
            string[,] resultMatrix = new string[4, 4];
            int[,] matrix1 = new int[4, 4]
            {
        {2, 3, 1, 1},
        {1, 2, 3, 1},
        {1, 1, 2, 3},
        {3, 1, 1, 2}
            };
            string lastthing;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    int sum = 0;
                    for (int k = 0; k < 4; k++)
                    {
                        int x = matrix1[i, k];
                        string y = matrix2[k, j];
                        int z = 0;
                        string binary;
                        int dec;
                        if (x == 1)
                        {
                            z = Convert.ToInt32(y, 16);
                            z = z ^ 0;
                            sum ^= z;
                        }
                        else if (x == 2)
                        {
                            binary = Convert.ToString(Convert.ToInt32(y, 16), 2);
                            if (binary.Length == 8 && binary[0] == '1')
                            {
                                binary = binary.Substring(1) + "0";
                                dec = Convert.ToInt32(binary, 2);
                                z = dec ^ Convert.ToInt32("1B", 16);
                                sum ^= z;
                            }
                            else
                            {
                                binary = binary + "0";
                                z = Convert.ToInt32(binary, 2);
                                sum ^= z;
                            }
                        }
                        else if (x == 3)
                        {
                            binary = Convert.ToString(Convert.ToInt32(y, 16), 2);
                            int dec0 = Convert.ToInt32(binary, 2);
                            if (binary.Length == 8 && binary[0] == '1')
                            {
                                binary = binary.Substring(1) + "0";
                                dec = Convert.ToInt32(binary, 2);
                                z = (dec ^ Convert.ToInt32("1B", 16)) ^ dec0;
                                sum ^= z;
                            }
                            else
                            {
                                binary = binary + "0";
                                z = (Convert.ToInt32(binary, 2));
                                z ^= dec0;
                                sum ^= z;
                            }
                        }
                    }
                    lastthing = sum.ToString("X");
                    if (lastthing.Length == 1)
                        lastthing = "0" + lastthing;
                    resultMatrix[i, j] = lastthing;

                }
            }
            return resultMatrix;
        }
        string[,] keySchedule(string[,] matrix, int[,] sub_Box, int[,] RCON, int counterr)
        {
            string before;
            int intValue1, intValue2, intValue3;
            string[,] outputkey = new string[4, 4];
            string value;
            string x1, x2;
            int y1, y2;
            string[] rconarray = new string[4];
            string y;
            int result;
            string[] last = new string[4];
            last[0] = matrix[1, 3];
            last[1] = matrix[2, 3];
            last[2] = matrix[3, 3];
            last[3] = matrix[0, 3];
            for (int i = 0; i < 4; i++)
            {
                value = last[i];
                x1 = "0x" + value[0];
                x2 = "0x" + value[1];
                y1 = Convert.ToInt32(x1, 16);
                y2 = Convert.ToInt32(x2, 16);
                last[i] = S_BOX[y1 + 1, y2 + 1].ToString("X");
                intValue1 = Convert.ToInt32(last[i], 16);
                intValue2 = Convert.ToInt32(matrix[i, 0], 16);
                y = Convert.ToString(RCON[i, counterr], 2);
                intValue3 = Convert.ToInt32(y, 2);
                result = intValue1 ^ intValue2 ^ intValue3;
                outputkey[i, 0] = result.ToString("X");
            }
            for (int i = 1; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    intValue1 = Convert.ToInt32(matrix[j, i], 16);
                    intValue2 = Convert.ToInt32(outputkey[j, i - 1], 16);
                    before = (intValue1 ^ intValue2).ToString("X");
                    if (before.Length == 1)
                    {
                        before = "0" + before;
                    }
                    outputkey[j, i] = before;
                }
            }
            return outputkey;
        }
    }
}
