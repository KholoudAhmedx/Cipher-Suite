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

        int[,] inv_SubBox = new int[16, 16]
        {
            {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
            {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
            {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
            {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
            {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
            {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
            {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
            {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
            {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
            {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
            {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
            {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
            {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
            {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
            {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
            {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}
        };

        int[,] RCON = new int[4, 10]
        {
        {0x01 , 0x02 , 0x04 , 0x08 , 0x10 , 0x20 , 0x40 , 0x80 , 0x1b , 0x36},
        {0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00},
        {0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00},
        {0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00}
        };

        string[,] invmixColumns = new string[,]
{
    { "0E", "0B", "0D", "09" },
    { "09", "0E", "0B", "0D" },
    { "0D", "09", "0E", "0B" },
    { "0B", "0D", "09", "0E" }
};

        string[,] Table1 = new string[,]
{
    { "00", "00", "19", "01", "32", "02", "1A", "C6", "4B", "C7", "1B", "68", "33", "EE", "DF", "03" },
    { "64", "04", "E0", "0E", "34", "8D", "81", "EF", "4C", "71", "08", "C8", "F8", "69", "1C", "C1" },
    { "7D", "C2", "1D", "B5", "F9", "B9", "27", "6A", "4D", "E4", "A6", "72", "9A", "C9", "09", "78" },
    { "65", "2F", "8A", "05", "21", "0F", "E1", "24", "12", "F0", "82", "45", "35", "93", "DA", "8E" },
    { "96", "8F", "DB", "BD", "36", "D0", "CE", "94", "13", "5C", "D2", "F1", "40", "46", "83", "38" },
    { "66", "DD", "FD", "30", "BF", "06", "8B", "62", "B3", "25", "E2", "98", "22", "88", "91", "10" },
    { "7E", "6E", "48", "C3", "A3", "B6", "1E", "42", "3A", "6B", "28", "54", "FA", "85", "3D", "BA" },
    { "2B", "79", "0A", "15", "9B", "9F", "5E", "CA", "4E", "D4", "AC", "E5", "F3", "73", "A7", "57" },
    { "AF", "58", "A8", "50", "F4", "EA", "D6", "74", "4F", "AE", "E9", "D5", "E7", "E6", "AD", "E8" },
    { "2C", "D7", "75", "7A", "EB", "16", "0B", "F5", "59", "CB", "5F", "B0", "9C", "A9", "51", "A0" },
    { "7F", "0C", "F6", "6F", "17", "C4", "49", "EC", "D8", "43", "1F", "2D", "A4", "76", "7B", "B7" },
    { "CC", "BB", "3E", "5A", "FB", "60", "B1", "86", "3B", "52", "A1", "6C", "AA", "55", "29", "9D" },
    { "97", "B2", "87", "90", "61", "BE", "DC", "FC", "BC", "95", "CF", "CD", "37", "3F", "5B", "D1" },
    { "53", "39", "84", "3C", "41", "A2", "6D", "47", "14", "2A", "9E", "5D", "56", "F2", "D3", "AB" },
    { "44", "11", "92", "D9", "23", "20", "2E", "89", "B4", "7C", "B8", "26", "77", "99", "E3", "A5" },
    { "67", "4A", "ED", "DE", "C5", "31", "FE", "18", "0D", "63", "8C", "80", "C0", "F7", "70", "07" }
};

        string[,] Table2 = new string[,]
        {
    { "01", "03", "05", "0F", "11", "33", "55", "FF", "1A", "2E", "72", "96", "A1", "F8", "13", "35" },
    { "5F", "E1", "38", "48", "D8", "73", "95", "A4", "F7", "02", "06", "0A", "1E", "22", "66", "AA" },
    { "E5", "34", "5C", "E4", "37", "59", "EB", "26", "6A", "BE", "D9", "70", "90", "AB", "E6", "31" },
    { "53", "F5", "04", "0C", "14", "3C", "44", "CC", "4F", "D1", "68", "B8", "D3", "6E", "B2", "CD" },
    { "4C", "D4", "67", "A9", "E0", "3B", "4D", "D7", "62", "A6", "F1", "08", "18", "28", "78", "88" },
    { "83", "9E", "B9", "D0", "6B", "BD", "DC", "7F", "81", "98", "B3", "CE", "49", "DB", "76", "9A" },
    { "B5", "C4", "57", "F9", "10", "30", "50", "F0", "0B", "1D", "27", "69", "BB", "D6", "61", "A3" },
    { "FE", "19", "2B", "7D", "87", "92", "AD", "EC", "2F", "71", "93", "AE", "E9", "20", "60", "A0" },
    { "FB", "16", "3A", "4E", "D2", "6D", "B7", "C2", "5D", "E7", "32", "56", "FA", "15", "3F", "41" },
    { "C3", "5E", "E2", "3D", "47", "C9", "40", "C0", "5B", "ED", "2C", "74", "9C", "BF", "DA", "75" },
    { "9F", "BA", "D5", "64", "AC", "EF", "2A", "7E", "82", "9D", "BC", "DF", "7A", "8E", "89", "80" },
    { "9B", "B6", "C1", "58", "E8", "23", "65", "AF", "EA", "25", "6F", "B1", "C8", "43", "C5", "54" },
    { "FC", "1F", "21", "63", "A5", "F4", "07", "09", "1B", "2D", "77", "99", "B0", "CB", "46", "CA" },
    { "45", "CF", "4A", "DE", "79", "8B", "86", "91", "A8", "E3", "3E", "42", "C6", "51", "F3", "0E" },
    { "12", "36", "5A", "EE", "29", "7B", "8D", "8C", "8F", "8A", "85", "94", "A7", "F2", "0D", "17" },
    { "39", "4B", "DD", "7C", "84", "97", "A2", "FD", "1C", "24", "6C", "B4", "C7", "52", "F6", "01" }
        };

        public override string Decrypt(string cipherText, string key)
        {
            List<string> duos1 = new List<string>();
            List<string> duos2 = new List<string>();
            String[,] mainCiphermatrix = new String[4, 4];
            String[,] keymatrix = new String[4, 4];
            List<string[,]> matrixList = new List<string[,]>();

            for (int i = 2; i <= 32; i += 2)
            {
                String duo1 = cipherText.Substring(i, 2);
                String duo2 = key.Substring(i, 2);
                duos1.Add(duo1);
                duos2.Add(duo2);
            }
            int counter = 0;
            for (int j = 0; j < 4; j++)
            {
                for (int i = 0; i < 4; i++)
                {
                    mainCiphermatrix[i, j] = duos1[counter];
                    keymatrix[i, j] = duos2[counter];
                    counter++;
                }

            }
            matrixList.Add(keymatrix);
            for (int i = 0; i < 10; i++)
            {
                keymatrix = keySchedule(keymatrix, S_BOX, RCON, i);
                matrixList.Add(keymatrix);
            }

            string[,] beforeround = new string[4, 4];
            for (int i = 10; i >= 1; i--)
            {
                if (i == 10)
                {
                    beforeround = AddRoundKey(mainCiphermatrix, matrixList[10]);
                    beforeround = invShiftRows(beforeround);
                    beforeround = invSubBytes(beforeround, inv_SubBox);
                }
                else
                {
                    beforeround = AddRoundKey(beforeround, matrixList[i]);
                    beforeround = invMixColumns(beforeround);
                    beforeround = invShiftRows(beforeround);
                    beforeround = invSubBytes(beforeround, inv_SubBox);
                }
            }
            string[,] final = AddRoundKey(beforeround, matrixList[0]);
            string plaintext = "0x";
            for (int j = 0; j < 4; j++)
            {
                for (int i = 0; i < 4; i++)
                {
                    if (final[i, j].Length == 1)
                        final[i, j] = "0" + final[i, j];
                    plaintext += final[i, j];
                }
            }
            return plaintext;
        }

        string[,] invShiftRows(string[,] plainText)
        {
            // Move first row to the right by 3 positions
            string temp = plainText[1, 3];
            plainText[1, 3] = plainText[1, 2];
            plainText[1, 2] = plainText[1, 1];
            plainText[1, 1] = plainText[1, 0];
            plainText[1, 0] = temp;

            // Move second row to the right by 2 positions and first row to the right by 2 positions
            temp = plainText[2, 2];
            plainText[2, 2] = plainText[2, 0];
            plainText[2, 0] = temp;
            string temp2 = plainText[2, 3];
            plainText[2, 3] = plainText[2, 1];
            plainText[2, 1] = temp2;

            string temp3, temp4;
            // Move third row to the right by 1 position and first row to the right by 1 position
            string tempp = plainText[3, 0];
            string tempp2 = plainText[3, 1];
            string tempp3 = plainText[3, 2];
            string tempp4 = plainText[3, 3];

            plainText[3, 0] = tempp2;
            plainText[3, 1] = tempp3;
            plainText[3, 2] = tempp4;
            plainText[3, 3] = tempp;

            Console.WriteLine("Inverse Shift rows");
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    Console.Write(plainText[i, j]);
                    Console.Write(" ");
                }
                Console.WriteLine();
            }
            Console.WriteLine();
            return plainText;
        }

        string[,] invSubBytes(string[,] matrix, int[,] inv_Sub_Box)
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

                    // Perform inverse substitution using inv_Sub_Box
                    matrix[i, j] = inv_Sub_Box[y1, y2].ToString("X2");
                }
            }

            Console.WriteLine("Inverse Sub Bytes");
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    Console.Write(matrix[i, j]);
                    Console.Write(" ");
                }
                Console.WriteLine();
            }
            Console.WriteLine();
            return matrix;
        }

        string XOR(string A, string B)
        {
            if (A == "") return B;
            char[] output = new char[8];
            for (int i = 0; i < A.Length; i++)
            {
                if (A.Substring(i, 1) == B.Substring(i, 1)) output[i] = '0';
                else output[i] = '1';
            }
            return new string(output);
        }
        string multInvMixColumns(string A, string B)
        {

            if (A.Length < 2) A = "0" + A;
            if (B.Length < 2) B = "0" + B;
            if (A == "00" || B == "00") return "00";
            int row1 = Convert.ToInt32(A.Substring(0, 1), 16);
            int col1 = Convert.ToInt32(A.Substring(1, 1), 16);

            int row2 = Convert.ToInt32(B.Substring(0, 1), 16);
            int col2 = Convert.ToInt32(B.Substring(1, 1), 16);

            int sum = Convert.ToInt32(Table1[row1, col1], 16) + Convert.ToInt32(Table1[row2, col2], 16);
            if (sum > Convert.ToInt32("FF", 16))
            {
                sum = sum - Convert.ToInt32("FF", 16);
            }
            string ans = sum.ToString("X2");
            int row = Convert.ToInt32(ans.Substring(0, 1), 16);
            int col = Convert.ToInt32(ans.Substring(1, 1), 16);
            return Table2[row, col];
        }

        string[,] invMixColumns(string[,] state)
        {
            for (int col = 0; col < 4; col++)
            {
                string[,] tempState = new string[4, 1];
                for (int i = 0; i < 4; i++)
                {
                    tempState[i, 0] = state[i, col];
                }

                string[,] tempColMixMatrix = new string[4, 1];

                for (int i = 0; i < 4; i++)
                {
                    for (int z = 0; z < 4; z++)
                    {
                        tempColMixMatrix[z, 0] = invmixColumns[i, z];
                    }
                    string temp = "";
                    for (int j = 0; j < 4; j++)
                    {
                        string ans = multInvMixColumns(tempColMixMatrix[j, 0], tempState[j, 0]);
                        ans = Convert.ToString(Convert.ToInt32(ans, 16), 2).PadLeft(8, '0');
                        temp = XOR(temp, ans);
                    }
                    state[i, col] = Convert.ToString(Convert.ToInt32(temp, 2), 16);
                }
            }
            return state;
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
