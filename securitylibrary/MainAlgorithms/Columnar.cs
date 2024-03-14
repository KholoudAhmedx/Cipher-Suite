using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            int plainLength = plainText.Length;

            for (int k = 2; k <= plainLength; k++)
            {
                List<int> colNumbers = new List<int>() { 1 };

                colNumbers.AddRange(Enumerable.Range(2, k - 1));

                int numCols = k;
                double numRows = Math.Ceiling((double)plainLength / numCols);

                
                bool refactoredCipher = cipherText.Length == numRows * numCols;

                
                List<StringBuilder> colsList = new List<StringBuilder>(numCols);
                for (int i = 0; i < numCols; i++)
                {
                    colsList.Add(new StringBuilder());
                }

                
                for (int i = 0; i < plainText.Length; i++)
                {
                    int columnIndex = i % numCols; 
                    colsList[columnIndex].Append(plainText[i]); 
                }

                
                StringBuilder[] cols = colsList.ToArray();

                int start = 0;
                int end = (int)numRows;
                List<int> copyCol = new List<int>(colNumbers);
                List<int> finalKey = new List<int>();

                for (int i = 0; i < numCols; i++)
                {
                    foreach (var colNum in colNumbers)
                    {
                        string inCol = cols[colNum - 1].ToString();
                        end = (int)numRows;

                        if (!refactoredCipher && colNum >= (numCols - (numRows * numCols - cipherText.Length) + 1))
                        {
                            end -= 1;
                        }

                        string inCipher = cipherText.Substring(start, end);

                        if (string.Equals(inCipher, inCol))
                        {
                            colNumbers.Remove(colNum);
                            finalKey.Add(colNum);

                            if (end == (int)numRows - 1)
                            {
                                start += (int)numRows - 1;
                                end++;
                            }
                            else start += (int)numRows;
                            break;
                        }
                    }
                }
                if (finalKey.Count == numCols)
                {
                    List<int> keyhere = new List<int>(new int[numCols]);

                    for (int i = 0; i < numCols; i++)
                    {
                        keyhere[finalKey[i] - 1] = i + 1;
                    }

                    return keyhere;
                }

            }

           
            List<int> defaultKey = new List<int>();
            for (int i = 1; i <= plainText.Length; i++)
            {
                defaultKey.Add(i);
            }
            return defaultKey;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            int col = key.Count;
            int row = (int)Math.Ceiling((double)cipherText.Length / col);
            char[,] cipherMat = new char[row, col];

            
            
            for (int j = 0, k = 0; j < col; j++)
            {
                for (int i = 0; i < row; i++)
                {
                    if (k < cipherText.Length)
                    {
                        cipherMat[i, j] = cipherText[k];
                        k++;
                    }
                    else
                    {
                        cipherMat[i, j] = 'x'; 
                    }
                }
            }

            
            char[,] decCipher = new char[row, col];
            for (int j = 0; j < col; j++)
            {
                int index = key[j] - 1; 
                for (int i = 0; i < row; i++)
                {
                    decCipher[i, j] = cipherMat[i, index];
                }
            }

            
            StringBuilder msg = new StringBuilder();
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    
                    if (decCipher[i, j] != 'x' && decCipher[i, j] != '\0') 
                    {
                        msg.Append(decCipher[i, j]);
                    }
                }
            }

            return msg.ToString();
        }

        public string Encrypt(string plainText, List<int> key)
        {
            int col = key.Count;
            int row = (int)Math.Ceiling((double)plainText.Length / col);
            char[,] matrix = new char[row, col];

            int paddingLength = row * col - plainText.Length;
            if (paddingLength > 0)
            {
                plainText = plainText.PadRight(plainText.Length + paddingLength, 'x');
            }

            
            for (int i = 0, k = 0; i < row; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    if (k < plainText.Length)
                    {
                        char ch = plainText[k];
                        matrix[i, j] = ch;
                        k++;
                    }
                }
            }

            List<int> sortedIndices = key.Select((x, i) => new KeyValuePair<int, int>(x, i))
                                         .OrderBy(x => x.Key)
                                         .Select(x => x.Value)
                                         .ToList();

            StringBuilder cipher = new StringBuilder();

            foreach (int colIndex in sortedIndices)
            {
                for (int i = 0; i < row; i++)
                {
                    if (char.IsLetter(matrix[i, colIndex]) || matrix[i, colIndex] == ' ' || matrix[i, colIndex] == 'x')
                    {
                        cipher.Append(matrix[i, colIndex]);
                    }
                }
            }

            return cipher.ToString();
        }

    }
}
