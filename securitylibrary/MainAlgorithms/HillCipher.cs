using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{

    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {

        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            string plain = convertListToString(plainText);
            string cipher = convertListToString(cipherText);
            List<string> substrings1 = new List<string>();
            List<string> substrings2 = new List<string>();
            string sub1, sub2, possiblekey;
            int matrixsize = 2;
            int[,] matrix;
            int[,] matrix2;
            int determinant;
            int[,] matrixinverse;
            bool complete;
            for (int i = 0; i <= plain.Length - 2; i += 2)
            {
                sub1 = plain.Substring(i, 2);
                substrings1.Add(sub1);
            }
            for (int i = 0; i <= cipher.Length - 2; i += 2)
            {
                sub2 = cipher.Substring(i, 2);
                substrings2.Add(sub2);
            }
            for (int i = 0; i < substrings1.Count; i++)
            {
                for (int j = 0; j < substrings1.Count; j++)
                {
                    if (i != j)
                    {
                        possiblekey = substrings1[i] + substrings1[j];
                        matrix = creatematrix1(matrixsize, possiblekey);
                        determinant = getDeterminantAnalisis2By2(matrix);
                        complete = validitaionAnalyse(matrix, matrixsize, determinant);
                        if (complete)
                        {
                            matrixinverse = getMatrixInverseAnalisis2By2(matrix, determinant);
                            string ccipher = substrings2[i] + substrings2[j];
                            matrix2 = creatematrix1(matrixsize, ccipher);
                            List<int> outkey = MultiplyMatrices(matrix2, matrixinverse, matrixsize);
                            List<int> cipher2 = Encrypt(plainText, outkey);
                            bool isEqual = cipherText.SequenceEqual(cipher2);
                            if (isEqual)
                            {
                                return outkey;
                            }
                        }
                    }
                    continue;
                }
            }
        throw new InvalidAnlysisException();
            //throw new NotImplementedException();
        }
        bool validitaionAnalyse(int[,] matrix, int size, int determinant)
        {
            for (int i = 0; i < size; i++)
            {
                for (int j = 0; j < size; j++)
                {
                    if (matrix[i, j] < 0 && matrix[i, j] > 26)
                    {
                        return false;
                    }
                }
            }
            if (determinant == 0 || gcd(determinant) != 1)
            {
                return false;
            }
            if (multiplicativeInverse(determinant) == -1)
            {
                return false;
            }
            return true;
        }
        int[,] getMatrixInverseAnalisis2By2(int[,] matrix, int determinant)
        {
            int[,] newmatrix = new int[2, 2];
            newmatrix[0, 0] = matrix[1, 1] * determinant;
            newmatrix[0, 1] = -1 * matrix[0, 1] * determinant;
            newmatrix[1, 0] = -1 * matrix[1, 0] * determinant;
            newmatrix[1, 1] = matrix[0, 0] * determinant;
            return newmatrix;
        }
        int getDeterminantAnalisis2By2(int[,] matrix)
        {
            int determinant = matrix[0, 0] * matrix[1, 1] - (matrix[0, 1] * matrix[1, 0]);
            determinant = multiplicativeInverse(determinant);
            return determinant;
        }
        
        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }
        
        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            string keyy = convertListToString(key);
            string cipher = convertListToString(cipherText);
            int key_len = keyy.Length;
            int matrixsize = getMatrixSize(key_len);
            int[,] matrix;
            int determinant;
            int[,] matrixinverse;
            int[] vector;
            string sub = "";
            int[] res;
            List<int> listOfIntegers = new List<int>();
            if (matrixsize == 2)
            {
                matrix = creatematrix(matrixsize, keyy);
                determinant = getDeterminant2By2(matrix);
                bool complete = validitaion(matrix, matrixsize, determinant);
                matrixinverse = getMatrixInverse2By2(matrix, determinant);
                for (int i = 0; i < cipher.Length; i += matrixsize)
                {
                    sub = cipher.Substring(i, matrixsize);
                    vector = createVector(sub);
                    res = matrixMultiplication(matrixinverse, vector, matrixsize);
                    listOfIntegers.AddRange(res);
                }
            }
            else if (matrixsize == 3)
            {
                int v1, v2, v3;
                matrix = creatematrix(matrixsize, keyy);
                getDeterminant3By3(in matrix, out determinant, out v1, out v2, out v3);
                bool complete = validitaion(matrix, matrixsize, determinant);
                int[,] matrixinverse1 = getMatrixInverse3By3(matrix, determinant, v1, v2, v3);
                for (int i = 0; i < cipher.Length; i += matrixsize)
                {
                    sub = cipher.Substring(i, matrixsize);
                    vector = createVector(sub);
                    res = matrixMultiplication(matrixinverse1, vector, matrixsize);
                    listOfIntegers.AddRange(res);
                }
            }
            return listOfIntegers;
            //throw new NotImplementedException();
        }
        bool validitaion(int[,] matrix, int size, int determinant)
        {
            for (int i = 0; i < size; i++)
            {
                for (int j = 0; j < size; j++)
                {
                    if (matrix[i, j] < 0 && matrix[i, j] > 26)
                    {
                        throw new Exception();
                    }
                }
            }
            if (determinant == 0 || gcd(determinant) != 1)
            {
                throw new Exception();
            }
            if (multiplicativeInverse(determinant) == -1)
            {
                throw new Exception();
            }
            return true;
        }
        int gcd(int determinant)
        {
            int GCD = 1;
            for (int i = 2; i <= determinant; i++)
            {
                if (26 % i == 0 && determinant % i == 0)
                    GCD = i;
            }
            return GCD;
        }
        int getDeterminant2By2(int[,] matrix)
        {
            int determinant = matrix[0, 0] * matrix[1, 1] - (matrix[0, 1] * matrix[1, 0]);
            return determinant;
        }
        void getDeterminant3By3(in int[,] matrix, out int determinant, out int v1, out int v2, out int v3)
        {
            int[,] matrix1 = 
            {
                {matrix[1,1], matrix[1,2]},
                {matrix[2,1], matrix[2,2]}
            };
            int[,] matrix2 = 
            {
                {matrix[1,0], matrix[1,2]},
                {matrix[2,0], matrix[2,2]}
            };
            int[,] matrix3 = 
            {
                {matrix[1,0], matrix[1,1]},
                {matrix[2,0], matrix[2,1]}
            };
            v1 = getDeterminant2By2(matrix1);
            v2 = getDeterminant2By2(matrix2);
            v3 = getDeterminant2By2(matrix3);
            determinant = matrix[0, 0] * v1 - matrix[0, 1] * v2 + matrix[0, 2] * v3;
            determinant = multiplicativeInverse(determinant);
        }
        int modolu(int Det)
        {
            int r = Det % 26;
            if (r < 0)
            {
                r += 26;
            }
            return r;
        }
        int multiplicativeInverse(int Det)
        {
            Det = modolu(Det);
            int inverse = 0;
            for (int i = 0; i < 26; i++)
            {
                if ((Det * i) % 26 == 1)
                {
                    inverse = i;
                    break;
                }
            }
            return inverse;
        }
        int[,] getMatrixInverse3By3(int[,] matrix, int determinant, int v1, int v2, int v3)
        {
            int[,] matrix4 = 
            {
            {matrix[0,1], matrix[0,2]},{matrix[2,1], matrix[2,2]}
            };
            int[,] matrix5 = 
            {
                {matrix[0,0], matrix[0,2]},{matrix[2,0], matrix[2,2]}
            };
            int[,] matrix6 = 
            {
                {matrix[0,0], matrix[0,1]},{matrix[2,0], matrix[2,1]}
            };
            int[,] matrix7 = 
            {
                {matrix[0,1], matrix[0,2]},{matrix[1,1], matrix[1,2]}
            };
            int[,] matrix8 = 
            {
                {matrix[0,0], matrix[0,2]},{matrix[1,0], matrix[1,2]}
            };
            int[,] matrix9 = 
            {
                {matrix[0,0], matrix[0,1]},{matrix[1,0], matrix[1,1]}
            };
            v2 = v2 * -1;
            int v4 = getDeterminant2By2(matrix4) * -1;
            int v5 = getDeterminant2By2(matrix5);
            int v6 = getDeterminant2By2(matrix6) * -1;
            int v7 = getDeterminant2By2(matrix7);
            int v8 = getDeterminant2By2(matrix8) * -1;
            int v9 = getDeterminant2By2(matrix9);
            int[,] newmatrix = new int[3, 3];
            newmatrix[0, 0] = ((v1 * determinant) + 26 * 300) % 26;
            newmatrix[1, 0] = ((v2 * determinant) + 26 * 300) % 26;
            newmatrix[2, 0] = ((v3 * determinant) + 26 * 300) % 26;
            newmatrix[0, 1] = ((v4 * determinant) + 26 * 300) % 26;
            newmatrix[1, 1] = ((v5 * determinant) + 26 * 300) % 26;
            newmatrix[2, 1] = ((v6 * determinant) + 26 * 300) % 26;
            newmatrix[0, 2] = ((v7 * determinant) + 26 * 300) % 26;
            newmatrix[1, 2] = ((v8 * determinant) + 26 * 300) % 26;
            newmatrix[2, 2] = ((v9 * determinant) + 26 * 300) % 26;
            return newmatrix;

        }
        int[,] getMatrixInverse2By2(int[,] matrix, int determinant)
        {
            int[,] newmatrix = new int[2, 2];
            newmatrix[0, 0] = matrix[1, 1] * (1 / determinant);
            newmatrix[0, 1] = -1 * matrix[0, 1] * (1 / determinant);
            newmatrix[1, 0] = -1 * matrix[1, 0] * (1 / determinant);
            newmatrix[1, 1] = matrix[0, 0] * (1 / determinant);
            return newmatrix;
        }
        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }


        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            string keyy = convertListToString(key);
            string plain = convertListToString(plainText);
            int key_len = keyy.Length;
            int matrixsize = getMatrixSize(key_len);
            int[,] matrix = creatematrix(matrixsize, keyy);
            string sub = "";
            int[] vector;
            int[] res;
            List<int> listOfIntegers = new List<int>();
            for (int i = 0; i < plain.Length; i += matrixsize)
            {
                sub = plain.Substring(i, matrixsize);
                vector = createVector(sub);
                res = matrixMultiplication(matrix, vector, matrixsize);
                listOfIntegers.AddRange(res);
            }
            return listOfIntegers;
            //throw new NotImplementedException();
        }
        string convertListToString(List<int> list)
        {
            char[] listtoarray = new char[list.Count];
            for (int i = 0; i < list.Count; i++)
            {
                listtoarray[i] = (char)(list[i] + 'a');
            }
            string converted = new string(listtoarray);
            return converted;
        }
        int getMatrixSize(int len)
        {
            if (len == 9)
                return 3;
            else if (len == 4)
                return 2;
            throw new Exception();
        }
        int[] createVector(string message)
        {
            int[] vector = new int[message.Length];
            for (int i = 0; i < message.Length; i++)
            {
                vector[i] = message[i] - 'a';
            }
            return vector;
        }
        int[,] creatematrix(int len, string key)
        {
            int[,] matrix = new int[len, len];
            int counter = 0;
            for (int i = 0; i < len; i++)
            {
                for (int j = 0; j < len; j++)
                {
                    matrix[i, j] = key[counter] - 'a';
                    counter++;
                }
            }
            return matrix;
        }
        int[] matrixMultiplication(int[,] martix, int[] vector, int len)
        {
            int[] result = new int[len];
            int res;
            for (int i = 0; i < len; i++)
            {
                res = 0;
                for (int j = 0; j < len; j++)
                {
                    res += martix[i, j] * vector[j];
                }
                result[i] = (res + (26 * 5)) % 26;
            }
            return result;
        }
        public string Encrypt(string plainText, string key)
        {
            string message = plainText.ToLower();
            int key_len = key.Length;
            int matrixsize = getMatrixSize(key_len);
            int[] vector;
            int[,] matrix = creatematrix(matrixsize, key);
            char[] res;
            string cypher;
            string sub = "";
            string subcypher = "";
            for (int i = 0; i < message.Length; i += matrixsize)
            {
                sub = message.Substring(i, matrixsize);
                vector = createVector(sub);
                res = matrixMultiplication2(matrix, vector, matrixsize);
                cypher = new string(res);
                subcypher += cypher;
            }
            return subcypher.ToUpper();
            //throw new NotImplementedException();
        }
        char[] matrixMultiplication2(int[,] martix, int[] vector, int len)
        {
            char[] result = new char[len];
            int res;
            for (int i = 0; i < len; i++)
            {
                res = 0;
                for (int j = 0; j < len; j++)
                {
                    res += martix[i, j] * vector[j];
                }
                result[i] = (char)((res % 26) + 'a');
            }
            return result;
        }
        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            int[,] matrix;
            int[,] matrix2;
            int determinant;
            int[,] matrixinverse;
            int v1, v2, v3;
            string plain = convertListToString(plain3);
            string cipher = convertListToString(cipher3);
            getValidMatrix(plain, 9, out determinant, out matrix, out v1, out v2, out v3);
            matrixinverse = getMatrixInverse3By3(matrix, determinant, v1, v2, v3);
            matrix2 = creatematrix1(3, cipher);
            List<int> key = MultiplyMatrices(matrix2, matrixinverse,3);
            return key;
            //throw new NotImplementedException();
        }
        List<int> MultiplyMatrices(int[,] matrix1, int[,] matrix2,int size)
        {
            List<int> key = new List<int>();
            int[,] result = new int[size, size];

            for (int i = 0; i < size; i++)
            {
                for (int j = 0; j < size; j++)
                {
                    int var = 0;

                    for (int k = 0; k < size; k++)
                    {
                        var += matrix1[i, k] * matrix2[k, j];
                    }
                    result[i, j] = var % 26;
                    key.Add(result[i, j]);
                }
            }
            return key;
        }
        int[,] creatematrix1(int len, string key)
        {
            int[,] matrix = new int[len, len];
            int counter = 0;
            for (int j = 0; j < len; j++)
            {
                for (int i = 0; i < len; i++)
                {
                    matrix[i, j] = key[counter] - 'a';
                    counter++;
                }
            }
            return matrix;
        }
        void getValidMatrix(in string plaintext, in int size, out int determinant, out int[,] matrix, out int v1, out int v2, out int v3)
        {
            string key;
            int matrixsize = getMatrixSize(9);
            bool complete;
            for (int i = 0; i <= plaintext.Length - size; i++)
            {
                key = plaintext.Substring(i, size);
                matrix = creatematrix1(matrixsize, key);
                getDeterminant3By3(matrix, out determinant, out v1, out v2, out v3);
                complete = validitaion(matrix, matrixsize, determinant);
                if (complete)
                    return;
            }
            throw new InvalidAnlysisException();
        }
        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }
    }
}

