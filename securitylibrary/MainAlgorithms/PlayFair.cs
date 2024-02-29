using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public string Decrypt(string cipherText, string key)
        {
            string mainKey = key.ToLower();
            string cypher = cipherText.ToLower();
            char[] unique = new char[26];
            char[,] matrix = new char[5, 5];
            char[] mainKeyarray = mainKey.ToCharArray();
            int counter = 0;
            for (int i = 0; i < mainKey.Length; i++)
            {
                if (mainKeyarray[i] == 'j')
                {
                    mainKeyarray[i] = 'i';
                }
                if (!CharExists(unique, mainKeyarray[i]))
                {
                    unique[counter] = mainKeyarray[i];
                    counter++;
                }
            }
            char character = 'a';
            for (int i = 0; i < 26; i++)
            {
                if (character == 'j')
                {
                    character++;
                    continue;
                }
                if (!CharExists(unique, character))
                {
                    unique[counter] = character;
                    counter++;
                }
                character++;
            }
            int counter2 = 0;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    matrix[i, j] = unique[counter2];
                    counter2++;
                }
            }
            int i1, j1, i2, j2;
            int newp1 = 0;
            int newp2 = 0;
            string back = "";
            for (int i = 0; i < cypher.Length - 1; i += 2)
            {
                char char1 = cypher[i];
                char char2 = cypher[i + 1];
                (i1, j1) = getPosition(matrix, char1);
                (i2, j2) = getPosition(matrix, char2);
                if (i1 == i2)
                {
                    if (j1 == 0)
                    {
                        newp1 = 4;
                    }
                    else
                    {
                        newp1 = (j1 - 1) % 5;
                    }
                    if (j2 == 0)
                    {
                        newp2 = 4;
                    }
                    else
                    {
                        newp2 = (j2 - 1) % 5;
                    }
                    back += matrix[i1, newp1];
                    back += matrix[i2, newp2];
                }
                else if (j1 == j2)
                {
                    if (i1 == 0)
                    {
                        newp1 = 4;
                    }
                    else
                    {
                        newp1 = (i1 - 1) % 5;
                    }
                    if (i2 == 0)
                    {
                        newp2 = 4;
                    }
                    else
                    {
                        newp2 = (i2 - 1) % 5;
                    }
                    back += matrix[newp1, j1];
                    back += matrix[newp2, j2];
                }
                else
                {
                    back += matrix[i1, j2];
                    back += matrix[i2, j1];
                }
            }
            if ((back.Length % 2) == 0 && back.EndsWith("x"))
            {
                back = back.Substring(0, (back.Length) - 1);
            }
                StringBuilder removeX = new StringBuilder(back);
            for (int x = 1; x < removeX.Length; x = x + 2)
            {
                if (removeX[x] == 'x' && removeX[x + 1] == removeX[x - 1])
                {
                    removeX.Remove(x, 1);
                    x = x + 1;
                }
            }
            return removeX.ToString();
        }

        public string Encrypt(string plainText, string key)
        {
            char[,] matrix = new char[5, 5];
            char[] unique = new char[26];
            char[] mainKeyarray = key.ToCharArray();
            int counter = 0;
            for (int i = 0; i < key.Length; i++)
            {
                if (mainKeyarray[i] == 'j')
                {
                    mainKeyarray[i] = 'i';
                }
                if (!CharExists(unique, mainKeyarray[i]))
                {
                    unique[counter] = mainKeyarray[i];
                    counter++;
                }
            }
            char character = 'a';
            for (int i = 0; i < 26; i++)
            {
                if (character == 'j')
                {
                    character++;
                    continue;
                }
                if (!CharExists(unique, character))
                {
                    unique[counter] = character;
                    counter++;
                }
                character++;
            }
            int counter2 = 0;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    matrix[i, j] = unique[counter2];
                    counter2++;
                }
            }
            string newmainPlain = insertXBetweenDuplicates(plainText);
            if ((newmainPlain.Length % 2) != 0)
            {
                newmainPlain += 'x';
            }
            int i1, j1, i2, j2;
            int newp1, newp2;
            string cypher = "";
            for (int i = 0; i < newmainPlain.Length - 1; i += 2)
            {
                char char1 = newmainPlain[i];
                char char2 = newmainPlain[i + 1];
                (i1, j1) = getPosition(matrix, char1);
                (i2, j2) = getPosition(matrix, char2);
                if (i1 == i2)
                {
                    newp1 = (j1 + 1) % 5;
                    newp2 = (j2 + 1) % 5;
                    cypher += matrix[i1, newp1];
                    cypher += matrix[i2, newp2];
                }
                else if (j1 == j2)
                {
                    newp1 = (i1 + 1) % 5;
                    newp2 = (i2 + 1) % 5;
                    cypher += matrix[newp1, j1];
                    cypher += matrix[newp2, j2];
                }
                else
                {
                    cypher += matrix[i1, j2];
                    cypher += matrix[i2, j1];
                }
            }
            return cypher;
        }   
        bool CharExists(char[] array, char character)
        {
            return array.Contains(character);
        }
        public (int, int) getPosition(char[,] matrix, char character)
        {
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (matrix[i, j] == character)
                    {
                        return (i, j);
                    }
                }
            }
            return (-1, -1);
        }
        static string insertXBetweenDuplicates(string word)
        {
            char[] charArray = word.ToCharArray();
            for (int i = 0; i < word.Length - 1; i += 2)
            {
                char char1 = word[i];
                char char2 = word[i + 1];
                if (char1 == char2)
                {
                    word = word.Insert(i + 1, "x");
                }
            }
            return word;
        }
    }
}
