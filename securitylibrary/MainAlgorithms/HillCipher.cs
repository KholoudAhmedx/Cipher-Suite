﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{

    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {

        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {

            throw new NotImplementedException();
        }
        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }
        
        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            
            throw new NotImplementedException();
        }
        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }


        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            throw new NotImplementedException();
        }
        public string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }


        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {

            throw new NotImplementedException();
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }



    }
}

