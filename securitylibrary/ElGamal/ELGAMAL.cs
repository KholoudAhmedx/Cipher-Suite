using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        /// 

        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            List<long> result = new List<long>();
            long C1 = power(alpha, k, q);
            result.Add(C1);
            long K = power(y, k, q);
            long C2 = (K * m) % q;
            result.Add(C2);
            return result;
        }
        long power(long b, long n, long m)
        {
            long result = 1;
            for (int i = 0; i < n; i++)
            {
                result *= b;
                result %= m;
            }
            return result;
        }


        public int Decrypt(int c1, int c2, int x, int q)
        {
            long K = power(c1, x, q);
            int inK = GetMultiplicativeInverse(K, q);
            int p = (c2 * inK) % q;
            return p;

        }
        long modolu(long number, long baseN)
        {
            // To handle negative remainders
            long r = number % baseN;
            if (r < 0)
            {
                r += baseN;
            }
            return r;
        }
        int GetMultiplicativeInverse(long number, long baseN)
        {
            number = modolu(number, baseN);
            long inverse = 0;
            for (long i = 0; i < (long)baseN; i++)
            {
                long GCD = (((long)number * i) % (long)baseN);
                if (GCD == 1)
                {
                    inverse = i;
                    break;
                }
                else
                {
                    inverse = -1;
                }
            }
            return (int)inverse;
        }
    }
}