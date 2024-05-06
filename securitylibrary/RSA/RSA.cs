using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            long n = p * q;
            long qn = (p - 1) * (q - 1);
            long d = GetMultiplicativeInverse(e, qn);
            long C = (power(M, e, n));
            return (int)C;
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
        public int Decrypt(int p, int q, int C, int e)
        {
            long n = p * q;
            long qn = (p - 1) * (q - 1);
            long d = GetMultiplicativeInverse(e, qn);
            long M = (power(C, d, n));
            return (int)M;
            //throw new NotImplementedException();
        }
    }
}