using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid 
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        int modolu(int number, int baseN)
        {
            // To handle negative remainders
            int r = number % baseN;
            if (r < 0)
            {
                r += baseN;
            }
            return r;
        }
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            number = modolu(number, baseN);
            long inverse = 0;
            for (long i = 0; i < (long)baseN; i++)
            {
                long GCD = (((long)number * i) % (long)baseN);
                if ( GCD == 1)
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
