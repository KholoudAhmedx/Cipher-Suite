using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace SecurityLibrary.DiffieHellman
{


    public class DiffieHellman
    {

        public int power(int f, int s, int sf)
        {
            
            int result = 1;

            for (int i = 0; i < s; i++)
            {
                result *= f;
                result = result % sf;
            }
            return result;
        }

        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            List<int> keys = new List<int>();

            int ya, yb, ka, kb;
            ya = power(alpha, xa, q);
            yb = power(alpha, xb, q);
            ka = power(yb, xa, q);
            kb = power(ya, xb, q);

            keys.Add((int)ka);
            keys.Add((int)kb);

            return keys;
            //#throw new NotImplementedException();
        }
    }
}