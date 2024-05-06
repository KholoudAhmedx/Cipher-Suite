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

            throw new NotImplementedException();
        }

        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            List<int> keys = new List<int>();
            long ya = 1;
            long yb = 1;
            long ka = 1;
            long kb = 1;
            for (int i = 0; i < xa; i++) {
                ya *= alpha;
                ya = ya % q;
            }
           
            for (int i = 0; i < xb; i++) { 
                yb *= alpha;
                yb = yb % q;
            }
            
            for (int i = 0; i < xa; i++) {
                ka *= yb;
                ka = ka % q;
            }
            
            for (int i = 0; i < xb; i++) {
                kb *= ya;
                kb = kb % q;
            } 

            keys.Add((int)ka);
            keys.Add((int)kb);

            return keys;
            //#throw new NotImplementedException();
        }
    }
}