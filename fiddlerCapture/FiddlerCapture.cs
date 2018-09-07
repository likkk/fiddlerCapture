using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace fiddlerCapture
{
    class FiddlerCapture
    {
        private static Capture m_capture = null;
        public static void Main(string[] args)
        {
            Console.WriteLine("FiddlerCapture is startup");
            Console.SetWindowSize(120, 50);
            m_capture = new Capture();
            Console.Read();
        }

    }
}
