 

namespace L2CCCliente.Bibliotecas
{
    using System;
    using System.Runtime.InteropServices;
    public static class NativeMethods
    {
        [DllImport("L2CCLib.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr StartCapture();

        [DllImport("L2CCLib.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void FreeString(IntPtr str);

        [DllImport("L2CCLib.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern bool StopCapture();

        [DllImport("L2CCLib.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void SetPID(uint pid);

        public static string GetStringFromIntPtr(IntPtr ptr)
        {
            if (ptr == IntPtr.Zero) return null;
            return Marshal.PtrToStringAnsi(ptr);
        }
    }

}
