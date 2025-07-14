using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace L2CCCliente.Bibliotecas
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public struct PacketInfo
    {
        public byte opcode;
        [MarshalAs(UnmanagedType.Bool)]
        public bool isInbound;
        public uint packetSize;
        public uint sequence;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string timestamp;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 16)]
        public string sourceIp;
        public ushort sourcePort;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 16)]
        public string destIp;
        public ushort destPort;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 16)]
        public string serverType;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string description;
    }
}
