using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace L2CCCliente.Bibliotecas
{
    public class PacketModel
    {
        public uint Sequence { get; set; }
        public string Timestamp { get; set; }
        public string Source { get; set; }
        public string Destination { get; set; }
        public uint Size { get; set; }
        public byte Opcode { get; set; }
        public string Direction { get; set; }
        public string ServerType { get; set; }
        public string Description { get; set; }
    }
}
