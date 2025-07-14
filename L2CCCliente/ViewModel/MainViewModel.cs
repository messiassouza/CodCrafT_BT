using L2CCCliente.Bibliotecas;
using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Net.Sockets;
using System.Text;
using System.Text.Json; // For JSON parsing
using System.Threading;
using System.Windows;
using System.Windows.Input;

namespace L2CCCliente.ViewModel
{
    public class MainViewModel : ObservableObject
    {
        private ObservableCollection<string> _messages;
        private ObservableCollection<PacketModel> _packets;
        private ObservableCollection<Process> _processes;
        private bool _isCapturing;
        private TcpClient _tcpClient;
        private NetworkStream _stream;
        private Thread _receiveThread;
        private Process _selectedProcess;
        private string _opcodeFilter;

        public ObservableCollection<string> Messages { get => _messages; set { _messages = value; RaisePropertyChanged(nameof(Messages)); } }
        public ObservableCollection<PacketModel> Packets { get => _packets; set { _packets = value; RaisePropertyChanged(nameof(Packets)); } }
        public ObservableCollection<Process> Processes { get => _processes; set { _processes = value; RaisePropertyChanged(nameof(Processes)); } }
        public Process SelectedProcess { get => _selectedProcess; set { _selectedProcess = value; RaisePropertyChanged(nameof(SelectedProcess)); } }
        public bool IsCapturing { get => _isCapturing; set { _isCapturing = value; RaisePropertyChanged(nameof(IsCapturing)); } }
        public string OpcodeFilter { get => _opcodeFilter; set { _opcodeFilter = value; RaisePropertyChanged(nameof(OpcodeFilter)); ; } }  // Para filtro futuro

        public ICommand LoadProcessesCommand { get; }
        public ICommand StartCaptureCommand { get; }
        public ICommand StopCaptureCommand { get; }

        public MainViewModel()
        {
            Messages = new ObservableCollection<string>();
            Packets = new ObservableCollection<PacketModel>();
            Processes = new ObservableCollection<Process>();
            LoadProcessesCommand = new RelayCommand(LoadProcesses);
            StartCaptureCommand = new RelayCommand(StartCapture, () => !IsCapturing && SelectedProcess != null);
            StopCaptureCommand = new RelayCommand(StopCapture, () => IsCapturing);
        }

        private void LoadProcesses()
        {
            Processes.Clear();
            var l2Processes = Process.GetProcessesByName("l2");
            foreach (var proc in l2Processes)
            {
                Processes.Add(proc);
            }
        }

        private void StartCapture()
        {
            try
            {
                if (!System.IO.File.Exists("L2CCLib.dll"))
                {
                    MessageBox.Show("L2CCLib.dll não encontrado.", "Erro", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                NativeMethods.SetPID((uint)SelectedProcess.Id);

                IntPtr resultPtr = NativeMethods.StartCapture();
                string result = NativeMethods.GetStringFromIntPtr(resultPtr);
                NativeMethods.FreeString(resultPtr);

                if (result == "DLL respondendo")
                {
                    _tcpClient = new TcpClient();
                    _tcpClient.Connect("127.0.0.1", 12345);
                    _stream = _tcpClient.GetStream();
                    _receiveThread = new Thread(ReceiveMessages);
                    _receiveThread.IsBackground = true;
                    _receiveThread.Start();

                    IsCapturing = true;
                    Messages.Add("Captura iniciada para PID: " + SelectedProcess.Id);
                }
                else
                {
                    MessageBox.Show($"Falha ao iniciar captura: {result}", "Erro", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Erro ao iniciar captura: {ex.Message}", "Erro", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void StopCapture()
        {
            try
            {
                if (!NativeMethods.StopCapture())
                {
                    MessageBox.Show("Falha ao parar captura. Verifique packets.log para detalhes.", "Erro", MessageBoxButton.OK, MessageBoxImage.Error);
                }

                IsCapturing = false;
                if (_stream != null)
                {
                    _stream.Close();
                    _stream = null;
                }
                if (_tcpClient != null)
                {
                    _tcpClient.Close();
                    _tcpClient = null;
                }
                if (_receiveThread != null)
                {
                    _receiveThread.Join(1000);
                    _receiveThread = null;
                }
                Application.Current.Dispatcher.Invoke(() => Messages.Add("Captura parada."));
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Erro ao parar captura: {ex.Message}", "Erro", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ReceiveMessages()
        {
            try
            {
                byte[] buffer = new byte[4096];
                StringBuilder messageBuilder = new StringBuilder();
                while (_tcpClient?.Connected == true)
                {
                    int bytesRead = _stream.Read(buffer, 0, buffer.Length);
                    if (bytesRead == 0) break;

                    string data = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                    messageBuilder.Append(data);

                    string fullData = messageBuilder.ToString();
                    int lastNewline = 0;
                    while (true)
                    {
                        if (string.IsNullOrEmpty(fullData.Trim())) break; // No more complete lines

                        lastNewline = fullData.IndexOf('\n', lastNewline);
                        if (lastNewline == -1) break; // No more complete lines

                        string line = fullData.Substring(0, lastNewline).Trim();
                        if (!string.IsNullOrEmpty(line))
                        {
                            Application.Current.Dispatcher.Invoke(() => Messages.Add(line));

                            if (line.StartsWith("[") && line.Contains("Pacote capturado"))
                            {
                                // Safe parsing for PacketModel
                                try
                                {
                                    // Log the full line for debug
                                    Application.Current.Dispatcher.Invoke(() => Messages.Add("Parsing line: " + line));

                                    // Example line: "[seq][time] Pacote capturado (direction, tamanho: bufferLen bytes, payload: dataLen bytes, servidor: serverType)"
                                    // Opcode: 0xopcode Fonte: src Destino: dst
                                    // Descrição: desc
                                    int seqStart = line.IndexOf('[') + 1;
                                    if (seqStart == 0)
                                    {
                                        Application.Current.Dispatcher.Invoke(() => Messages.Add("Debug: seqStart invalid"));
                                        continue; // Invalid
                                    }
                                    int seqEnd = line.IndexOf(']', seqStart);
                                    if (seqEnd == -1)
                                    {
                                        Application.Current.Dispatcher.Invoke(() => Messages.Add("Debug: seqEnd not found"));
                                        continue;
                                    }
                                    string seqStr = line.Substring(seqStart, seqEnd - seqStart);
                                    uint seq = uint.Parse(seqStr);

                                    int timeStart = line.IndexOf('[', seqEnd + 1) + 1;
                                    if (timeStart == 0)
                                    {
                                        Application.Current.Dispatcher.Invoke(() => Messages.Add("Debug: timeStart invalid"));
                                        continue;
                                    }
                                    int timeEnd = line.IndexOf(']', timeStart);
                                    if (timeEnd == -1)
                                    {
                                        Application.Current.Dispatcher.Invoke(() => Messages.Add("Debug: timeEnd not found"));
                                        continue;
                                    }
                                    string timestamp = line.Substring(timeStart, timeEnd - timeStart);

                                    // Parse direction
                                    int directionStart = line.IndexOf('(', timeEnd) + 1;
                                    if (directionStart == 0)
                                    {
                                        Application.Current.Dispatcher.Invoke(() => Messages.Add("Debug: directionStart invalid"));
                                        continue;
                                    }
                                    int directionEnd = line.IndexOf(',', directionStart);
                                    if (directionEnd == -1)
                                    {
                                        Application.Current.Dispatcher.Invoke(() => Messages.Add("Debug: directionEnd not found"));
                                        continue;
                                    }
                                    string direction = line.Substring(directionStart, directionEnd - directionStart).Trim();

                                    // Parse tamanho
                                    int sizeStart = line.IndexOf("tamanho: ", directionEnd) + 9;
                                    if (sizeStart == 9)
                                    {
                                        Application.Current.Dispatcher.Invoke(() => Messages.Add("Debug: sizeStart invalid"));
                                        continue;
                                    }
                                    int sizeEnd = line.IndexOf(" bytes", sizeStart);
                                    if (sizeEnd == -1)
                                    {
                                        Application.Current.Dispatcher.Invoke(() => Messages.Add("Debug: sizeEnd not found"));
                                        continue;
                                    }
                                    string sizeStr = line.Substring(sizeStart, sizeEnd - sizeStart);
                                    uint size = uint.Parse(sizeStr);

                                    // Parse payload
                                    int payloadStart = line.IndexOf("payload: ", sizeEnd) + 9;
                                    if (payloadStart == 9)
                                    {
                                        Application.Current.Dispatcher.Invoke(() => Messages.Add("Debug: payloadStart invalid"));
                                        continue;
                                    }
                                    int payloadEnd = line.IndexOf(" bytes", payloadStart);
                                    if (payloadEnd == -1)
                                    {
                                        Application.Current.Dispatcher.Invoke(() => Messages.Add("Debug: payloadEnd not found"));
                                        continue;
                                    }
                                    string payloadStr = line.Substring(payloadStart, payloadEnd - payloadStart);
                                    uint payload = uint.Parse(payloadStr);

                                    // Parse servidor
                                    int serverTypeStart = line.IndexOf("servidor: ", payloadEnd) + 10;
                                    if (serverTypeStart == 10)
                                    {
                                        Application.Current.Dispatcher.Invoke(() => Messages.Add("Debug: serverTypeStart invalid"));
                                        continue;
                                    }
                                    int serverTypeEnd = line.IndexOf(')', serverTypeStart);
                                    if (serverTypeEnd == -1)
                                    {
                                        Application.Current.Dispatcher.Invoke(() => Messages.Add("Debug: serverTypeEnd not found"));
                                        continue;
                                    }
                                    string serverType = line.Substring(serverTypeStart, serverTypeEnd - serverTypeStart).Trim();

                                    // Parse opcode
                                    int opcodeStart = line.IndexOf("Opcode: 0x", serverTypeEnd) + 10;
                                    if (opcodeStart == 9)
                                    {
                                        Application.Current.Dispatcher.Invoke(() => Messages.Add("Debug: opcodeStart invalid"));
                                        continue;
                                    }
                                    int opcodeEnd = line.IndexOf(" Fonte: ", opcodeStart);
                                    if (opcodeEnd == -1)
                                    {
                                        Application.Current.Dispatcher.Invoke(() => Messages.Add("Debug: opcodeEnd not found"));
                                        continue;
                                    }
                                    string opcodeStr = line.Substring(opcodeStart, opcodeEnd - opcodeStart);
                                    byte opcode = byte.Parse(opcodeStr, System.Globalization.NumberStyles.HexNumber);

                                    // Parse source
                                    int sourceStart = opcodeEnd + 8;
                                    int sourceEnd = line.IndexOf(" Destino: ", sourceStart);
                                    if (sourceEnd == -1)
                                    {
                                        Application.Current.Dispatcher.Invoke(() => Messages.Add("Debug: sourceEnd not found"));
                                        continue;
                                    }
                                    string source = line.Substring(sourceStart, sourceEnd - sourceStart);

                                    // Parse destination
                                    int destStart = sourceEnd + 10;
                                    int destEnd = line.IndexOf("Descrição: ", destStart);
                                    if (destEnd == -1)
                                    {
                                        destEnd = line.Length;
                                        Application.Current.Dispatcher.Invoke(() => Messages.Add("Debug: desc not found, using end of line"));
                                    }
                                    string destination = line.Substring(destStart, destEnd - destStart).Trim();

                                    // Parse description
                                    string description = "";
                                    if (destEnd != line.Length)
                                    {
                                        description = line.Substring(destEnd + 11).Trim();
                                    }

                                    PacketModel packet = new PacketModel
                                    {
                                        Sequence = seq,
                                        Timestamp = timestamp,
                                        Source = source,
                                        Destination = destination,
                                        Size = size,
                                        Opcode = opcode,
                                        Direction = direction,
                                        ServerType = serverType,
                                        Description = description
                                    };
                                    Application.Current.Dispatcher.Invoke(() => Packets.Add(packet));
                                }
                                catch (Exception parseEx)
                                {
                                    Application.Current.Dispatcher.Invoke(() => Messages.Add("Erro ao parsear linha: " + line + " - " + parseEx.Message));
                                }
                            }
                            else if (line.StartsWith("Ping:"))
                            {
                                string pongMessage = $"Pong: {DateTime.Now:yyyy-MM-dd HH:mm:ss}\n";
                                byte[] pongBytes = Encoding.UTF8.GetBytes(pongMessage);
                                _stream.Write(pongBytes, 0, pongBytes.Length);
                                Application.Current.Dispatcher.Invoke(() => Messages.Add(pongMessage.Trim()));
                            }
                        }
                        fullData = fullData.Substring(lastNewline + 1);
                    }
                    messageBuilder.Clear();
                    messageBuilder.Append(fullData);
                }
            }
            catch (Exception ex)
            {
                if (IsCapturing)
                {
                    Application.Current.Dispatcher.Invoke(() => {
                        MessageBox.Show($"Erro na recepção de mensagens: {ex.Message}", "Erro", MessageBoxButton.OK, MessageBoxImage.Error);
                    });
                }
            }
        }

    }

    public class RelayCommand : ICommand
    {
        private readonly Action _execute;
        private readonly Func<bool> _canExecute;

        public RelayCommand(Action execute, Func<bool> canExecute = null)
        {
            _execute = execute;
            _canExecute = canExecute;
        }

        public bool CanExecute(object parameter) => _canExecute?.Invoke() ?? true;
        public void Execute(object parameter) => _execute();
        public event EventHandler CanExecuteChanged
        {
            add { CommandManager.RequerySuggested += value; }
            remove { CommandManager.RequerySuggested -= value; }
        }
    }
}

// Classe auxiliar para comandos
public class RelayCommand : ICommand
{
    private readonly Action _execute;
    private readonly Func<bool> _canExecute;

    public RelayCommand(Action execute, Func<bool> canExecute = null)
    {
        _execute = execute;
        _canExecute = canExecute;
    }

    public bool CanExecute(object parameter) => _canExecute?.Invoke() ?? true;
    public void Execute(object parameter) => _execute();
    public event EventHandler CanExecuteChanged
    {
        add { CommandManager.RequerySuggested += value; }
        remove { CommandManager.RequerySuggested -= value; }
    }
}