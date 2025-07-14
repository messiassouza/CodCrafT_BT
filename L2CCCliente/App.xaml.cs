using L2CCCliente.ViewModel;
using System.Configuration;
using System.Data;
using System.Security.Principal;
using System.Windows;

namespace L2CCCliente
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            if (!IsRunningAsAdministrator())
            {
                MessageBox.Show("Esta aplicação requer privilégios administrativos para capturar pacotes.", "Erro", MessageBoxButton.OK, MessageBoxImage.Error);
                Shutdown();
                return;
            }

            var mainWindow = new View.Main
            {
                DataContext = new   ViewModel.MainViewModel()
            };
            mainWindow.Show();
            MainWindow = mainWindow;
        }

        private bool IsRunningAsAdministrator()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }
    }

}
