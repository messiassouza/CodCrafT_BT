using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace L2CCCliente.Bibliotecas
{
    public static class Help
    {


    }





    [Serializable]
    public abstract class ObservableObject : INotifyPropertyChanged
    {
        #region Debugging Aides
        [Conditional("DEBUG")]
        [DebuggerStepThrough]
        public virtual void VerifyPropertyName(string propertyName)
        {
            if (TypeDescriptor.GetProperties(this)[propertyName] == null)
            {
                string msg = "Invalid property name: " + propertyName;
                if (this.ThrowOnInvalidPropertyName)
                    throw new Exception(msg);
                else
                    Debug.Fail(msg);
            }
        }

        protected virtual bool ThrowOnInvalidPropertyName { get; private set; }
        #endregion

        #region INotifyPropertyChanged Members
        public virtual void RaisePropertyChanged(string propertyName)
        {
            this.VerifyPropertyName(propertyName);
            OnPropertyChanged(propertyName);
        }

        public event PropertyChangedEventHandler PropertyChanged;

        protected virtual void OnPropertyChanged(string propertyName)
        {
            this.VerifyPropertyName(propertyName);
            PropertyChangedEventHandler handler = this.PropertyChanged;
            if (handler != null)
            {
                var e = new PropertyChangedEventArgs(propertyName);
                handler(this, e);
            }
        }
        #endregion
    }
}
