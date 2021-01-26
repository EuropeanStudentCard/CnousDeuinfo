using SpringCard.LibCs;
using SpringCard.LibCs.Windows;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DueInfo
{
    
    partial class LogManager : IDisposable
    {
        private static ObservableCollection<string> log_fifo = new ObservableCollection<string>();
        static public void InstantiateLogManager()
        {
            bool singleInstance = AppUtils.IsSingleInstance("SPRINGCARDLOG");

            if (!singleInstance)
            {

            }
            else
            {
                log_fifo.CollectionChanged += new System.Collections.Specialized.NotifyCollectionChangedEventHandler(
                delegate (object sender, System.Collections.Specialized.NotifyCollectionChangedEventArgs e)
                {
                    if (e.Action == System.Collections.Specialized.NotifyCollectionChangedAction.Add)
                    {
                        LogCompletionCallback();
                    }
                }
            );
            }
        }
        ~LogManager()
        {
            AppUtils.ReleaseInstance();
        }
        #region dispose
        public void Dispose()
        {
            //throw new NotImplementedException();

            AppUtils.ReleaseInstance();
        }


        #endregion

        static public void DoLogOperation(string log_to_add)
        {
            lock (log_fifo)
            {
                if (log_fifo != null)
                {
                    log_fifo.Add(log_to_add);
                }
            }
        }

        static private void LogCompletionCallback()
        {
            lock(log_fifo)
            {
                for (int i = 0; i < log_fifo.Count; i++)
                {
                    if (log_fifo[i].Contains("[WARNING]"))
                        Logger.Warning("{0} ...", log_fifo[i]);
                    if (log_fifo[i].Contains("[DEBUG]"))
                        Logger.Debug("{0} ...", log_fifo[i]);
                    if (log_fifo[i].Contains("[ERROR]"))
                        Logger.Error("{0} ...", log_fifo[i]);
                    if (log_fifo[i].Contains("[INFO]"))
                        Logger.Info("{0} ...", log_fifo[i]);

                    Console.WriteLine("{0} ...", log_fifo[i]);

                }
                log_fifo.Clear();
            }
        }
        
    }
}
