using System.Windows;
using System.Windows.Threading;

namespace Recovery.App;

public partial class App : Application
{
    public App()
    {
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
        {
            if (args.ExceptionObject is Exception exception) AppDiagnostics.WriteException("AppDomain", exception);
            else AppDiagnostics.Write($"UNHANDLED AppDomain object: {args.ExceptionObject}");
        };
        TaskScheduler.UnobservedTaskException += (_, args) => AppDiagnostics.WriteException("TaskScheduler", args.Exception);
        AppDiagnostics.Write("Application starting.");
    }

    private static void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs args) =>
        AppDiagnostics.WriteException("WPF Dispatcher", args.Exception);
}
