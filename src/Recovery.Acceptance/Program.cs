using Recovery.Acceptance;
using System.Text;

Console.OutputEncoding = Encoding.UTF8;
Console.InputEncoding = Encoding.UTF8;
var interactive = args.Length == 0;

try
{
    var arguments = args.ToList();
    if (arguments.Count == 0)
    {
        Console.WriteLine("雨痕恢复验收工具");
        Console.WriteLine("1. 生成标准测试文件集");
        Console.WriteLine("2. 验收恢复结果");
        Console.Write("请选择 1 或 2：");
        var choice = Console.ReadLine()?.Trim();
        if (choice == "1")
        {
            Console.Write("请输入测试文件集目录（必须为空或不存在）：");
            arguments.AddRange(["generate", Console.ReadLine()?.Trim() ?? string.Empty]);
        }
        else if (choice == "2")
        {
            Console.Write("请输入验收清单 JSON 路径：");
            var manifest = Console.ReadLine()?.Trim() ?? string.Empty;
            Console.Write("请输入雨痕恢复输出目录：");
            var recovered = Console.ReadLine()?.Trim() ?? string.Empty;
            Console.Write("请输入报告目录（直接回车自动创建）：");
            var report = Console.ReadLine()?.Trim();
            arguments.AddRange(["verify", manifest, recovered]);
            if (!string.IsNullOrWhiteSpace(report)) arguments.Add(report);
        }
        else
        {
            PrintHelp();
            WaitForExitIfInteractive(interactive);
            return 1;
        }
    }

    switch (arguments[0].ToLowerInvariant())
    {
        case "generate" when arguments.Count == 2:
        {
            var result = await AcceptanceCaseService.GenerateAsync(arguments[1]);
            Console.WriteLine($"生成完成：{result.Manifest.Files.Count:N0} 个文件，{result.Manifest.Files.Sum(file => file.Length):N0} 字节");
            Console.WriteLine($"待复制目录：{result.ContentDirectory}");
            Console.WriteLine($"验收清单：{result.ManifestPath}");
            Console.WriteLine("下一步：把“待复制文件”中的内容复制到测试介质，再执行删除或格式化测试。");
            WaitForExitIfInteractive(interactive);
            return 0;
        }
        case "verify" when arguments.Count is 3 or 4:
        {
            var result = await AcceptanceCaseService.VerifyAsync(arguments[1], arguments[2],
                arguments.Count == 4 ? arguments[3] : null);
            Console.WriteLine($"验收完成：完整 {result.Report.Summary.ContentRecovered:N0}/{result.Report.Summary.Expected:N0}，" +
                              $"原名 {result.Report.Summary.OriginalNameRecovered:N0}，损坏 {result.Report.Summary.Damaged:N0}，" +
                              $"缺失 {result.Report.Summary.Missing:N0}，额外 {result.Report.Summary.Extra:N0}");
            Console.WriteLine($"Markdown 报告：{result.MarkdownPath}");
            Console.WriteLine($"JSON 报告：{result.JsonPath}");
            Console.WriteLine($"CSV 报告：{result.CsvPath}");
            WaitForExitIfInteractive(interactive);
            return result.Report.Summary.ContentRecovered == result.Report.Summary.Expected ? 0 : 2;
        }
        case "help" or "--help" or "-h":
            PrintHelp();
            return 0;
        default:
            PrintHelp();
            return 1;
    }
}
catch (Exception exception)
{
    Console.Error.WriteLine($"操作失败：{exception.Message}");
    WaitForExitIfInteractive(interactive);
    return 1;
}

static void PrintHelp()
{
    Console.WriteLine("用法：");
    Console.WriteLine("  雨痕恢复验收工具.exe generate <测试文件集目录>");
    Console.WriteLine("  雨痕恢复验收工具.exe verify <验收清单.json> <恢复输出目录> [报告目录]");
}

static void WaitForExitIfInteractive(bool interactive)
{
    if (!interactive) return;
    Console.WriteLine();
    Console.Write("按回车键退出…");
    Console.ReadLine();
}
