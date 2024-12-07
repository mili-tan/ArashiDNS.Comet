using ARSoft.Tools.Net.Dns;
using System.Net;

namespace ArashiDNS.Comet
{
    internal class Program
    {
        public static IPAddress Server = IPAddress.Parse("223.5.5.5");
        public static IPEndPoint ListenerEndPoint = new(IPAddress.Loopback, 23353);

        static void Main(string[] args)
        {
            var dnsServer = new DnsServer(new UdpServerTransport(ListenerEndPoint),
                new TcpServerTransport(ListenerEndPoint));
            dnsServer.QueryReceived += DnsServerOnQueryReceived;
            dnsServer.Start();

            Console.WriteLine("Now listening on: " + ListenerEndPoint);
            Console.WriteLine("Application started. Press Ctrl+C / q to shut down.");
            if (!Console.IsInputRedirected && Console.KeyAvailable)
            {
                while (true)
                    if (Console.ReadKey().KeyChar == 'q')
                        Environment.Exit(0);
            }

            EventWaitHandle wait = new AutoResetEvent(false);
            while (true) wait.WaitOne();
        }

        private static async Task DnsServerOnQueryReceived(object sender, QueryReceivedEventArgs e)
        {
            if (e.Query is not DnsMessage query || query.Questions.Count == 0) return;
            var quest = query.Questions.First();
            var nsRecord = new DnsClient(Server, 10000).Resolve(quest.Name, RecordType.Ns).AnswerRecords.First();
            var nsServerName = ((NsRecord)nsRecord).NameServer;

            var nsARecord = new DnsClient(Server, 10000).Resolve(nsServerName)?.AnswerRecords.First();
            var nsAddress = ((ARecord)nsARecord).Address;

            var answer = await new DnsClient(nsAddress, 10000).ResolveAsync(quest.Name, quest.RecordType,
                options: new DnsQueryOptions() {EDnsOptions = query.EDnsOptions, IsEDnsEnabled = query.IsEDnsEnabled});
            
            var response = query.CreateResponseInstance();
            response.ReturnCode = answer.ReturnCode;
            response.IsRecursionAllowed = true;
            response.IsRecursionDesired = true;
            response.AnswerRecords.AddRange(answer.AnswerRecords);
            e.Response = response;
        }
    }
}
