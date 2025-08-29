using ARSoft.Tools.Net.Dns;
using Org.BouncyCastle.Tls;
using System.Net;
using ARSoft.Tools.Net;
using NStack;

namespace ArashiDNS.Comet
{
    internal class Program
    {
        public static IPAddress Server = IPAddress.Parse("223.5.5.5");
        public static IPEndPoint ListenerEndPoint = new(IPAddress.Loopback, 23353);
        public static int Timeout = 5000;
        public static TldExtract TldExtractor = new();

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

            var nsServerNames = await NameServerResolve(query);
            if (nsServerNames.Count == 0)
            {
                e.Response = query.CreateResponseInstance();
                e.Response.ReturnCode = ReturnCode.NxDomain;
                return;
            }

            var answer = await ResultResolve(nsServerNames, query);
            if (answer == null)
            {
                e.Response = query.CreateResponseInstance();
                e.Response.ReturnCode = ReturnCode.ServerFailure;
            }
            else
            {
                var response = query.CreateResponseInstance();
                response.ReturnCode = answer.ReturnCode;
                response.IsRecursionAllowed = true;
                response.IsRecursionDesired = true;
                response.AnswerRecords.AddRange(answer.AnswerRecords);
                e.Response = response;

                //answer.TransactionID = query.TransactionID;
                //e.Response = answer;
            }
        }

        private static async Task<List<DomainName>> NameServerResolve(DnsMessage query)
        {
            var name = query.Questions.First().Name;
            //var nsResolve = await new DnsClient(Server, Timeout).ResolveAsync(name, RecordType.Ns);

            var tld = TldExtractor.Extract(name.ToString());
            var rootName = string.IsNullOrWhiteSpace(tld.tld)
                ? name.GetParentName()
                : DomainName.Parse(tld.root + "." + tld.tld);
            var nsResolve = await new DnsClient(Server, Timeout).ResolveAsync(rootName, RecordType.Ns);

            return nsResolve?.AnswerRecords.Where(x => x.RecordType == RecordType.Ns)
                .Select(x => ((NsRecord)x).NameServer).ToList() ?? [];
        }

        private static async Task<DnsMessage?> ResultResolve(List<DomainName> nsServerNames, DnsMessage query)
        {
            try
            {
                var quest = query.Questions.First();

                foreach (var item in nsServerNames)
                {
                    var nsARecords = (await new DnsClient(Server, Timeout).ResolveAsync(item))?.AnswerRecords ?? [];
                    var nsAddresses = nsARecords.Where(x => x.RecordType == RecordType.A).Select(x => ((ARecord)x).Address);

                    foreach (var address in nsAddresses)
                    {
                        var answer = await new DnsClient(address, Timeout).ResolveAsync(quest.Name, quest.RecordType,
                            options: new DnsQueryOptions { EDnsOptions = query.EDnsOptions, IsEDnsEnabled = query.IsEDnsEnabled });
                        if (answer == null || answer.ReturnCode == ReturnCode.ServerFailure) continue;

                        if (answer.ReturnCode == ReturnCode.Refused || answer.AnswerRecords.Count == 0)
                            answer = await new DnsClient(address, Timeout).ResolveAsync(quest.Name, quest.RecordType) ?? answer;
                        return answer;
                    }
                }
                return null;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return null;
            }
        }
    }
}
