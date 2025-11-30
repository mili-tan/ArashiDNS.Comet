using ARSoft.Tools.Net;
using ARSoft.Tools.Net.Dns;
using NStack;
using System.Net;
using IPAddress = System.Net.IPAddress;

namespace ArashiDNS.Comet
{
    internal class Program
    {
        public static IPAddress Server = IPAddress.Parse("223.5.5.5");
        public static IPEndPoint ListenerEndPoint = new(IPAddress.Loopback, 23353);
        public static int Timeout = 5000;
        public static TldExtract TldExtractor = new("public_suffix_list.dat");

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

            var nsServerNames = await GetNameServerName(query);
            if (nsServerNames.Count == 0)
            {
                e.Response = query.CreateResponseInstance();
                e.Response.ReturnCode = ReturnCode.NxDomain;
                return;
            }
            var nsServerIPs = await GetNameServerIp(nsServerNames);
            if (nsServerIPs.Count == 0)
            {
                e.Response = query.CreateResponseInstance();
                e.Response.ReturnCode = ReturnCode.NxDomain;
                return;
            }

            var answer = await ResultResolve(nsServerIPs, query);
            //if (answer == null || answer.AnswerRecords.Count == 0)
            //{
            //    nsServerNames = await GetNameServerName(query.Questions.First().Name, nsServerIPs.First());
            //    nsServerIPs = await GetNameServerIp(nsServerNames);
            //    answer = await ResultResolve(nsServerIPs, query);
            //}

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

        private static async Task<List<DomainName>> GetNameServerName(DnsMessage query)
        {
            var name = query.Questions.First().Name;
            //var nsResolve = await new DnsClient(Server, Timeout).ResolveAsync(name, RecordType.Ns);

            var tld = TldExtractor.Extract(name.ToString());
            var rootName = name.LabelCount == 2
                ? name
                : string.IsNullOrWhiteSpace(tld.tld)
                    ? DomainName.Parse(string.Join('.', name.Labels.TakeLast(2)))
                    : DomainName.Parse(tld.root + "." + tld.tld);

            //Console.WriteLine(tld);
            //Console.WriteLine(rootName);

            var nsResolve = await new DnsClient(Server, Timeout).ResolveAsync(rootName, RecordType.Ns);

            return nsResolve?.AnswerRecords.Where(x => x.RecordType == RecordType.Ns)
                .Select(x => ((NsRecord)x).NameServer).ToList() ?? [];
        }

        private static async Task<List<DomainName>> GetNameServerName(DomainName name, IPAddress ipAddress)
        {
            var nsResolve = await new DnsClient(ipAddress, Timeout).ResolveAsync(name, RecordType.Ns);

            return nsResolve?.AnswerRecords.Where(x => x.RecordType == RecordType.Ns)
                .Select(x => ((NsRecord)x).NameServer).ToList() ?? [];
        }


        private static async Task<List<IPAddress>> GetNameServerIp(List<DomainName> nsServerNames)
        {
            var nsIps = new List<IPAddress>();

            await Parallel.ForEachAsync(nsServerNames, async (item, c) =>
            {
                var nsARecords = (await new DnsClient(Server, Timeout).ResolveAsync(item, token: c))?.AnswerRecords ?? [];
                if (nsARecords.Any(x => x.RecordType == RecordType.A))
                    nsIps.AddRange(nsARecords.Where(x => x.RecordType == RecordType.A)
                        .Select(x => ((ARecord) x).Address));
            });

            return nsIps;
        }

        private static async Task<DnsMessage?> ResultResolve(List<IPAddress> nsAddresses, DnsMessage query)
        {
            try
            {
                Console.WriteLine(string.Join(' ',nsAddresses));
                var quest = query.Questions.First();
                var client = new DnsClient(nsAddresses,
                    [new TcpClientTransport(), new UdpClientTransport()],
                    queryTimeout: Timeout);

                var answer = await client.ResolveAsync(quest.Name, quest.RecordType,
                    options: new DnsQueryOptions { EDnsOptions = query.EDnsOptions, IsEDnsEnabled = query.IsEDnsEnabled });
                
                if (answer is {AnswerRecords.Count: 0} &&
                    answer.AuthorityRecords.Any(x => x.RecordType == RecordType.Ns))
                {
                    return await ResultResolve(
                        await GetNameServerIp(answer.AuthorityRecords.Where(x => x.RecordType == RecordType.Ns)
                            .Select(x => ((NsRecord) x).NameServer).ToList()),
                        query);
                }
                if (answer == null || answer.ReturnCode == ReturnCode.Refused || answer.AnswerRecords.Count == 0)
                    answer = await client.ResolveAsync(quest.Name, quest.RecordType) ?? answer;

                return answer;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return null;
            }
        }
    }
}
