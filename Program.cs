using ARSoft.Tools.Net;
using ARSoft.Tools.Net.Dns;
using NStack;
using System.Net;
using DeepCloner.Core;
using IPAddress = System.Net.IPAddress;

namespace ArashiDNS.Comet
{
    internal class Program
    {
        public static IPAddress Server = IPAddress.Parse("223.5.5.5");
        public static IPEndPoint ListenerEndPoint = new(IPAddress.Loopback, 23353);
        public static int Timeout = 1000;
        public static TldExtract TldExtractor = new("./public_suffix_list.dat");

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

            var answer = await DoResolve(query);

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
            }
        }

        private static async Task<DnsMessage?> DoResolve(DnsMessage query, int cnameDepth = 0)
        {
            var answer = query.CreateResponseInstance();

            var nsServerNames = await GetNameServerName(query.Questions.First());
            if (nsServerNames.Count == 0)
            {
                answer.ReturnCode = ReturnCode.NxDomain;
                return answer;
            }

            var nsServerIPs = await GetNameServerIp(nsServerNames);
            if (nsServerIPs.Count == 0)
            {
                answer.ReturnCode = ReturnCode.NxDomain;
                return answer;
            }

            answer = await ResultResolve(nsServerIPs, query);

            if (answer != null && answer.AnswerRecords.Count != 0 &&
                answer.AnswerRecords.All(x => x.RecordType == RecordType.CName) && cnameDepth <= 20)
            {
                var copyQuery = query.DeepClone();
                copyQuery.Questions.Clear();
                copyQuery.Questions.Add(new DnsQuestion(
                    ((CNameRecord) answer.AnswerRecords.LastOrDefault(x => x.RecordType == RecordType.CName)!)
                    .CanonicalName,
                    query.Questions.First().RecordType,
                    query.Questions.First().RecordClass));
                var cnameAnswer = await DoResolve(copyQuery, cnameDepth + 1);
                if (cnameAnswer is {AnswerRecords.Count: > 0})
                    answer.AnswerRecords.AddRange(cnameAnswer.AnswerRecords);
            }

            //if (answer == null || answer.AnswerRecords.Count == 0)
            //{
            //    nsServerNames = await GetNameServerName(query.Questions.First().Name, nsServerIPs.First());
            //    nsServerIPs = await GetNameServerIp(nsServerNames);
            //    answer = await ResultResolve(nsServerIPs, query);
            //}

            return answer;
        }

        private static async Task<List<DomainName>> GetNameServerName(DnsQuestion query)
        {
            var name = query.Name;
            var tld = TldExtractor.Extract(name.ToString().Trim('.'));
            var rootName = name.LabelCount == 2
                ? name
                : string.IsNullOrWhiteSpace(tld.tld)
                    ? DomainName.Parse(string.Join('.', name.Labels.TakeLast(2)))
                    : DomainName.Parse(tld.root + "." + tld.tld);

            //Console.WriteLine(tld);

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
                //Console.WriteLine(string.Join(' ', nsAddresses));

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
