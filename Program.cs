using ARSoft.Tools.Net;
using ARSoft.Tools.Net.Dns;
using NStack;
using System.Net;
using DeepCloner.Core;
using IPAddress = System.Net.IPAddress;
using System.Collections.Concurrent;

namespace ArashiDNS.Comet
{
    internal class Program
    {
        public static IPAddress Server = IPAddress.Parse("223.5.5.5");
        public static IPEndPoint ListenerEndPoint = new(IPAddress.Loopback, 23353);
        public static int Timeout = 1000;
        public static TldExtract TldExtractor = new("./public_suffix_list.dat");

        public static Timer CacheCleanupTimer;
        public class CacheItem<T>
        {
            public T Value { get; set; }
            public DateTime ExpiryTime { get; set; }
            public bool IsExpired => DateTime.UtcNow >= ExpiryTime;
        }

        public static ConcurrentDictionary<string, CacheItem<DnsMessage>> DnsResponseCache = new();
        public static ConcurrentDictionary<string, CacheItem<DnsMessage>> NsQueryCache = new();

        static void Main(string[] args)
        {
            CleanupCacheTask();

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

        private static void CleanupCacheTask()
        {
            CacheCleanupTimer = new Timer(_ =>
            {
                try
                {
                    var expiredDnsKeys = DnsResponseCache.Where(kv => kv.Value.IsExpired)
                        .Select(kv => kv.Key).ToList();
                    foreach (var key in expiredDnsKeys) DnsResponseCache.TryRemove(key, out var _);

                    var expiredNsKeys = NsQueryCache.Where(kv => kv.Value.IsExpired)
                        .Select(kv => kv.Key).ToList();
                    foreach (var key in expiredNsKeys) NsQueryCache.TryRemove(key, out var _);

                    if (expiredDnsKeys.Any() || expiredNsKeys.Any())
                        Console.WriteLine($"Cache cleanup: {expiredDnsKeys.Count} DNS entries, " +
                                          $"{expiredNsKeys.Count} NS entries removed.");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Cache cleanup error: {ex.Message}");
                }
            }, null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(5));
        }

        private static async Task DnsServerOnQueryReceived(object sender, QueryReceivedEventArgs e)
        {
            if (e.Query is not DnsMessage query || query.Questions.Count == 0) return;

            var cacheKey = GenerateCacheKey(query.Questions.First());
            if (DnsResponseCache.TryGetValue(cacheKey, out var cacheItem) && !cacheItem.IsExpired)
            {
                var cachedResponse = cacheItem.Value.DeepClone();
                cachedResponse.TransactionID = query.TransactionID;
                e.Response = cachedResponse;
                Console.WriteLine($"Cache hit for: {query.Questions.First().Name}");
                return;
            }

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

                if (answer.ReturnCode is ReturnCode.NoError or ReturnCode.NxDomain)
                    CacheDnsResponse(cacheKey, response);
            }
        }

        private static string GenerateCacheKey(DnsQuestion question) =>
            $"{question.Name}:{question.RecordType}:{question.RecordClass}";

        private static string GenerateNsCacheKey(DomainName domain, RecordType recordType) => 
            $"{domain}:{recordType}";

        private static void CacheDnsResponse(string key, DnsMessage response)
        {
            var ttl = Math.Max(response.AnswerRecords.Count > 0
                ? response.AnswerRecords.Min(r => r.TimeToLive)
                : (response.AuthorityRecords.Count > 0
                    ? response.AuthorityRecords.Min(r => r.TimeToLive)
                    : 300),60);

            DnsResponseCache[key] = new CacheItem<DnsMessage>
            {
                Value = response.DeepClone(),
                ExpiryTime = DateTime.UtcNow.AddSeconds(ttl)
            };
            Console.WriteLine($"Cached response for: {key} (TTL: {ttl}s)");
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
                if (cnameAnswer is { AnswerRecords.Count: > 0 })
                    answer.AnswerRecords.AddRange(cnameAnswer.AnswerRecords);
            }

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

            var nsCacheKey = GenerateNsCacheKey(rootName, RecordType.Ns);
            if (NsQueryCache.TryGetValue(nsCacheKey, out var nsCacheItem) && !nsCacheItem.IsExpired)
            {
                Console.WriteLine($"NS cache hit for: {rootName}");
                return nsCacheItem.Value.AnswerRecords
                    .Where(x => x.RecordType == RecordType.Ns)
                    .Select(x => ((NsRecord)x).NameServer)
                    .ToList();
            }

            var nsResolve = await new DnsClient(Server, Timeout).ResolveAsync(rootName, RecordType.Ns);

            if (nsResolve != null)
            {
                var ttl = Math.Min(nsResolve.AnswerRecords.Count > 0
                    ? nsResolve.AnswerRecords.Min(r => r.TimeToLive)
                    : (nsResolve.AuthorityRecords.Count > 0
                        ? nsResolve.AuthorityRecords.Min(r => r.TimeToLive)
                        : 300), 86400);

                NsQueryCache[nsCacheKey] = new CacheItem<DnsMessage>
                {
                    Value = nsResolve.DeepClone(),
                    ExpiryTime = DateTime.UtcNow.AddSeconds(ttl)
                };
                Console.WriteLine($"Cached NS records for: {rootName} (TTL: {ttl}s)");
            }

            return nsResolve?.AnswerRecords.Where(x => x.RecordType == RecordType.Ns)
                .Select(x => ((NsRecord)x).NameServer).ToList() ?? [];
        }

        private static async Task<List<DomainName>> GetNameServerName(DomainName name, IPAddress ipAddress)
        {
            var nsCacheKey = GenerateNsCacheKey(name, RecordType.Ns);
            if (NsQueryCache.TryGetValue(nsCacheKey, out var nsCacheItem) && !nsCacheItem.IsExpired)
            {
                Console.WriteLine($"NS cache hit for: {name}");
                return nsCacheItem.Value.AnswerRecords
                    .Where(x => x.RecordType == RecordType.Ns)
                    .Select(x => ((NsRecord)x).NameServer)
                    .ToList();
            }

            var nsResolve = await new DnsClient(ipAddress, Timeout).ResolveAsync(name, RecordType.Ns);

            if (nsResolve != null)
            {
                var ttl = Math.Min(nsResolve.AnswerRecords.Count > 0
                    ? nsResolve.AnswerRecords.Min(r => r.TimeToLive)
                    : (nsResolve.AuthorityRecords.Count > 0
                        ? nsResolve.AuthorityRecords.Min(r => r.TimeToLive)
                        : 300), 86400);

                NsQueryCache[nsCacheKey] = new CacheItem<DnsMessage>
                {
                    Value = nsResolve.DeepClone(),
                    ExpiryTime = DateTime.UtcNow.AddSeconds(ttl)
                };
                Console.WriteLine($"Cached NS records for: {name} (TTL: {ttl}s)");
            }

            return nsResolve?.AnswerRecords.Where(x => x.RecordType == RecordType.Ns)
                .Select(x => ((NsRecord)x).NameServer).ToList() ?? [];
        }

        private static async Task<List<IPAddress>> GetNameServerIp(List<DomainName> nsServerNames)
        {
            var nsIps = new List<IPAddress>();

            await Parallel.ForEachAsync(nsServerNames, async (item, c) =>
            {
                var aCacheKey = GenerateNsCacheKey(item, RecordType.A);
                if (NsQueryCache.TryGetValue(aCacheKey, out var aCacheItem) && !aCacheItem.IsExpired)
                {
                    var cachedIps = aCacheItem.Value.AnswerRecords
                        .Where(x => x.RecordType == RecordType.A)
                        .Select(x => ((ARecord)x).Address)
                        .ToList();

                    lock (nsIps) nsIps.AddRange(cachedIps);
                    Console.WriteLine($"A record cache hit for: {item}");
                    return;
                }

                var nsARecords = (await new DnsClient(Server, Timeout).ResolveAsync(item, token: c))?.AnswerRecords ?? [];
                if (nsARecords.Any(x => x.RecordType == RecordType.A))
                {
                    var addresses = nsARecords.Where(x => x.RecordType == RecordType.A)
                        .Select(x => ((ARecord)x).Address)
                        .ToList();

                    lock (nsIps) nsIps.AddRange(addresses);

                    if (nsARecords.Any())
                    {
                        var response = new DnsMessage();
                        response.AnswerRecords.AddRange(nsARecords);
                        var ttl = Math.Max(nsARecords.Min(r => r.TimeToLive), 60);

                        NsQueryCache[aCacheKey] = new CacheItem<DnsMessage>
                        {
                            Value = response,
                            ExpiryTime = DateTime.UtcNow.AddSeconds(ttl)
                        };
                        Console.WriteLine($"Cached A records for: {item} (TTL: {ttl}s)");
                    }
                }
            });

            return nsIps.Distinct().ToList();
        }

        private static async Task<DnsMessage?> ResultResolve(List<IPAddress> nsAddresses, DnsMessage query)
        {
            try
            {
                var quest = query.Questions.First();
                var client = new DnsClient(nsAddresses,
                    [new TcpClientTransport(), new UdpClientTransport()],
                    queryTimeout: Timeout);

                var answer = await client.ResolveAsync(quest.Name, quest.RecordType,
                    options: new DnsQueryOptions
                    { EDnsOptions = query.EDnsOptions, IsEDnsEnabled = query.IsEDnsEnabled });

                if (answer is { AnswerRecords.Count: 0 } &&
                    answer.AuthorityRecords.Any(x => x.RecordType == RecordType.Ns))
                {
                    return await ResultResolve(
                        await GetNameServerIp(answer.AuthorityRecords.Where(x => x.RecordType == RecordType.Ns)
                            .Select(x => ((NsRecord) x).NameServer).ToList()),
                        query);
                }

                if (answer == null ||
                    (answer.ReturnCode != ReturnCode.NoError && answer.ReturnCode != ReturnCode.NxDomain))
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