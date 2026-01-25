using ARSoft.Tools.Net;
using ARSoft.Tools.Net.Dns;
using DeepCloner.Core;
using NStack;
using System.Collections.Concurrent;
using System.Net;
using IPAddress = System.Net.IPAddress;

namespace ArashiDNS.Comet
{
    internal class Program
    {
        public static IPAddress[] Servers =
        [
            IPAddress.Parse("223.5.5.5"), IPAddress.Parse("119.29.29.29"), IPAddress.Parse("223.6.6.6"),
            IPAddress.Parse("119.28.28.28")
        ];

        public static IPEndPoint ListenerEndPoint = new(IPAddress.Loopback, 23353);
        public static TldExtract TldExtractor = new("./public_suffix_list.dat");

        public static int Timeout = 1000;
        public static int MaxCnameDepth = 30;
        public static int MinNsTTL = 3600;
        public static int MinTTL = 60;

        public static bool UseLessResponse = false;
        public static bool UseV6Ns = false;
        public static bool UseLog = true;
        public static bool UseResponseCache = false;
        public static bool UseCnameFoldingCache = true;
        public static bool UseEcsCache = true;
        public static bool UseEcsAdded = false;
        public static bool UseLessEDns = true;

        public static bool UseNsWarmUp = true;

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
            if (!File.Exists("./public_suffix_list.dat") ||
                (DateTime.UtcNow - File.GetLastWriteTimeUtc("./public_suffix_list.dat")).TotalDays > 15)
            {
                Console.WriteLine("Downloading public_suffix_list.dat...");
                File.WriteAllBytes("./public_suffix_list.dat",
                    new HttpClient()
                        .GetByteArrayAsync(
                            "https://publicsuffix.org/list/public_suffix_list.dat")
                        .Result);
                TldExtractor = new("./public_suffix_list.dat");
            }

            InitCleanupCacheTask();

            var dnsServer = new DnsServer(new UdpServerTransport(ListenerEndPoint),
                new TcpServerTransport(ListenerEndPoint));
            dnsServer.QueryReceived += OnQueryReceived;
            dnsServer.Start();

            Console.WriteLine("Now listening on: " + ListenerEndPoint);
            Console.WriteLine("Application started. Press Ctrl+C / q to shut down.");

            if (UseNsWarmUp)
            {
                var nsList = new List<string>();

                nsList.AddRange(new HttpClient()
                    .GetStringAsync(
                        "https://fastly.jsdelivr.net/gh/mili-tan/ArashiDNS.Comet@main/nslist/top10k-ns.list")
                    .Result.Split('\n').Skip(1).ToList());

                nsList.AddRange(new HttpClient()
                    .GetStringAsync(
                        "https://fastly.jsdelivr.net/gh/indianajson/cloudflare-nameservers@main/cloudflare-names.txt")
                    .Result.Split('\n').Skip(1).ToList());

                Parallel.ForEach(nsList, new ParallelOptions { MaxDegreeOfParallelism = 3 }, item =>
                {
                    Console.WriteLine("NS WarmUp: " + item);
                    _ = GetAuthorityServerIps([DomainName.Parse(item.Trim())]);
                });
            }

            if (File.Exists("warmup.csv"))
                Parallel.ForEach(File.ReadLines("warmup.csv"), new ParallelOptions {MaxDegreeOfParallelism = 3},
                    item =>
                    {
                        Console.WriteLine("NS WarmUp: " + item);
                        _ = GetAuthorityServerIps([DomainName.Parse(item.Trim())]);
                    });

            if (!Console.IsInputRedirected && Console.KeyAvailable)
            {
                while (true)
                    if (Console.ReadKey().KeyChar == 'q')
                        Environment.Exit(0);
            }

            EventWaitHandle wait = new AutoResetEvent(false);
            while (true) wait.WaitOne();
        }

        private static void InitCleanupCacheTask()
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

                    GC.Collect();
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Cache cleanup error: {ex.Message}");
                }
            }, null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(5));
        }

        private static async Task OnQueryReceived(object sender, QueryReceivedEventArgs e)
        {
            if (e.Query is not DnsMessage query || query.Questions.Count == 0) return;

            var quest = query.Questions.First();

            if (quest.RecordType == RecordType.Any &&
                (Equals(ListenerEndPoint.Address, IPAddress.Any) ||
                 Equals(ListenerEndPoint.Address, IPAddress.IPv6Any)))
            {
                var msg = query.CreateResponseInstance();
                msg.AnswerRecords.Add(
                    new HInfoRecord(quest.Name, 3600, "ANY Obsoleted", "RFC8482"));
                e.Response = msg;
                return;
            }

            if (query.Questions.First().RecordClass == RecordClass.Chaos && query.Questions.First().RecordType == RecordType.Txt &&
                query.Questions.First().Name.IsEqualOrSubDomainOf(DomainName.Parse("version.bind")))
            {
                var msg = query.CreateResponseInstance();
                msg.AnswerRecords.Add(
                    new TxtRecord(query.Questions.First().Name, 3600, "ArashiDNS.Comet"));
                e.Response = msg;

                return;
            }

            try
            {
                query.EDnsOptions ??= new OptRecord();
                if (UseEcsAdded && !query.IsEDnsEnabled ||
                    query.EDnsOptions!.Options.All(x => x.Type != EDnsOptionType.ClientSubnet))
                {
                    Console.WriteLine("ECS Added:" + string.Join(".",
                        e.RemoteEndpoint.Address.ToString().Split('.').Take(3).Append("0")));
                    query.IsEDnsEnabled = true;
                    query.EDnsOptions.Options.Add(new ClientSubnetOption(24, IPAddress.Parse(string.Join(".", e.RemoteEndpoint.Address.ToString().Split('.').Take(3).Append("0")))));
                }
            }
            catch (Exception exception)
            {
                Console.WriteLine(exception);
            }

            var cacheKey = UseEcsCache ? BuildCacheKey(query) : BuildCacheKey(quest);
            if (UseResponseCache && DnsResponseCache.TryGetValue(cacheKey, out var cacheItem) && !cacheItem.IsExpired)
            {
                var cachedResponse = cacheItem.Value.DeepClone();
                cachedResponse.TransactionID = query.TransactionID;
                e.Response = cachedResponse;
                if (UseLog) Task.Run(() => Console.WriteLine($"Cache hit for: {quest.Name}"));
                return;
            }

            var answer = await ResolveAsync(query);

            if (answer == null)
            {
                e.Response = query.CreateResponseInstance();
                e.Response.ReturnCode = ReturnCode.ServerFailure;
            }
            else
            {
                var response = query.CreateResponseInstance();
                if (UseLessResponse)
                {
                    response.ReturnCode = answer.ReturnCode;
                    response.IsRecursionAllowed = true;
                    response.IsRecursionDesired = true;
                    response.AnswerRecords.AddRange(answer.AnswerRecords);
                }
                else
                {
                    response = answer;
                    response.TransactionID = query.TransactionID;
                    response.IsRecursionAllowed = true;
                    response.IsRecursionDesired = true;
                }

                if (!UseEcsCache && response.IsEDnsEnabled && response.EDnsOptions != null)
                    response.EDnsOptions.Options.RemoveAll(x => x.Type == EDnsOptionType.ClientSubnet);

                e.Response = response;

                if (UseResponseCache && answer.ReturnCode is ReturnCode.NoError or ReturnCode.NxDomain)
                    CacheResponse(cacheKey, response);
            }
        }

        private static string BuildCacheKey(DnsQuestion question) =>
            $"{question.Name}:{question.RecordType}:{question.RecordClass}";

        private static string BuildCacheKey(DnsMessage message)
        {
            var quest = message.Questions.First();
            return $"{quest.Name}:{quest.RecordType}:{quest.RecordClass}:{GetClientIpBase64(message)}";
        }

        private static string BuildNsCacheKey(DomainName domain, RecordType recordType) =>
            $"{domain}:{recordType}";

        private static void CacheResponse(string key, DnsMessage response)
        {
            var ttl = Math.Max(response.AnswerRecords.Count > 0
                ? response.AnswerRecords.Min(r => r.TimeToLive)
                : (response.AuthorityRecords.Count > 0
                    ? response.AuthorityRecords.Min(r => r.TimeToLive)
                    : 300), MinTTL);

            DnsResponseCache[key] = new CacheItem<DnsMessage>
            {
                Value = response.DeepClone(),
                ExpiryTime = DateTime.UtcNow.AddSeconds(ttl)
            };
            if (UseLog) Task.Run(() => Console.WriteLine($"Cached response for: {key} (TTL: {ttl}s)"));
        }

        public static DnsMessage CloneQuery(DnsMessage qMessage, DnsQuestion question)
        {
            var newQuery = qMessage.DeepClone();
            newQuery.Questions.Clear();
            newQuery.Questions.Add(question);
            return newQuery;
        }

        private static async Task<DnsMessage?> ResolveAsync(DnsMessage query, int cnameDepth = 0)
        {
            if (cnameDepth > MaxCnameDepth) return null;
            var answer = query.CreateResponseInstance();
            var quest = query.Questions.First();
            var cnameFoldCacheKey = $"{quest.Name}:CNAME-FOLD:{quest.RecordClass}";
            if (UseEcsCache) cnameFoldCacheKey += $":{GetClientIpBase64(query)}";

            if (UseCnameFoldingCache && DnsResponseCache.TryGetValue(cnameFoldCacheKey, out var nsRootCacheItem) &&
                !nsRootCacheItem.IsExpired)
            {
                var cNameRecord = (nsRootCacheItem.Value.AnswerRecords
                    .Last(x => x.RecordType == RecordType.CName) as CNameRecord);
                if (UseLog) Task.Run(() => Console.WriteLine($"CNAME cache hit for: {cNameRecord.CanonicalName}"));
                answer.AnswerRecords.Add(new CNameRecord(quest.Name, cNameRecord.TimeToLive,
                    cNameRecord.CanonicalName));
                var cnameAnswer = await ResolveAsync(CloneQuery(query, new DnsQuestion(cNameRecord.CanonicalName,
                    quest.RecordType,
                    quest.RecordClass)), cnameDepth + 1);
                //Console.WriteLine(cnameAnswer.ReturnCode);
                if (cnameAnswer is { AnswerRecords.Count: > 0 })
                {
                    answer.AnswerRecords.AddRange(cnameAnswer.AnswerRecords);
                    return answer;
                }
            }

            var (nsServers, nsReturnCode) = await GetAuthorityServers(quest);
            if (nsServers.Count == 0)
            {
                answer.ReturnCode = nsReturnCode;
                return answer;
            }

            var nsIps = await GetAuthorityServerIps(nsServers.Order().Take(2));
            if (nsIps.Count == 0)
            {
                answer.ReturnCode = ReturnCode.ServerFailure;
                return answer;
            }

            answer = await ResolveFromAuthority(nsIps, query);

            if (answer != null && answer.AnswerRecords.Count != 0 &&
                answer.AnswerRecords.All(x => x.RecordType == RecordType.CName) && cnameDepth <= MaxCnameDepth)
            {
                var cnameAnswer = await ResolveAsync(CloneQuery(query, new DnsQuestion(
                    ((CNameRecord)answer.AnswerRecords.LastOrDefault(x => x.RecordType == RecordType.CName)!)
                    .CanonicalName,
                    quest.RecordType,
                    quest.RecordClass)), cnameDepth + 1);
                //Console.WriteLine(cnameAnswer.ReturnCode);

                if (cnameAnswer is { AnswerRecords.Count: > 0 })
                {
                    answer.AnswerRecords.AddRange(cnameAnswer.AnswerRecords);
                    if (UseCnameFoldingCache && cnameAnswer.AnswerRecords.Any(x => x.RecordType == RecordType.CName))
                    {
                        var cnameRecord = cnameAnswer.AnswerRecords
                            .Last(x => x.RecordType == RecordType.CName);
                        var ttl = Math.Max(cnameAnswer.AnswerRecords.Count > 0
                            ? cnameAnswer.AnswerRecords.Max(r => r.TimeToLive)
                            : 60, MinTTL);
                        DnsResponseCache[cnameFoldCacheKey] =
                            new CacheItem<DnsMessage>
                            {
                                Value = cnameAnswer,
                                ExpiryTime = DateTime.UtcNow.AddSeconds(ttl)
                            };
                        if (UseLog)
                            Task.Run(() =>
                                Console.WriteLine($"Cached CNAME records for: {cnameRecord.Name} (TTL: {ttl}s)"));
                    }
                }
            }

            return answer;
        }

        private static async Task<(List<DomainName>, ReturnCode)> GetAuthorityServers(DnsQuestion query)
        {
            var name = query.Name;
            if (NsQueryCache.TryGetValue(BuildNsCacheKey(name, RecordType.Ns), out var nsMainCacheItem) &&
                !nsMainCacheItem.IsExpired)
            {
                if (UseLog) Task.Run(() => Console.WriteLine($"NS cache hit for: {name}"));
                return (nsMainCacheItem.Value.AnswerRecords
                    .Where(x => x.RecordType == RecordType.Ns)
                    .Select(x => ((NsRecord)x).NameServer)
                    .ToList(), ReturnCode.NoError);
            }

            var tld = TldExtractor.Extract(name.ToString().Trim('.'));
            var rootName = name.LabelCount == 2
                ? name
                : string.IsNullOrWhiteSpace(tld.tld)
                    ? DomainName.Parse(string.Join('.', name.Labels.TakeLast(2)))
                    : DomainName.Parse(tld.root + "." + tld.tld);

            if (!name.GetParentName().Equals(rootName) &&
                NsQueryCache.TryGetValue(BuildNsCacheKey(name.GetParentName(), RecordType.Ns),
                    out var nsParentCacheItem) &&
                !nsParentCacheItem.IsExpired)
            {
                if (UseLog) Task.Run(() => Console.WriteLine($"NS cache hit for: {name.GetParentName()}"));
                return (nsParentCacheItem.Value.AnswerRecords
                    .Where(x => x.RecordType == RecordType.Ns)
                    .Select(x => ((NsRecord)x).NameServer)
                    .ToList(), ReturnCode.NoError);
            }

            var nsRootCacheKey = BuildNsCacheKey(rootName, RecordType.Ns);
            if (NsQueryCache.TryGetValue(nsRootCacheKey, out var nsRootCacheItem) && !nsRootCacheItem.IsExpired)
            {
                if (UseLog) Task.Run(() => Console.WriteLine($"NS cache hit for: {rootName}"));
                return (nsRootCacheItem.Value.AnswerRecords
                    .Where(x => x.RecordType == RecordType.Ns)
                    .Select(x => ((NsRecord)x).NameServer)
                    .ToList(), ReturnCode.NoError);
            }

            var nsAnswer = await QueryAsync(Servers, rootName, RecordType.Ns, isUdpFirst: true);

            if (nsAnswer is { AnswerRecords.Count: 0 })
                nsAnswer = await QueryAsync(Servers, rootName.GetParentName(), RecordType.Ns, isUdpFirst: true);

            if (nsAnswer != null)
            {
                var ttl = Math.Min(nsAnswer.AnswerRecords.Count > 0
                    ? nsAnswer.AnswerRecords.Min(r => r.TimeToLive)
                    : (nsAnswer.AuthorityRecords.Count > 0
                        ? nsAnswer.AuthorityRecords.Min(r => r.TimeToLive)
                        : 300), MinNsTTL);

                NsQueryCache[nsRootCacheKey] = new CacheItem<DnsMessage>
                {
                    Value = nsAnswer.DeepClone(),
                    ExpiryTime = DateTime.UtcNow.AddSeconds(ttl)
                };
                if (UseLog) Task.Run(() => Console.WriteLine($"Cached NS records for: {rootName} (TTL: {ttl}s)"));
            }

            return (nsAnswer?.AnswerRecords.Where(x => x.RecordType == RecordType.Ns)
                    .Select(x => ((NsRecord)x).NameServer).ToList() ?? [],
                nsAnswer?.ReturnCode ?? ReturnCode.ServerFailure);
        }

        private static async Task<List<DomainName>> GetAuthorityServers(DomainName name, IPAddress ipAddress)
        {
            var nsCacheKey = BuildNsCacheKey(name, RecordType.Ns);
            if (NsQueryCache.TryGetValue(nsCacheKey, out var nsCacheItem) && !nsCacheItem.IsExpired)
            {
                Console.WriteLine($"NS cache hit for: {name}");
                return nsCacheItem.Value.AnswerRecords
                    .Where(x => x.RecordType == RecordType.Ns)
                    .Select(x => ((NsRecord)x).NameServer)
                    .ToList();
            }

            var nsAnswer = await new DnsClient(ipAddress, Timeout).ResolveAsync(name, RecordType.Ns);

            if (nsAnswer != null)
            {
                var ttl = Math.Min(nsAnswer.AnswerRecords.Count > 0
                    ? nsAnswer.AnswerRecords.Min(r => r.TimeToLive)
                    : (nsAnswer.AuthorityRecords.Count > 0
                        ? nsAnswer.AuthorityRecords.Min(r => r.TimeToLive)
                        : 300), MinNsTTL);

                NsQueryCache[nsCacheKey] = new CacheItem<DnsMessage>
                {
                    Value = nsAnswer.DeepClone(),
                    ExpiryTime = DateTime.UtcNow.AddSeconds(ttl)
                };
                Console.WriteLine($"Cached NS records for: {name} (TTL: {ttl}s)");
            }

            return nsAnswer?.AnswerRecords.Where(x => x.RecordType == RecordType.Ns)
                .Select(x => ((NsRecord)x).NameServer).ToList() ?? [];
        }

        private static async Task<List<IPAddress>> GetAuthorityServerIps(IEnumerable<DomainName> nsServers)
        {
            var nsIps = new List<IPAddress>();

            await Parallel.ForEachAsync(nsServers, async (item, c) =>
            {
                var aCacheKey = BuildNsCacheKey(item, RecordType.A);
                var aaaaCacheKey = BuildNsCacheKey(item, RecordType.Aaaa);
                if (NsQueryCache.TryGetValue(aCacheKey, out var aCacheItem) && !aCacheItem.IsExpired)
                {
                    var cachedIps = aCacheItem.Value.AnswerRecords
                        .Where(x => x.RecordType == RecordType.A)
                        .Select(x => ((ARecord)x).Address)
                        .ToList();

                    lock (nsIps) nsIps.AddRange(cachedIps);
                    if (UseLog) Task.Run(() => Console.WriteLine($"A record cache hit for: {item}"));
                    return;
                }

                if (UseV6Ns && NsQueryCache.TryGetValue(aaaaCacheKey, out var aaaaCacheItem) &&
                    !aaaaCacheItem.IsExpired)
                {
                    var cachedIps = aaaaCacheItem.Value.AnswerRecords
                        .Where(x => x.RecordType == RecordType.A)
                        .Select(x => ((ARecord)x).Address)
                        .ToList();

                    lock (nsIps) nsIps.AddRange(cachedIps);
                    if (UseLog) Task.Run(() => Console.WriteLine($"AAAA record cache hit for: {item}"));
                    return;
                }

                var nsARecords = (await QueryAsync(Servers, item, RecordType.A, isUdpFirst: true))?.AnswerRecords ??
                                 [];
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
                        var ttl = Math.Max(nsARecords.Min(r => r.TimeToLive), MinTTL);

                        NsQueryCache[aCacheKey] = new CacheItem<DnsMessage>
                        {
                            Value = response,
                            ExpiryTime = DateTime.UtcNow.AddSeconds(ttl)
                        };
                        if (UseLog) Task.Run(() => Console.WriteLine($"Cached A records for: {item} (TTL: {ttl}s)"));
                    }
                }
                else if (UseV6Ns)
                {
                    var nsAaaaRecords =
                        (await QueryAsync(Servers, item, RecordType.Aaaa, isUdpFirst: true))
                        ?.AnswerRecords ?? [];
                    if (nsAaaaRecords.Any(x => x.RecordType == RecordType.A))
                    {
                        var addresses = nsAaaaRecords.Where(x => x.RecordType == RecordType.Aaaa)
                            .Select(x => ((AaaaRecord)x).Address)
                            .ToList();

                        lock (nsIps) nsIps.AddRange(addresses);

                        if (nsAaaaRecords.Any())
                        {
                            var response = new DnsMessage();
                            response.AnswerRecords.AddRange(nsAaaaRecords);
                            var ttl = Math.Max(nsAaaaRecords.Min(r => r.TimeToLive), MinTTL);

                            NsQueryCache[aaaaCacheKey] = new CacheItem<DnsMessage>
                            {
                                Value = response,
                                ExpiryTime = DateTime.UtcNow.AddSeconds(ttl)
                            };
                            if (UseLog)
                                Task.Run(() => Console.WriteLine($"Cached AAAA records for: {item} (TTL: {ttl}s)"));
                        }
                    }
                }
            });

            return nsIps.Distinct().ToList();
        }

        private static async Task<DnsMessage?> ResolveFromAuthority(IEnumerable<IPAddress> nsAddresses, DnsMessage query,
            int depth = 0)
        {
            if (depth > MaxCnameDepth) return null;
            try
            {
                var quest = query.Questions.First();

                if (UseLessEDns && query.EDnsOptions != null && query.EDnsOptions.Options.Any())
                    query.EDnsOptions.Options.RemoveAll(x => x.Type != EDnsOptionType.ClientSubnet);

                var answer = await QueryAsync(nsAddresses, quest.Name, quest.RecordType,
                    options: new DnsQueryOptions
                    {
                        EDnsOptions = query.EDnsOptions,
                        IsEDnsEnabled = query.IsEDnsEnabled,
                        IsRecursionDesired = true
                    });

                if (answer == null ||
                    (answer.ReturnCode != ReturnCode.NoError && answer.ReturnCode != ReturnCode.NxDomain))
                    answer = await QueryAsync(nsAddresses, quest.Name, quest.RecordType, isUdpFirst: true) ?? answer;
                //options: new DnsQueryOptions()

                if (answer is { AnswerRecords.Count: 0 } &&
                    answer.AuthorityRecords.Any(x => x.RecordType == RecordType.Ns) &&
                    answer.AuthorityRecords.FirstOrDefault(x => x.RecordType == RecordType.Ns)!.Name.LabelCount > 1)
                {
                    var nsCacheMsg = query.CreateResponseInstance();
                    var ttl = DateTime.UtcNow.AddSeconds(Math.Min(answer.AuthorityRecords.Count > 0
                        ? answer.AuthorityRecords.Min(r => r.TimeToLive)
                        : 300, MinNsTTL));
                    nsCacheMsg.AnswerRecords.AddRange(
                        answer.AuthorityRecords.Where(x => x.RecordType == RecordType.Ns));

                    NsQueryCache[BuildNsCacheKey(quest.Name, RecordType.Ns)] = new CacheItem<DnsMessage>
                    {
                        Value = nsCacheMsg,
                        ExpiryTime = ttl
                    };
                    NsQueryCache[
                        BuildNsCacheKey(answer.AuthorityRecords.First(x => x.RecordType == RecordType.Ns).Name,
                            RecordType.Ns)] = new CacheItem<DnsMessage>
                            {
                                Value = nsCacheMsg,
                                ExpiryTime = ttl
                            };

                    return await ResolveFromAuthority(
                        await GetAuthorityServerIps(answer.AuthorityRecords.Where(x => x.RecordType == RecordType.Ns)
                            .Select(x => ((NsRecord)x).NameServer).Order().Take(2)),
                        query, depth + 1);
                }

                //if (answer is { AnswerRecords.Count: 0 } && answer.AuthorityRecords.Any())
                //    answer = await QueryAsync(nsAddresses, quest.Name, quest.RecordType,
                //        options: new DnsQueryOptions() { IsRecursionDesired = true }, isUdpFirst: true) ?? answer;

                return answer;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return null;
            }
        }

        public static async Task<DnsMessage?> QueryAsync(IEnumerable<IPAddress> ipAddresses, DomainName name,
            RecordType type, RecordClass recordClass = RecordClass.INet,
            DnsQueryOptions? options = null, bool isParallel = true, bool isUdpFirst = true)
        {
            //Console.WriteLine(name + ":" + type + "@" + ipAddresses.First() + ":" + isUdpFirst);
            try
            {
                //options ??= new DnsQueryOptions() {IsRecursionDesired = true};
                if (isParallel)
                {
                    // var items = ipAddresses.Take(6);
                    foreach (var items in ipAddresses.Chunk(4))
                    {
                        var cts = new CancellationTokenSource(Timeout);
                        var tasks = items.Select(server =>
                            Task.Run(async () =>
                            {
                                try
                                {
                                    return await new DnsClient([server],
                                        isUdpFirst
                                            ? [new UdpClientTransport(), new TcpClientTransport()]
                                            : [new TcpClientTransport(), new UdpClientTransport()],
                                        queryTimeout: Timeout).ResolveAsync(name, type,
                                        recordClass, options, cts.Token);
                                }
                                catch
                                {
                                    return null;
                                }
                            }, cts.Token)).ToList();

                        var completedTask = await Task.WhenAny(tasks);
                        await cts.CancelAsync();

                        if (await completedTask != null)
                            return await completedTask;
                    }
                }
                else 
                    return await new DnsClient(ipAddresses, isUdpFirst
                            ? [new UdpClientTransport(), new TcpClientTransport()]
                            : [new TcpClientTransport(), new UdpClientTransport()],
                        queryTimeout: Timeout).ResolveAsync(name, type, recordClass, options);

                return null;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        public static IPAddress GetClientIp(DnsMessage dnsMsg)
        {
            try
            {
                if (dnsMsg is { IsEDnsEnabled: false }) return IPAddress.Any;
                foreach (var eDnsOptionBase in dnsMsg.EDnsOptions.Options.ToList())
                {
                    if (eDnsOptionBase is ClientSubnetOption option)
                        return option.Address;
                }

                return IPAddress.Any;
            }
            catch (Exception)
            {
                return IPAddress.Any;
            }
        }

        public static string GetClientIpBase64(DnsMessage dnsMsg)
        {
            return Convert.ToBase64String(GetClientIp(dnsMsg).GetAddressBytes());
        }
    }
}