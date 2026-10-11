using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

// =============================================================================
//  HttpsProxy  —  proxy HTTPS avec trois modes : setup, capture et replay
//
//  setup   : genere une CA racine locale (proxy-ca.pfx) + un certificat serveur
//            signe par cette CA pour le domaine fourni (proxy-cert.pfx), puis
//            installe la CA dans le magasin « Racines de confiance » Windows si
//            elle n'y est pas deja. Le client fait ainsi confiance au proxy sans
//            option -k.
//
//  capture : agit comme reverse-proxy TLS vers une destination (IP:port).
//            Il relaie chaque requete du client vers le vrai serveur, renvoie
//            la vraie reponse au client, ET enregistre la reponse brute
//            (octet pour octet) indexee par le PATH de la requete
//            (les parametres GET/POST / la query string sont ignores).
//            Une nouvelle capture sur le meme path ecrase la precedente.
//
//  replay  : n'appelle plus personne. Pour chaque requete recue, il prend le
//            PATH (query ignoree), cherche la derniere reponse capturee pour
//            ce path et la renvoie telle quelle (octet pour octet).
//
//  Usage :
//     dotnet run -- setup <domaine[,domaine...]> [--ca .\proxy-ca.pfx]
//                                       [--cert .\proxy-cert.pfx] [--machine] [--renew] [--renew-ca]
//     dotnet run -- capture <ip[:port]> [--listen 443] [--store .\captures]
//                                       [--sni host] [--cert .\proxy-cert.pfx]
//                                       [--ca .\proxy-ca.pfx] [--domain host] [--trust] [--machine]
//                                       [--renew] [--renew-ca]
//                                       [--set-hosts domaine:ip] [--force-disable-hosts]
//                                       [--close-after-replay sec] [--close-after-timeout sec]
//     dotnet run -- replay            [--listen 443] [--store .\captures]
//                                       [--cert .\proxy-cert.pfx] [--ca .\proxy-ca.pfx]
//                                       [--domain host] [--trust] [--machine] [--renew] [--renew-ca]
//                                       [--forward-leftover ip[:port]] [--save-misses]
//                                       [--set-hosts domaine:ip] [--force-disable-hosts]
//                                       [--close-after-replay sec] [--close-after-timeout sec]
//
//  --domain   : domaine(s) couverts par le certificat serveur (virgule = plusieurs).
//  --trust    : (capture/replay) installe aussi la CA dans le magasin de confiance.
//  --machine  : installe la CA dans LocalMachine (exige des droits administrateur).
//  --renew    : regenere le certificat serveur meme s'il existe deja.
//  --renew-ca : regenere la CA (nouvelle cle) + le certificat serveur, et REMPLACE
//               l'ancienne CA dans le magasin Racines de confiance.
//  --set-hosts <domaine>:<ip> : active (de-commente/ajoute) la ligne dans le
//               fichier hosts, puis la restaure a l'arret. Ex. exemple.com:127.0.0.2
//  --force-disable-hosts : a l'arret, desactive la ligne hosts meme si elle etait
//               deja active avant le lancement.
//  --close-after-replay <sec> : ferme le proxy `sec` s apres la premiere reponse
//               servie en mode replay.
//  --close-after-timeout <sec> : ferme le proxy apres `sec` s (quel que soit le trafic).
//
//  NB : comme on termine le TLS cote client, le client doit accepter la CA du
//       proxy (option -k / « ignorer les erreurs de certif », ou installation
//       de la CA dans le magasin de confiance via le mode setup).
// =============================================================================

var opts = Options.Parse(args);
if (opts is null) { Options.PrintUsage(); return 1; }

Directory.CreateDirectory(opts.StoreDir);

// CA racine locale (auto-signee). Stable entre les runs, sauf --renew-ca.
var ca = CertStore.GetOrCreateCa(opts.CaPath, opts.RenewCa);

// --renew-ca regenere la CA donc casse la chaine du certificat serveur : on le
// regenere aussi (renew = opts.Renew || opts.RenewCa).
bool renewServer = opts.Renew || opts.RenewCa;

if (opts.Mode == Mode.Setup)
{
    using var setupCert = CertStore.GetOrCreateServer(opts.CertPath, ca, opts.Domains, renewServer);
    EnsureCaTrusted(ca, opts.Machine, replace: opts.RenewCa);
    Console.WriteLine();
    Console.WriteLine($"CA racine         : {Path.GetFullPath(opts.CaPath)}");
    Console.WriteLine($"Certificat serveur: {Path.GetFullPath(opts.CertPath)}");
    Console.WriteLine($"Domaines couverts : {string.Join(", ", opts.Domains)}");
    Console.WriteLine();
    Console.WriteLine("Lancez ensuite capture/replay avec --domain (et eventuellement --trust).");
    return 0;
}

if (opts.Trust || opts.RenewCa)
    EnsureCaTrusted(ca, opts.Machine, replace: opts.RenewCa);

// Certificat serveur (cote client), signe par la CA, couvrant les domaines demandes.
// Stable entre les runs : genere une fois puis relu depuis le .pfx.
var serverCert = CertStore.GetOrCreateServer(opts.CertPath, ca, opts.Domains, renewServer);

Console.WriteLine($"=== HttpsProxy — mode {opts.Mode.ToString().ToUpperInvariant()} ===");
Console.WriteLine($"Ecoute        : https://{opts.BindAddress}:{opts.ListenPort}");
Console.WriteLine($"Dossier store : {Path.GetFullPath(opts.StoreDir)}");
Console.WriteLine($"Certificat    : {Path.GetFullPath(opts.CertPath)}  (CN={opts.CertCommonName})");
Console.WriteLine($"CA racine     : {Path.GetFullPath(opts.CaPath)}");
if (opts.Mode == Mode.Capture)
{
    Console.WriteLine($"Destination   : {opts.DestHost}:{opts.DestPort}");
    Console.WriteLine($"SNI amont     : {opts.UpstreamSni ?? "(Host: de la requete)"}");
}
else if (opts.HasUpstream)
{
    Console.WriteLine($"Forward-left. : paths absents -> {opts.DestHost}:{opts.DestPort}" +
                      (opts.SaveMisses ? " (+ enregistrement)" : ""));
    Console.WriteLine($"SNI amont     : {opts.UpstreamSni ?? "(Host: de la requete)"}");
}
else
{
    Console.WriteLine("Forward-left. : desactive (paths absents -> 404)");
}
// -------------------------------------------------------------------------
//  Fichier hosts (--set-hosts) : activation avant l'ecoute, restauration a l'arret.
// -------------------------------------------------------------------------
var hostsInitial = HostsFile.InitialState.Absent;
bool hostsTouched = false;

if (opts.HostsSource is not null && opts.HostsDest is not null)
{
    if (!HostsFile.TryActivate(opts.HostsDest, opts.HostsSource, out hostsInitial, out string? hErr))
    {
        Console.Error.WriteLine($"Impossible de modifier le fichier hosts : {hErr}");
        Console.Error.WriteLine("Modifier le fichier hosts exige d'executer en tant qu'administrateur.");
        return 1;
    }
    hostsTouched = true;
    Console.WriteLine($"Hosts          : {opts.HostsDest} {opts.HostsSource} (etat initial : {hostsInitial})");
}

Console.WriteLine("Ctrl+C pour arreter.\n");

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

// Fermetures planifiees : --close-after-timeout et --close-after-replay.
if (opts.CloseAfterTimeoutSec >= 0)
    ScheduleClose(cts, opts.CloseAfterTimeoutSec);
var closeCtrl = new CloseController(cts, opts.CloseAfterReplaySec);

var listener = new TcpListener(opts.BindAddress, opts.ListenPort);
listener.Start();

try
{
    while (!cts.IsCancellationRequested)
    {
        TcpClient client;
        try { client = await listener.AcceptTcpClientAsync(cts.Token); }
        catch (OperationCanceledException) { break; }
        _ = Task.Run(() => HandleClientAsync(client, opts, serverCert, closeCtrl.NotifyReplaySuccess, cts.Token));
    }
}
finally
{
    listener.Stop();
    if (hostsTouched && !HostsFile.TryDeactivate(opts.HostsDest!, opts.HostsSource!, hostsInitial, opts.ForceDisableHosts, out string? hErr))
        Console.Error.WriteLine($"Impossible de restaurer le fichier hosts : {hErr}");
}
Console.WriteLine("Arrete.");
return 0;

// -----------------------------------------------------------------------------
//  Traitement d'une connexion client
// -----------------------------------------------------------------------------
static async Task HandleClientAsync(TcpClient client, Options opts, X509Certificate2 cert, Action? notifyReplay, CancellationToken ct)
{
    var remote = client.Client.RemoteEndPoint?.ToString() ?? "?";
    try
    {
        using (client)
        using (var raw = client.GetStream())
        using (var tls = new SslStream(raw, false))
        {
            await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = cert,
                ClientCertificateRequired = false,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            }, ct);

            var wire = new Wire(tls);

            // Boucle keep-alive : plusieurs requetes possibles sur la meme connexion.
            while (!ct.IsCancellationRequested)
            {
                var req = HttpMessage.Read(wire, isResponse: false);
                if (req is null) break; // le client a ferme proprement

                var path = HttpMessage.NormalizePath(req.Target);
                bool keepAlive;

                if (opts.Mode == Mode.Capture)
                    keepAlive = await ForwardAsync(opts, req, path, tls, remote, save: true, tag: "CAPTURE", ct);
                else
                    keepAlive = await ReplayOneAsync(opts, req, path, tls, remote, notifyReplay, ct);

                if (!keepAlive) break;
            }
        }
    }
    catch (OperationCanceledException) { }
    catch (Exception ex)
    {
        Console.WriteLine($"[{remote}] connexion fermee : {ex.GetType().Name}: {ex.Message}");
    }
}

// -----------------------------------------------------------------------------
//  RELAIS : relaie la requete vers le vrai serveur, renvoie la vraie reponse au
//  client, et (si save) enregistre la reponse indexee par path.
//  Utilise par le mode capture (toujours) et par le mode replay sur un path
//  absent de la capture quand --forward-leftover est fourni.
// -----------------------------------------------------------------------------
static async Task<bool> ForwardAsync(Options opts, HttpMessage req, string path,
                                     SslStream clientTls, string remote,
                                     bool save, string tag, CancellationToken ct)
{
    // SNI / TargetHost pour le TLS amont : --sni, sinon le Host: de la requete, sinon l'IP.
    string sni = opts.UpstreamSni ?? HostOnly(req.GetHeader("host")) ?? opts.DestHost;

    HttpMessage resp;
    using (var up = new TcpClient())
    {
        await up.ConnectAsync(opts.DestHost, opts.DestPort, ct);
        using var upRaw = up.GetStream();
        using var upTls = new SslStream(upRaw, false); // validation faite via les options ci-dessous
        await upTls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = sni,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            RemoteCertificateValidationCallback = (_, _, _, _) => true,
        }, ct);

        // On envoie la requete brute telle quelle vers l'amont.
        await upTls.WriteAsync(req.Raw, ct);
        await upTls.FlushAsync(ct);

        var upWire = new Wire(upTls);
        var r = HttpMessage.Read(upWire, isResponse: true);
        if (r is null) throw new IOException("aucune reponse de la destination");
        resp = r;
    } // connexion amont fermee (une par requete : simple et sans etat)

    // Enregistrement : derniere reponse par path (ecrase).
    if (save) Store.Save(opts.StoreDir, path, req, resp);
    Console.WriteLine($"[{remote}] {tag} {req.Method} {path} -> {resp.StatusCode}  ({resp.Raw.Length} o){(save ? " enregistre" : "")}");

    // On renvoie la vraie reponse au client, octet pour octet.
    await clientTls.WriteAsync(resp.Raw, ct);
    await clientTls.FlushAsync(ct);

    return KeepAlive(req, resp);
}

// -----------------------------------------------------------------------------
//  MODE REPLAY : renvoie la derniere reponse capturee pour ce path
// -----------------------------------------------------------------------------
static async Task<bool> ReplayOneAsync(Options opts, HttpMessage req, string path,
                                       SslStream clientTls, string remote, Action? onReplay, CancellationToken ct)
{
    var bytes = Store.Load(opts.StoreDir, path);
    if (bytes is null)
    {
        // Path absent de la capture : si --forward-leftover est fourni, on relaie
        // en live vers la vraie destination (et on enregistre si --save-misses).
        if (opts.HasUpstream)
        {
            Console.WriteLine($"[{remote}] REPLAY miss {req.Method} {path} -> forward {opts.DestHost}:{opts.DestPort}");
            bool ka = await ForwardAsync(opts, req, path, clientTls, remote,
                                         save: opts.SaveMisses, tag: "FORWARD", ct);
            onReplay?.Invoke();
            return ka;
        }

        Console.WriteLine($"[{remote}] REPLAY {req.Method} {path} -> 404 (aucune capture)");
        var body = Encoding.UTF8.GetBytes($"No capture for path: {path}\n");
        var notFound = Encoding.ASCII.GetBytes(
            "HTTP/1.1 404 Not Found\r\n" +
            "Content-Type: text/plain; charset=utf-8\r\n" +
            $"Content-Length: {body.Length}\r\n" +
            "Connection: close\r\n\r\n");
        await clientTls.WriteAsync(notFound);
        await clientTls.WriteAsync(body);
        await clientTls.FlushAsync();
        return false;
    }

    Console.WriteLine($"[{remote}] REPLAY {req.Method} {path} -> {bytes.Length} o (reponse capturee)");
    await clientTls.WriteAsync(bytes);
    await clientTls.FlushAsync();
    onReplay?.Invoke();

    // On respecte le cadrage de la reponse capturee pour decider keep-alive.
    var resp = HttpMessage.Parse(bytes, isResponse: true);
    return KeepAlive(req, resp);
}

// -----------------------------------------------------------------------------
//  Keep-alive : on garde la connexion ouverte seulement si requete ET reponse
//  le permettent et si la reponse est correctement cadree (longueur connue).
// -----------------------------------------------------------------------------
static bool KeepAlive(HttpMessage req, HttpMessage resp)
{
    bool reqKeep = !req.ConnectionClose && (!req.Http10 || req.ConnectionKeepAlive);
    bool respFramed = resp.Chunked || resp.ContentLength >= 0 || resp.NoBody;
    bool respClose = resp.ConnectionClose || !respFramed;
    return reqKeep && !respClose;
}

static string? HostOnly(string? host)
{
    if (string.IsNullOrEmpty(host)) return null;
    int c = host.IndexOf(':');
    return c >= 0 ? host[..c] : host;
}

// -----------------------------------------------------------------------------
//  Installe la CA dans le magasin « Racines de confiance » Windows si absente.
//  machine=true -> LocalMachine (admin requis), sinon CurrentUser.
//  replace=true -> supprime les anciennes CA du meme nom puis installe la nouvelle.
// -----------------------------------------------------------------------------
static void EnsureCaTrusted(X509Certificate2 ca, bool machine, bool replace = false)
{
    string scope = machine ? "machine (LocalMachine)" : "utilisateur (CurrentUser)";
    if (!replace && WindowsTrustStore.IsTrusted(ca, machine))
    {
        Console.WriteLine($"CA deja presente dans le magasin Racines de confiance ({scope}).");
        return;
    }
    try
    {
        if (replace)
        {
            int removed = WindowsTrustStore.Replace(ca, machine);
            Console.WriteLine($"CA remplacee dans le magasin Racines de confiance ({scope}) ({removed} ancienne(s) retiree(s)).");
        }
        else
        {
            WindowsTrustStore.Trust(ca, machine);
            Console.WriteLine($"CA installee dans le magasin Racines de confiance ({scope}).");
        }
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"Impossible d'installer la CA ({scope}) : {ex.Message}");
        if (machine)
            Console.Error.WriteLine("L'installation dans LocalMachine exige d'executer en tant qu'administrateur.");
    }
}

// -----------------------------------------------------------------------------
//  Planifie la fermeture du proxy apres `sec` secondes (annule le CTS).
// -----------------------------------------------------------------------------
static void ScheduleClose(CancellationTokenSource cts, int sec)
{
    _ = Task.Run(async () =>
    {
        try { await Task.Delay(sec * 1000, cts.Token); }
        catch (OperationCanceledException) { return; }
        cts.Cancel();
    });
}

// =============================================================================
//  Options / parsing de la ligne de commande
// =============================================================================
enum Mode { Capture, Replay, Setup }

sealed class Options
{
    public Mode Mode;
    public IPAddress BindAddress = IPAddress.Any;
    public int ListenPort = 443;
    public string StoreDir = "captures";
    public string CertPath = "proxy-cert.pfx";
    public string CaPath = "proxy-ca.pfx";
    public string Domain = "";
    public string DestHost = "";
    public int DestPort = 443;
    public string? UpstreamSni;
    public bool SaveMisses;
    public bool Trust;
    public bool Machine;
    public bool Renew;
    public bool RenewCa;
    public string? HostsSource;
    public string? HostsDest;
    public bool ForceDisableHosts;
    public int CloseAfterReplaySec = -1;
    public int CloseAfterTimeoutSec = -1;

    public bool HasUpstream => !string.IsNullOrEmpty(DestHost);

    // Domaines a couvrir par le certificat serveur (SAN + CN = premier).
    public IEnumerable<string> Domains
    {
        get
        {
            if (!string.IsNullOrWhiteSpace(Domain))
                foreach (var d in Domain.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                    yield return d;
            else if (HasUpstream)
                yield return DestHost;
            else
                yield return "localhost";
        }
    }

    public string CertCommonName => Domains.FirstOrDefault() ?? "localhost";

    public static Options? Parse(string[] args)
    {
        if (args.Length == 0) return null;
        var o = new Options();
        int i = 0;

        switch (args[0].ToLowerInvariant())
        {
            case "capture": o.Mode = Mode.Capture; break;
            case "replay": o.Mode = Mode.Replay; break;
            case "setup": o.Mode = Mode.Setup; break;
            default: Console.Error.WriteLine($"Mode inconnu : {args[0]}"); return null;
        }
        i = 1;

        if (o.Mode == Mode.Capture)
        {
            if (args.Length < 2 || args[1].StartsWith("--"))
            {
                Console.Error.WriteLine("Le mode capture exige une destination : <ip[:port]>");
                return null;
            }
            var dest = args[1];
            int c = dest.LastIndexOf(':');
            if (c >= 0 && int.TryParse(dest[(c + 1)..], out int dp)) { o.DestHost = dest[..c]; o.DestPort = dp; }
            else o.DestHost = dest;
            i = 2;
        }
        else if (o.Mode == Mode.Setup)
        {
            // Domaine(s) optionnel en position : setup <domaine[,domaine...]>.
            // Peut aussi etre fourni via --domain.
            if (args.Length >= 2 && !args[1].StartsWith("--"))
            {
                o.Domain = args[1];
                i = 2;
            }
        }

        for (; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--listen":
                    {
                        var v = Value(args, ref i, "--listen");
                        if (v is null || !int.TryParse(v, out o.ListenPort))
                        {
                            Console.Error.WriteLine("--listen attend un numero de port.");
                            return null;
                        }
                        break;
                    }
                case "--bind":
                    {
                        var v = Value(args, ref i, "--bind");
                        if (v is null) return null;
                        if (v.Equals("any", StringComparison.OrdinalIgnoreCase)) o.BindAddress = IPAddress.Any;
                        else if (!IPAddress.TryParse(v, out o.BindAddress!))
                        {
                            Console.Error.WriteLine($"Adresse --bind invalide : {v}");
                            return null;
                        }
                        break;
                    }
                case "--store":
                    {
                        var v = Value(args, ref i, "--store");
                        if (v is null) return null;
                        o.StoreDir = v; break;
                    }
                case "--cert":
                    {
                        var v = Value(args, ref i, "--cert");
                        if (v is null) return null;
                        o.CertPath = v; break;
                    }
                case "--ca":
                    {
                        var v = Value(args, ref i, "--ca");
                        if (v is null) return null;
                        o.CaPath = v; break;
                    }
                case "--domain":
                    {
                        var v = Value(args, ref i, "--domain");
                        if (v is null) return null;
                        o.Domain = v; break;
                    }
                case "--trust": o.Trust = true; break;
                case "--machine": o.Machine = true; break;
                case "--renew": o.Renew = true; break;
                case "--renew-ca": o.RenewCa = true; break;
                case "--set-hosts":
                    {
                        var v = Value(args, ref i, "--set-hosts");
                        if (v is null) return null;
                        int c = v.IndexOf(':');
                        if (c <= 0 || c == v.Length - 1)
                        {
                            Console.Error.WriteLine("--set-hosts attend la forme <domaine>:<ip> (ex. exemple.com:127.0.0.2).");
                            return null;
                        }
                        o.HostsSource = v[..c];
                        o.HostsDest = v[(c + 1)..];
                        break;
                    }
                case "--force-disable-hosts": o.ForceDisableHosts = true; break;
                case "--close-after-replay":
                    {
                        var v = Value(args, ref i, "--close-after-replay");
                        if (v is null || !int.TryParse(v, out o.CloseAfterReplaySec) || o.CloseAfterReplaySec < 0)
                        {
                            Console.Error.WriteLine("--close-after-replay attend un nombre de secondes >= 0.");
                            return null;
                        }
                        break;
                    }
                case "--close-after-timeout":
                    {
                        var v = Value(args, ref i, "--close-after-timeout");
                        if (v is null || !int.TryParse(v, out o.CloseAfterTimeoutSec) || o.CloseAfterTimeoutSec < 0)
                        {
                            Console.Error.WriteLine("--close-after-timeout attend un nombre de secondes >= 0.");
                            return null;
                        }
                        break;
                    }
                case "--sni":
                    {
                        var v = Value(args, ref i, "--sni");
                        if (v is null) return null;
                        o.UpstreamSni = v; break;
                    }
                case "--forward-leftover":
                    {
                        if (o.Mode != Mode.Replay)
                        {
                            Console.Error.WriteLine("--forward-leftover ne s'utilise qu'en mode replay.");
                            return null;
                        }
                        var dest = Value(args, ref i, "--forward-leftover");
                        if (dest is null) return null;
                        int c = dest.LastIndexOf(':');
                        if (c >= 0 && int.TryParse(dest[(c + 1)..], out int dp)) { o.DestHost = dest[..c]; o.DestPort = dp; }
                        else o.DestHost = dest;
                        break;
                    }
                case "--save-misses": o.SaveMisses = true; break;
                default: Console.Error.WriteLine($"Argument inconnu : {args[i]}"); return null;
            }
        }
        return o.Validate() ? o : null;
    }

    private bool Validate()
    {
        if (HostsSource is not null)
        {
            if (IPAddress.TryParse(HostsSource, out _))
            {
                Console.Error.WriteLine("--set-hosts : le premier parametre doit etre un nom de domaine (pas une IP).");
                return false;
            }
            if (HostsDest is null || !IPAddress.TryParse(HostsDest, out _))
            {
                Console.Error.WriteLine("--set-hosts : le second parametre doit etre une adresse IP.");
                return false;
            }
        }
        return true;
    }

    // Lit la valeur qui suit une option. Refuse les valeurs absentes ou qui
    // commencent par "--" (evite d'avaler l'option suivante comme valeur).
    private static string? Value(string[] args, ref int i, string opt)
    {
        if (i + 1 >= args.Length || args[i + 1].StartsWith("--"))
        {
            Console.Error.WriteLine($"L'option {opt} attend une valeur.");
            return null;
        }
        return args[++i];
    }

    public static void PrintUsage()
    {
        Console.Error.WriteLine(
@"Usage :
  setup <domaine[,domaine...]> [--ca .\proxy-ca.pfx] [--cert .\proxy-cert.pfx] [--machine] [--renew] [--renew-ca]
  capture <ip[:port]>          [--bind 0.0.0.0] [--listen 443] [--store .\captures] [--sni host]
                               [--cert .\proxy-cert.pfx] [--ca .\proxy-ca.pfx] [--domain host]
                               [--trust] [--machine] [--renew] [--renew-ca]
                               [--set-hosts <domaine>:<ip>] [--force-disable-hosts]
                               [--close-after-replay <sec>] [--close-after-timeout <sec>]
  replay                       [--bind 0.0.0.0] [--listen 443] [--store .\captures]
                               [--forward-leftover <ip[:port]>] [--save-misses] [--sni host]
                               [--cert .\proxy-cert.pfx] [--ca .\proxy-ca.pfx] [--domain host]
                               [--trust] [--machine] [--renew] [--renew-ca]
                               [--set-hosts <domaine>:<ip>] [--force-disable-hosts]
                               [--close-after-replay <sec>] [--close-after-timeout <sec>]

  --bind              : adresse d'ecoute (defaut 0.0.0.0 = toutes les interfaces). Ex. 127.0.0.2
  --forward-leftover  : (replay) relaie vers cette destination les paths absents de la capture
  --save-misses       : (replay) enregistre aussi les reponses relayees par --forward-leftover
  --domain            : domaine(s) du certificat serveur (virgule = plusieurs). Ex. api.example.com
  --ca                : chemin du .pfx de la CA racine (defaut .\proxy-ca.pfx)
  --trust             : installe la CA dans le magasin Racines de confiance si absente
  --machine           : installe la CA dans LocalMachine (admin requis) au lieu de CurrentUser
  --renew             : regenere le certificat serveur meme s'il existe deja
  --renew-ca          : regenere la CA (nouvelle cle), regenere le certificat serveur
                        et REMPLACE l'ancienne CA dans le magasin Racines de confiance
  --set-hosts <d>:<ip>: active la ligne « <ip> <d> » dans le fichier hosts, puis la
                        restaure a l'arret. Ex. exemple.com:127.0.0.2 (admin requis)
  --force-disable-hosts: a l'arret, desactive la ligne hosts meme si elle etait deja
                        active avant le lancement
  --close-after-replay <sec> : ferme le proxy <sec> s apres la 1re reponse servie en replay
  --close-after-timeout <sec> : ferme le proxy apres <sec> s (quel que soit le trafic)

Exemples :
  dotnet run -- setup api.example.com
  dotnet run -- setup api.example.com --renew-ca
  dotnet run -- capture 11.22.33.44 --domain api.example.com --trust --bind 127.0.0.2 --listen 443
  dotnet run -- replay --forward-leftover 11.22.33.44 --domain exemple.com \
        --set-hosts exemple.com:127.0.0.2 --close-after-replay 5
  dotnet run -- replay --forward-leftover 11.22.33.44 --bind 127.0.0.2 --listen 443");
    }
}

// =============================================================================
//  Wire : source d'octets au-dessus d'un Stream, avec pushback (relecture).
//  Permet de lire des messages HTTP sans « deborder » sur le message suivant.
// =============================================================================
sealed class Wire
{
    private readonly Stream _s;
    private byte[] _pb = Array.Empty<byte>();
    private int _pbPos;

    public Wire(Stream s) => _s = s;

    public int ReadSome(byte[] buf, int off, int len)
    {
        if (_pbPos < _pb.Length)
        {
            int n = Math.Min(len, _pb.Length - _pbPos);
            Array.Copy(_pb, _pbPos, buf, off, n);
            _pbPos += n;
            return n;
        }
        return _s.Read(buf, off, len);
    }

    // Remet des octets devant, a relire avant toute lecture suivante.
    public void Push(byte[] data, int off, int len)
    {
        int rem = _pb.Length - _pbPos;
        var merged = new byte[rem + len];
        Array.Copy(_pb, _pbPos, merged, 0, rem);
        Array.Copy(data, off, merged, rem, len);
        _pb = merged;
        _pbPos = 0;
    }
}

// =============================================================================
//  HttpMessage : lecture/cadrage d'un message HTTP brut (requete ou reponse).
//  On conserve TOUJOURS les octets exacts (Raw) pour un relais/replay fidele.
// =============================================================================
sealed class HttpMessage
{
    public byte[] Raw = Array.Empty<byte>();
    public string FirstLine = "";
    public string Method = "";
    public string Target = "";
    public int StatusCode;
    public bool Http10;
    public int ContentLength = -1;
    public bool Chunked;
    public bool NoBody;
    public bool ConnectionClose;
    public bool ConnectionKeepAlive;
    private readonly Dictionary<string, string> _headers = new(StringComparer.OrdinalIgnoreCase);

    public string? GetHeader(string name) => _headers.TryGetValue(name, out var v) ? v : null;

    // Chemin sans query string (les parametres GET/POST sont ignores).
    public static string NormalizePath(string target)
    {
        if (string.IsNullOrEmpty(target)) return "/";
        // Forme absolue eventuelle (http://host/path) -> on garde a partir du path.
        int scheme = target.IndexOf("://", StringComparison.Ordinal);
        if (scheme >= 0)
        {
            int slash = target.IndexOf('/', scheme + 3);
            target = slash >= 0 ? target[slash..] : "/";
        }
        int q = target.IndexOf('?');
        if (q >= 0) target = target[..q];
        int h = target.IndexOf('#');
        if (h >= 0) target = target[..h];
        return target.Length == 0 ? "/" : target;
    }

    // Lit un message complet depuis le Wire. Retourne null sur fin propre avant
    // tout octet (le pair a ferme la connexion).
    public static HttpMessage? Read(Wire w, bool isResponse)
    {
        // 1) En-tetes : on lit jusqu'a CRLFCRLF.
        var header = new MemoryStream();
        var tmp = new byte[4096];
        int bodyStart = -1;
        while (bodyStart < 0)
        {
            int n = w.ReadSome(tmp, 0, tmp.Length);
            if (n <= 0)
            {
                if (header.Length == 0) return null;
                throw new IOException("fin de flux au milieu des en-tetes");
            }
            header.Write(tmp, 0, n);
            bodyStart = FindDoubleCrlf(header.GetBuffer(), (int)header.Length);
        }

        byte[] hbuf = header.GetBuffer();
        int hlen = (int)header.Length;
        // Octets deja lus au-dela des en-tetes : debut du corps, a reinjecter.
        if (hlen > bodyStart) w.Push(hbuf, bodyStart, hlen - bodyStart);

        var msg = new HttpMessage();
        var body = new MemoryStream();
        body.Write(hbuf, 0, bodyStart); // les en-tetes font partie du Raw
        msg.ParseHeaders(hbuf, bodyStart, isResponse);

        // 2) Corps : cadrage selon chunked / Content-Length / fermeture.
        if (!msg.NoBody)
        {
            if (msg.Chunked) ReadChunked(w, body);
            else if (msg.ContentLength > 0) ReadExact(w, body, msg.ContentLength);
            else if (msg.ContentLength < 0 && isResponse) ReadToEnd(w, body); // reponse sans longueur -> jusqu'a fermeture
            // requete sans Content-Length -> pas de corps (ex. GET)
        }

        msg.Raw = body.ToArray();
        return msg;
    }

    // Variante : parse des octets deja complets (utile en replay).
    public static HttpMessage Parse(byte[] raw, bool isResponse)
    {
        int bodyStart = FindDoubleCrlf(raw, raw.Length);
        if (bodyStart < 0) bodyStart = raw.Length;
        var msg = new HttpMessage { Raw = raw };
        msg.ParseHeaders(raw, bodyStart, isResponse);
        return msg;
    }

    private void ParseHeaders(byte[] buf, int headerLen, bool isResponse)
    {
        string text = Encoding.Latin1.GetString(buf, 0, headerLen);
        var lines = text.Split("\r\n");
        FirstLine = lines.Length > 0 ? lines[0] : "";

        for (int i = 1; i < lines.Length; i++)
        {
            var line = lines[i];
            if (line.Length == 0) break;
            int c = line.IndexOf(':');
            if (c < 0) continue;
            string name = line[..c].Trim();
            string val = line[(c + 1)..].Trim();
            _headers[name] = val;

            if (name.Equals("content-length", StringComparison.OrdinalIgnoreCase))
                int.TryParse(val, out ContentLength);
            else if (name.Equals("transfer-encoding", StringComparison.OrdinalIgnoreCase)
                     && val.Contains("chunked", StringComparison.OrdinalIgnoreCase))
                Chunked = true;
            else if (name.Equals("connection", StringComparison.OrdinalIgnoreCase))
            {
                if (val.Contains("close", StringComparison.OrdinalIgnoreCase)) ConnectionClose = true;
                if (val.Contains("keep-alive", StringComparison.OrdinalIgnoreCase)) ConnectionKeepAlive = true;
            }
        }

        var parts = FirstLine.Split(' ');
        if (isResponse)
        {
            Http10 = FirstLine.StartsWith("HTTP/1.0", StringComparison.Ordinal);
            if (parts.Length >= 2) int.TryParse(parts[1], out StatusCode);
            NoBody = StatusCode is >= 100 and < 200 or 204 or 304;
        }
        else
        {
            if (parts.Length >= 1) Method = parts[0];
            if (parts.Length >= 2) Target = parts[1];
            Http10 = FirstLine.EndsWith("HTTP/1.0", StringComparison.Ordinal);
        }
    }

    private static void ReadExact(Wire w, MemoryStream dst, int count)
    {
        var buf = new byte[8192];
        int left = count;
        while (left > 0)
        {
            int n = w.ReadSome(buf, 0, Math.Min(buf.Length, left));
            if (n <= 0) throw new IOException("fin de flux prematuree dans le corps");
            dst.Write(buf, 0, n);
            left -= n;
        }
    }

    private static void ReadToEnd(Wire w, MemoryStream dst)
    {
        var buf = new byte[8192];
        int n;
        while ((n = w.ReadSome(buf, 0, buf.Length)) > 0) dst.Write(buf, 0, n);
    }

    private static void ReadChunked(Wire w, MemoryStream dst)
    {
        while (true)
        {
            string sizeLine = ReadLine(w, dst);           // ex. "1a\r\n" (ecrit tel quel dans dst)
            string hex = sizeLine.Split(';')[0].Trim();
            int size = Convert.ToInt32(hex, 16);
            if (size == 0)
            {
                // trailers eventuels jusqu'a une ligne vide.
                while (true)
                {
                    string t = ReadLine(w, dst);
                    if (t == "\r\n" || t == "\n" || t.Length == 0) break;
                }
                return;
            }
            ReadExact(w, dst, size);
            ReadLine(w, dst); // CRLF de fin de chunk
        }
    }

    // Lit une ligne terminee par LF (CRLF conserve), l'ecrit dans dst, la retourne.
    private static string ReadLine(Wire w, MemoryStream dst)
    {
        var sb = new List<byte>(32);
        var one = new byte[1];
        while (true)
        {
            int n = w.ReadSome(one, 0, 1);
            if (n <= 0) break;
            dst.WriteByte(one[0]);
            sb.Add(one[0]);
            if (one[0] == (byte)'\n') break;
        }
        return Encoding.Latin1.GetString(sb.ToArray());
    }

    private static int FindDoubleCrlf(byte[] buf, int len)
    {
        for (int i = 0; i + 3 < len; i++)
            if (buf[i] == 13 && buf[i + 1] == 10 && buf[i + 2] == 13 && buf[i + 3] == 10)
                return i + 4;
        return -1;
    }
}

// =============================================================================
//  Store : persistance des reponses capturees, indexees par path.
//  Un fichier .bin par path (derniere reponse) + un .meta.txt lisible.
// =============================================================================
static class Store
{
    public static void Save(string dir, string path, HttpMessage req, HttpMessage resp)
    {
        string baseName = KeyToBaseName(path);
        File.WriteAllBytes(Path.Combine(dir, baseName + ".response.bin"), resp.Raw);
        File.WriteAllBytes(Path.Combine(dir, baseName + ".request.bin"), req.Raw);
        File.WriteAllText(Path.Combine(dir, baseName + ".meta.txt"),
            $"date      : {DateTime.Now:yyyy-MM-dd HH:mm:ss}\n" +
            $"path      : {path}\n" +
            $"requete   : {req.FirstLine}\n" +
            $"reponse   : {resp.FirstLine}\n" +
            $"taille    : {resp.Raw.Length} octets\n", Encoding.UTF8);
    }

    public static byte[]? Load(string dir, string path)
    {
        string file = Path.Combine(dir, KeyToBaseName(path) + ".response.bin");
        return File.Exists(file) ? File.ReadAllBytes(file) : null;
    }

    // Nom de fichier deterministe et sans collision : path assaini + hash court.
    private static string KeyToBaseName(string path)
    {
        var sb = new StringBuilder();
        foreach (char ch in path)
            sb.Append(char.IsLetterOrDigit(ch) ? ch : '_');
        string safe = sb.ToString();
        if (safe.Length == 0) safe = "root";
        if (safe.Length > 60) safe = safe[..60];

        byte[] h = SHA256.HashData(Encoding.UTF8.GetBytes(path));
        string shortHash = Convert.ToHexString(h, 0, 4).ToLowerInvariant();
        return $"{safe}_{shortHash}";
    }
}

// =============================================================================
//  CertStore : autorite de certification (CA) locale + certificat serveur.
//  La CA est auto-signee et stable (generee une fois, relue ensuite). Elle peut
//  etre installee dans le magasin « Racines de confiance » Windows pour que le
//  client fasse confiance au proxy sans option -k.
//  Le certificat serveur est signe par la CA et couvre les domaines demandes
//  (SAN + CN), plus localhost / la loopback pour un usage local.
// =============================================================================
static class CertStore
{
    private const string Pw = "proxy";
    private const string ServerAuthOid = "1.3.6.1.5.5.7.3.1";

    // CA racine auto-signee (KeyCertSign). Reutilisee si elle existe deja, sauf
    // si renew est demande (nouvelle cle, l'ancienne peut alors etre remplacee).
    public static X509Certificate2 GetOrCreateCa(string caPath, bool renew = false)
    {
        if (File.Exists(caPath) && !renew)
            return Load(caPath);

        using var rsa = RSA.Create(3072);
        var req = new CertificateRequest("CN=HttpsProxy Root CA", rsa,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, false));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));

        using var cert = req.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(10));

        Write(caPath, cert);
        Console.WriteLine($"CA racine generee : {Path.GetFullPath(caPath)}");
        return Load(caPath);
    }

    // Certificat serveur signe par la CA, couvrant les domaines fournis.
    public static X509Certificate2 GetOrCreateServer(string certPath, X509Certificate2 ca,
                                                     IEnumerable<string> domains, bool renew)
    {
        if (File.Exists(certPath) && !renew)
            return Load(certPath);

        var list = domains
            .Where(d => !string.IsNullOrWhiteSpace(d))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (list.Count == 0) list.Add("localhost");
        string cn = list[0];

        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest($"CN={cn}", rsa,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var san = new SubjectAlternativeNameBuilder();
        foreach (var d in list)
        {
            if (IPAddress.TryParse(d, out var ip)) san.AddIpAddress(ip);
            else san.AddDnsName(d);
        }
        san.AddDnsName("localhost");
        san.AddIpAddress(IPAddress.Loopback);
        req.CertificateExtensions.Add(san.Build());

        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new Oid(ServerAuthOid) }, false)); // serverAuth
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));

        byte[] serial = new byte[16];
        RandomNumberGenerator.Fill(serial);
        serial[0] &= 0x7F; // serial positif (contrainte de certains clients)

        // Create() renvoie un certificat SANS cle privee (seule la cle publique du
        // sujet y figure). On y rattache notre RSA pour que le .pfx exporte contienne
        // bien la cle privee, requise par SslStream cote serveur.
        using var signed = req.Create(ca, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(2), serial);
        using var withKey = signed.CopyWithPrivateKey(rsa);
        Write(certPath, withKey);
        Console.WriteLine($"Certificat serveur genere : {Path.GetFullPath(certPath)}  (CN={cn})");
        return Load(certPath);
    }

    private static X509Certificate2 Load(string path) =>
        new(path, Pw, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

    private static void Write(string path, X509Certificate2 cert)
    {
        byte[] pfx = cert.Export(X509ContentType.Pfx, Pw);
        File.WriteAllBytes(path, pfx);
    }
}

// =============================================================================
//  WindowsTrustStore : presence / installation d'un certificat dans le magasin
//  « Racines de confiance » (Root) de Windows.
//  CurrentUser ne requiert pas l'admin ; LocalMachine oui.
// =============================================================================
static class WindowsTrustStore
{
    public static bool IsTrusted(X509Certificate2 cert, bool machine)
    {
        using var store = Open(StoreName.Root, machine, OpenFlags.ReadOnly);
        if (store is null) return false;
        foreach (var c in store.Certificates)
            if (string.Equals(c.Thumbprint, cert.Thumbprint, StringComparison.OrdinalIgnoreCase))
                return true;
        return false;
    }

    public static void Trust(X509Certificate2 cert, bool machine)
    {
        using var store = Open(StoreName.Root, machine, OpenFlags.ReadWrite)
            ?? throw new InvalidOperationException("magasin « Racines de confiance » indisponible");
        store.Add(cert);
    }

    // Supprime les certificats du meme sujet (anciennes CA) puis ajoute le nouveau.
    // Retourne le nombre d'anciens certificats retires.
    public static int Replace(X509Certificate2 cert, bool machine)
    {
        using var store = Open(StoreName.Root, machine, OpenFlags.ReadWrite)
            ?? throw new InvalidOperationException("magasin « Racines de confiance » indisponible");

        var toRemove = new List<X509Certificate2>();
        foreach (var c in store.Certificates)
            if (string.Equals(c.Subject, cert.Subject, StringComparison.OrdinalIgnoreCase)
                && !string.Equals(c.Thumbprint, cert.Thumbprint, StringComparison.OrdinalIgnoreCase))
                toRemove.Add(c);

        foreach (var c in toRemove)
            store.Remove(c);

        store.Add(cert);
        return toRemove.Count;
    }

    private static X509Store? Open(StoreName name, bool machine, OpenFlags flags)
    {
        var location = machine ? StoreLocation.LocalMachine : StoreLocation.CurrentUser;
        try
        {
            var store = new X509Store(name, location);
            store.Open(flags);
            return store;
        }
        catch
        {
            return null;
        }
    }
}

// =============================================================================
//  HostsFile : activation / desactivation d'une ligne dans le fichier hosts
//  Windows (C:\Windows\System32\drivers\etc\hosts).
//  L'activation de-commente (ou ajoute) la ligne « <dest> <source> » ; la
//  desactivation la re-commente (ou la supprime si on l'avait ajoutee).
//  On memorise l'etat initial pour pouvoir le restaurer a l'arret.
// =============================================================================
static class HostsFile
{
    private static readonly string Path = System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "drivers", "etc", "hosts");

    public enum InitialState { Absent, Active, Commented }

    public static bool TryActivate(string ip, string domain, out InitialState initialState, out string? error)
    {
        initialState = InitialState.Absent;
        error = null;
        try
        {
            var lines = File.ReadAllLines(Path).ToList();
            for (int i = 0; i < lines.Count; i++)
            {
                if (!Match(lines[i], ip, domain)) continue;
                if (IsCommented(lines[i]))
                {
                    initialState = InitialState.Commented;
                    lines[i] = Uncomment(lines[i]);
                    File.WriteAllLines(Path, lines);
                }
                else
                {
                    initialState = InitialState.Active;
                }
                return true;
            }
            lines.Add($"{ip} {domain}");
            File.WriteAllLines(Path, lines);
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    public static bool TryDeactivate(string ip, string domain, InitialState initialState, bool force, out string? error)
    {
        error = null;
        // Deja active a l'origine : on la laisse, sauf si force est demande.
        if (initialState == InitialState.Active && !force) return true;
        try
        {
            var lines = File.ReadAllLines(Path).ToList();
            for (int i = 0; i < lines.Count; i++)
            {
                if (!Match(lines[i], ip, domain)) continue;
                if (initialState == InitialState.Absent)
                    lines.RemoveAt(i);
                else
                    lines[i] = Comment(lines[i]);
                File.WriteAllLines(Path, lines);
                return true;
            }
            return true; // ligne deja absente (supprimee manuellement)
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private static bool Match(string line, string ip, string domain)
    {
        string t = line.Trim();
        if (t.StartsWith('#')) t = t[1..].TrimStart();
        int hash = t.IndexOf('#');
        if (hash >= 0) t = t[..hash].Trim();
        var parts = t.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
        return parts.Length == 2
            && string.Equals(parts[0], ip, StringComparison.OrdinalIgnoreCase)
            && string.Equals(parts[1], domain, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsCommented(string line) => line.TrimStart().StartsWith('#');

    private static string Uncomment(string line)
    {
        int idx = line.IndexOf('#');
        return idx >= 0 ? line.Remove(idx, 1) : line;
    }

    private static string Comment(string line) => "# " + line.TrimStart();
}

// =============================================================================
//  CloseController : fermeture planifiee apres un replay reussi (arme une seule
//  fois), via l'annulation du CancellationTokenSource partage.
// =============================================================================
sealed class CloseController
{
    private readonly CancellationTokenSource _cts;
    private readonly int _delaySec;
    private int _armed;

    public CloseController(CancellationTokenSource cts, int delaySec)
    {
        _cts = cts;
        _delaySec = delaySec;
    }

    public void NotifyReplaySuccess()
    {
        if (_delaySec < 0) return;
        if (Interlocked.Exchange(ref _armed, 1) != 0) return;
        _ = Task.Run(async () =>
        {
            try { await Task.Delay(_delaySec * 1000, _cts.Token); }
            catch (OperationCanceledException) { return; }
            _cts.Cancel();
        });
    }
}
