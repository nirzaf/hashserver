using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

class HashServer
{
    public static void Main(string[] args)
    {
        if (args.Length != 2 || !int.TryParse(args[1], out var delay))
        {
            Console.WriteLine("Usage: hashserver <port> <delay-milliseconds>");
            return;
        }

        var server = new TcpListener(IPAddress.Any, Int32.Parse(args[0]));

        Console.CancelKeyPress += (o, ev) => { ev.Cancel = true; server.Stop(); };
        try
        {
            server.Start();
            while (true)
            {
                var client = server.AcceptTcpClient();
                Task.Run(() => HandleClient(client, delay));
                //HandleClient(client, delay);
            }
        }
        catch (SocketException ex)
        {
            if ((int)ex.SocketErrorCode != 10004)
            {
                Console.WriteLine($"Error: {ex}");
            }
        }
    }

    static void HandleClient(TcpClient client, int delayMilliseconds)
    {
        try
        {
            var rnd = new Random();
            var buffer = new byte[4096];
            var stream = client.GetStream();
            var hashes = new HashAlgorithm[] { MD5.Create(), SHA1.Create(), SHA256.Create() };

            var nread = stream.Read(buffer, 0, 8);
            if (nread < 8)
            {
                Console.WriteLine("Error: invalid data size");
                return;
            }
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(buffer, 0, 8);
            }
            var payloadSize = BitConverter.ToInt64(buffer);

            while (payloadSize >= 0)
            {
                nread = stream.Read(buffer, 0, buffer.Length);
                if (nread == payloadSize)
                {
                    foreach (var hash in hashes)
                    {
                        hash.TransformFinalBlock(buffer, 0, nread);
                        stream.Write(hash.Hash);
                    }
                    break;
                }
                foreach (var hash in hashes)
                {
                    hash.TransformBlock(buffer, 0, nread, buffer, 0);
                }
                if (delayMilliseconds > 0)
                {
                    Thread.Sleep(rnd.Next(delayMilliseconds));
                }
                
                payloadSize -= buffer.Length;
            }
        }
        finally
        {
            client.Dispose();
        }
    }
}