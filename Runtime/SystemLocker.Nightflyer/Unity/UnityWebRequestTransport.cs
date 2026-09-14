// Engine adapter: the only runtime file in this package that references
// UnityEngine. The protocol and session layers remain engine-independent.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using UnityEngine;
using UnityEngine.Networking;

namespace SystemLocker.Nightflyer.Unity
{
    /// <summary>Installs the UnityWebRequest-based transport as the package default.</summary>
    public static class NightflyerUnityRuntime
    {
        internal static SynchronizationContext? MainThreadContext { get; private set; }
        internal static int MainThreadId { get; private set; }

        [RuntimeInitializeOnLoadMethod(RuntimeInitializeLoadType.AfterAssembliesLoaded)]
        private static void Install()
        {
            // UnityWebRequest may only be used from the engine's main thread;
            // session continuations run on worker threads, so the transport
            // marshals the request start back to the context captured here.
            MainThreadContext = SynchronizationContext.Current;
            MainThreadId = Thread.CurrentThread.ManagedThreadId;
            NightflyerTransports.DefaultTransportFactory =
                (timeout, userAgent) => new UnityWebRequestTransport(timeout, userAgent);
        }
    }

    /// <summary>
    /// HTTPS POST transport over UnityWebRequest. Redirects are disabled
    /// (redirectLimit 0 fails the request), response bodies are capped at
    /// 1 MiB while streaming, and any non-2xx status is surfaced with its body
    /// so the client can verify signed denials.
    /// </summary>
    public sealed class UnityWebRequestTransport : INightflyerTransport
    {
        private const int MaxResponseBytes = 1024 * 1024;
        private readonly TimeSpan _timeout;
        private readonly string _userAgent;

        public UnityWebRequestTransport(TimeSpan timeout, string userAgent)
        {
            _timeout = timeout;
            _userAgent = userAgent;
        }

        public Task<HttpExchange> PostJsonAsync(
            string url,
            string body,
            IReadOnlyDictionary<string, string> headers,
            CancellationToken cancellationToken = default)
        {
            if (cancellationToken.IsCancellationRequested)
                return Task.FromCanceled<HttpExchange>(cancellationToken);

            var completion = new TaskCompletionSource<HttpExchange>(TaskCreationOptions.RunContinuationsAsynchronously);
            try
            {
                RunOnMainThread(() =>
                {
                    CancellationTokenRegistration cancellation = default;
                    UnityWebRequest? request = null;
                    try
                    {
                        var handler = new BoundedDownloadHandler();
                        request = new UnityWebRequest(url, "POST")
                        {
                            redirectLimit = 0,
                            timeout = Math.Max(1, (int)Math.Ceiling(_timeout.TotalSeconds)),
                            uploadHandler = new UploadHandlerRaw(Encoding.UTF8.GetBytes(body)),
                            downloadHandler = handler,
                        };
                        var activeRequest = request;
                        activeRequest.SetRequestHeader("Content-Type", "application/json");
                        activeRequest.SetRequestHeader("Accept", "application/json");
                        activeRequest.SetRequestHeader("Cache-Control", "no-store");
                        activeRequest.SetRequestHeader("User-Agent", _userAgent);
                        foreach (var header in headers) activeRequest.SetRequestHeader(header.Key, header.Value);

                        // Unity documents that Abort may be called before or after
                        // SendWebRequest. Complete the Task immediately, then marshal
                        // the engine call so cancellation never strands a caller.
                        cancellation = cancellationToken.Register(() =>
                        {
                            completion.TrySetCanceled();
                            try
                            {
                                RunOnMainThread(() =>
                                {
                                    // The completion callback may have disposed
                                    // the request before this posted abort runs.
                                    try { activeRequest.Abort(); }
                                    catch (Exception) { }
                                });
                            }
                            catch (Exception) { }
                        });

                        var operation = activeRequest.SendWebRequest();
                        operation.completed += _ =>
                        {
                            cancellation.Dispose();
                            try
                            {
                                if (cancellationToken.IsCancellationRequested) completion.TrySetCanceled();
                                else completion.TrySetResult(Complete(activeRequest, handler));
                            }
                            finally { activeRequest.Dispose(); }
                        };
                    }
                    catch (Exception exception)
                    {
                        cancellation.Dispose();
                        request?.Dispose();
                        completion.TrySetResult(new HttpExchange(0, Array.Empty<byte>(), exception.Message));
                    }
                });
            }
            catch (Exception exception)
            {
                completion.TrySetResult(new HttpExchange(0, Array.Empty<byte>(), exception.Message));
            }
            return completion.Task;
        }

        private static void RunOnMainThread(Action action)
        {
            if (Thread.CurrentThread.ManagedThreadId == NightflyerUnityRuntime.MainThreadId)
            {
                action();
                return;
            }

            var context = NightflyerUnityRuntime.MainThreadContext;
            if (context is not null)
            {
                context.Post(state => ((Action)state!)(), action);
                return;
            }
            throw new InvalidOperationException("Nightflyer could not dispatch an HTTP request to Unity's main thread.");
        }

        private static HttpExchange Complete(UnityWebRequest request, BoundedDownloadHandler handler)
        {
            if (handler.Overflowed)
                return new HttpExchange(0, Array.Empty<byte>(), "response body exceeds 1 MiB limit");

            var status = (int)request.responseCode;
            if (status == 0)
                return new HttpExchange(0, Array.Empty<byte>(), string.IsNullOrEmpty(request.error) ? "UnityWebRequest failed" : request.error);

            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var responseHeaders = request.GetResponseHeaders();
            if (responseHeaders is not null)
            {
                foreach (var pair in responseHeaders)
                {
                    if (pair.Value is not null) headers[pair.Key] = pair.Value;
                }
            }
            return new HttpExchange(status, handler.TakeData(), Headers: headers);
        }

        /// <summary>
        /// Buffers the response while enforcing the 1 MiB protocol bound as data
        /// arrives instead of after the whole body has been downloaded.
        /// </summary>
        private sealed class BoundedDownloadHandler : DownloadHandlerScript
        {
            private readonly MemoryStream _buffer = new();

            internal bool Overflowed { get; private set; }

            protected override bool ReceiveData(byte[] data, int dataLength)
            {
                if (Overflowed) return false;
                if (dataLength <= 0) return true;
                if (_buffer.Length + dataLength > MaxResponseBytes)
                {
                    // Returning false makes Unity abort the download immediately;
                    // the completed callback still reports the bounded-body error.
                    Overflowed = true;
                    _buffer.SetLength(0);
                    return false;
                }
                _buffer.Write(data, 0, dataLength);
                return true;
            }

            internal byte[] TakeData() => _buffer.ToArray();
        }
    }
}
