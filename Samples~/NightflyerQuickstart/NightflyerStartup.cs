using System.Collections;
using System.Collections.Generic;
using System.Threading.Tasks;
using SystemLocker.Nightflyer;
using UnityEngine;

namespace SystemLocker.Nightflyer.Samples
{
    /// <summary>
    /// Minimal startup gate: requests an offline-capable Nightflyer lease before
    /// the protected scene work runs. Attach to a bootstrap GameObject and point
    /// protectedSceneName at the scene that needs a license.
    /// </summary>
    public sealed class NightflyerStartup : MonoBehaviour
    {
        private static NightflyerStartup? _instance;

        [SerializeField] private string systemId = "abcdefghijklmnopqrst";
        [SerializeField] private string signingKeyId = "YOUR_KID";
        [SerializeField, TextArea] private string signingKeyBase64Url = "YOUR_BASE64URL_ED25519_KEY";
        [SerializeField] private string protectedSceneName = "Main";

        private NightflyerAuthorizationSession? _session;
        private bool _authorizing;

        private void Awake()
        {
            if (_instance is not null && _instance != this)
            {
                Destroy(gameObject);
                return;
            }

            _instance = this;
            DontDestroyOnLoad(gameObject);
        }

        private IEnumerator Start()
        {
            var config = new NightflyerConfig(systemId, new Dictionary<string, string>
            {
                [signingKeyId] = signingKeyBase64Url,
            });
            _session = NightflyerAuthorizationSession.CreateMemory(config);
            yield return Authorize(null);
        }

        /// <summary>Connect this to the submit action in your license-key UI.</summary>
        public void SubmitLicenseKey(string licenseKey)
        {
            if (_session is null || _authorizing) return;
            StartCoroutine(Authorize(string.IsNullOrEmpty(licenseKey) ? null : licenseKey));
        }

        private IEnumerator Authorize(string? licenseKey)
        {
            if (_session is null) yield break;
            _authorizing = true;
            var startup = _session.EasyAuthorizeAsync(
                new NightflyerBinding(Application.version, "", SystemInfo.deviceUniqueIdentifier),
                requestedOfflineSeconds: 86400,
                licenseKey: licenseKey);
            while (!startup.IsCompleted) yield return null;
            _authorizing = false;

            if (startup.IsFaulted)
            {
                Debug.LogError($"Nightflyer startup failed: {startup.Exception?.GetBaseException().Message}");
                yield break;
            }
            if (startup.IsCanceled) yield break;

            var result = startup.Result;
            if (result.CanProceed)
            {
                Debug.Log($"Nightflyer authorized until {result.Lease!.ExpiresAt:O}.");
                UnityEngine.SceneManagement.SceneManager.LoadScene(protectedSceneName);
            }
            else if (result.ShouldPromptForKey)
            {
                Debug.Log("Nightflyer needs a license key. Show your key UI and pass its value to SubmitLicenseKey.");
            }
            else
            {
                Debug.LogWarning($"Nightflyer denied: {result.Diagnostic} (recommended: {result.RecommendedAction}).");
            }
        }

        private async void OnApplicationQuit() => await ShutdownSessionAsync();

        private async void OnDestroy()
        {
            if (_instance != this) return;
            _instance = null;
            await ShutdownSessionAsync();
        }

        private async Task ShutdownSessionAsync()
        {
            // Unity does not wait for application-quit callbacks. Detaching the
            // field prevents duplicate cleanup, while ShutdownAsync gives normal
            // scene teardown a chance to release a memory-only lease cleanly.
            var session = _session;
            _session = null;
            if (session is null) return;
            await session.ShutdownAsync();
            session.Dispose();
        }
    }
}
