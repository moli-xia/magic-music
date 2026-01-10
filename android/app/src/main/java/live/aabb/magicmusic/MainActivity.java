package live.aabb.magicmusic;

import android.annotation.SuppressLint;
import android.app.DownloadManager;
import android.content.Context;
import android.graphics.Color;
import android.media.AudioAttributes;
import android.media.AudioFocusRequest;
import android.media.AudioManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.PowerManager;
import android.view.View;
import android.view.WindowInsetsController;
import android.webkit.CookieManager;
import android.webkit.JavascriptInterface;
import android.webkit.URLUtil;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import androidx.activity.OnBackPressedCallback;
import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {
  private static final String START_URL = "https://music.aabb.live/";
  private WebView webView;
  private AudioManager audioManager;
  private AudioFocusRequest audioFocusRequest;
  private AudioManager.OnAudioFocusChangeListener audioFocusChangeListener;
  private PowerManager.WakeLock wakeLock;
  private boolean playbackActive = false;
  private boolean hasAudioFocus = false;
  private boolean everHadAudioFocusForThisPlayback = false;
  private long playbackActivatedAtMs = 0L;
  private boolean themeObserverInjected = false;

  @SuppressLint("SetJavaScriptEnabled")
  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_main);

    webView = findViewById(R.id.webview);
    initPlaybackGuards();

    WebSettings settings = webView.getSettings();
    settings.setJavaScriptEnabled(true);
    settings.setDomStorageEnabled(true);
    settings.setDatabaseEnabled(true);
    settings.setMediaPlaybackRequiresUserGesture(false);
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
      settings.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);
    }
    settings.setLoadWithOverviewMode(true);
    settings.setUseWideViewPort(true);
    settings.setSupportZoom(false);
    settings.setBuiltInZoomControls(false);
    settings.setDisplayZoomControls(false);
    settings.setUserAgentString(
        "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36");

    CookieManager cookieManager = CookieManager.getInstance();
    cookieManager.setAcceptCookie(true);
    cookieManager.setAcceptThirdPartyCookies(webView, true);

    webView.setWebChromeClient(new WebChromeClient() {
        @Override
        public void onPermissionRequest(final android.webkit.PermissionRequest request) {
            request.grant(request.getResources());
        }
    });
    webView.setDownloadListener(
        (url, userAgent, contentDisposition, mimeType, contentLength) -> {
          try {
            Uri uri = Uri.parse(url);
            String fileName = uri.getQueryParameter("filename");
            if (fileName == null || fileName.trim().isEmpty()) {
              fileName = URLUtil.guessFileName(url, contentDisposition, mimeType);
            }
            if (fileName == null || fileName.trim().isEmpty()) {
              fileName = "music";
            }
            fileName = fileName.replaceAll("[\\\\/:*?\"<>|]+", "_");

            DownloadManager.Request request = new DownloadManager.Request(uri);
            if (mimeType != null && !mimeType.trim().isEmpty()) {
              request.setMimeType(mimeType);
            }
            if (userAgent != null && !userAgent.trim().isEmpty()) {
              request.addRequestHeader("User-Agent", userAgent);
            }
            String cookie = CookieManager.getInstance().getCookie(url);
            if (cookie != null && !cookie.trim().isEmpty()) {
              request.addRequestHeader("Cookie", cookie);
            }
            request.setTitle(fileName);
            request.setNotificationVisibility(
                DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED);
            request.setDestinationInExternalPublicDir(Environment.DIRECTORY_DOWNLOADS, fileName);

            DownloadManager dm = (DownloadManager) getSystemService(Context.DOWNLOAD_SERVICE);
            if (dm != null) {
              dm.enqueue(request);
            }
          } catch (Exception ignored) {
          }
        });
    webView.addJavascriptInterface(new ThemeBridge(), "MagicMusicAndroid");
    webView.setWebViewClient(
        new WebViewClient() {
          @Override
          public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
            return false;
          }

          @Override
          public void onPageStarted(WebView view, String url, android.graphics.Bitmap favicon) {
            super.onPageStarted(view, url, favicon);
            themeObserverInjected = false;
          }

          @Override
          public void onPageFinished(WebView view, String url) {
            super.onPageFinished(view, url);
            if (!themeObserverInjected) {
              injectThemeObserver(view);
              themeObserverInjected = true;
            }
          }
        });

    if (savedInstanceState != null) {
      webView.restoreState(savedInstanceState);
    } else {
      webView.loadUrl(START_URL);
    }

    getOnBackPressedDispatcher()
        .addCallback(
            this,
            new OnBackPressedCallback(true) {
              @Override
              public void handleOnBackPressed() {
                if (webView == null) {
                  finish();
                  return;
                }

                webView.evaluateJavascript(
                    "(function(){try{var p=String(location.pathname||'');"
                        + "if(p==='/player'){"
                        + "history.replaceState({},'', '/playlists');"
                        + "try{window.dispatchEvent(new PopStateEvent('popstate'));}catch(e){}"
                        + "return '1';"
                        + "}"
                        + "return '0';"
                        + "}catch(e){return '0';}})();",
                    value -> {
                      String v = value == null ? "" : value.replace("\"", "").trim();
                      if ("1".equals(v)) {
                        return;
                      }
                      if (webView.canGoBack()) {
                        webView.goBack();
                        return;
                      }
                      finish();
                    });
              }
            });
  }

  @Override
  protected void onPause() {
    super.onPause();
  }

  @Override
  protected void onResume() {
    super.onResume();
    if (playbackActive) {
      requestAudioFocus();
      acquireWakeLock();
    }
  }

  @Override
  protected void onSaveInstanceState(Bundle outState) {
    super.onSaveInstanceState(outState);
    if (webView != null) {
      webView.saveState(outState);
    }
  }

  @Override
  protected void onDestroy() {
    setPlaybackActive(false);
    if (webView != null) {
      webView.destroy();
      webView = null;
    }
    super.onDestroy();
  }

  private void initPlaybackGuards() {
    audioManager = (AudioManager) getSystemService(Context.AUDIO_SERVICE);
    audioFocusChangeListener =
        focusChange -> {
          if (focusChange == AudioManager.AUDIOFOCUS_GAIN) {
            hasAudioFocus = true;
            everHadAudioFocusForThisPlayback = true;
            return;
          }
          if (focusChange == AudioManager.AUDIOFOCUS_LOSS
              || focusChange == AudioManager.AUDIOFOCUS_LOSS_TRANSIENT) {
            hasAudioFocus = false;
            return;
          }
          if (focusChange == AudioManager.AUDIOFOCUS_LOSS_TRANSIENT_CAN_DUCK) {
            hasAudioFocus = false;
          }
        };

    PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
    if (pm != null) {
      wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "MagicMusic:Playback");
      wakeLock.setReferenceCounted(false);
    }
  }

  private void setPlaybackActive(boolean active) {
    playbackActive = active;
    if (active) {
      playbackActivatedAtMs = android.os.SystemClock.elapsedRealtime();
      everHadAudioFocusForThisPlayback = false;
      requestAudioFocus();
      acquireWakeLock();
    } else {
      releaseWakeLock();
      abandonAudioFocus();
    }
  }

  private void requestAudioFocus() {
    if (audioManager == null) return;
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
      AudioAttributes attrs =
          new AudioAttributes.Builder()
              .setUsage(AudioAttributes.USAGE_MEDIA)
              .setContentType(AudioAttributes.CONTENT_TYPE_MUSIC)
              .build();
      audioFocusRequest =
          new AudioFocusRequest.Builder(AudioManager.AUDIOFOCUS_GAIN)
              .setAudioAttributes(attrs)
              .setOnAudioFocusChangeListener(audioFocusChangeListener)
              .build();
      int result = audioManager.requestAudioFocus(audioFocusRequest);
      hasAudioFocus = result == AudioManager.AUDIOFOCUS_REQUEST_GRANTED;
      return;
    }

    int result =
        audioManager.requestAudioFocus(
            audioFocusChangeListener, AudioManager.STREAM_MUSIC, AudioManager.AUDIOFOCUS_GAIN);
    hasAudioFocus = result == AudioManager.AUDIOFOCUS_REQUEST_GRANTED;
  }

  private void abandonAudioFocus() {
    if (audioManager == null) return;
    hasAudioFocus = false;
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
      if (audioFocusRequest != null) {
        audioManager.abandonAudioFocusRequest(audioFocusRequest);
      }
      return;
    }
    audioManager.abandonAudioFocus(audioFocusChangeListener);
  }

  private void acquireWakeLock() {
    if (wakeLock == null) return;
    if (!wakeLock.isHeld()) {
      wakeLock.acquire(10 * 60 * 1000L);
    }
  }

  private void releaseWakeLock() {
    if (wakeLock == null) return;
    if (wakeLock.isHeld()) {
      wakeLock.release();
    }
  }

  private void injectThemeObserver(WebView view) {
    String js =
        "(function(){"
            + "function mmSend(){"
            + "try{"
            + "var isLight=document.documentElement.classList.contains('light');"
            + "if(window.MagicMusicAndroid&&window.MagicMusicAndroid.setTheme){"
            + "window.MagicMusicAndroid.setTheme(isLight?'light':'dark');"
            + "}"
            + "}catch(e){}"
            + "}"
            + "mmSend();"
            + "try{new MutationObserver(mmSend).observe(document.documentElement,{attributes:true,attributeFilter:['class']});}catch(e){}"
            + "})();";
    view.evaluateJavascript(js, null);
  }

  private void applySystemBarTheme(boolean isLight) {
    int lightColor = Color.rgb(245, 245, 245);
    int darkColor = Color.rgb(18, 18, 18);
    int targetColor = isLight ? lightColor : darkColor;

    getWindow().setStatusBarColor(targetColor);
    getWindow().setNavigationBarColor(targetColor);

    int lightAppearanceMask =
        WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS
            | WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS;

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
      WindowInsetsController controller = getWindow().getInsetsController();
      if (controller != null) {
        controller.setSystemBarsAppearance(isLight ? lightAppearanceMask : 0, lightAppearanceMask);
      }
      return;
    }

    View decor = getWindow().getDecorView();
    int flags = decor.getSystemUiVisibility();

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
      if (isLight) {
        flags |= View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR;
      } else {
        flags &= ~View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR;
      }
    }

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
      if (isLight) {
        flags |= View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR;
      } else {
        flags &= ~View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR;
      }
    }

    decor.setSystemUiVisibility(flags);
  }

  private final class ThemeBridge {
    @JavascriptInterface
    public void setTheme(String theme) {
      final boolean isLight = "light".equalsIgnoreCase(theme);
      runOnUiThread(() -> applySystemBarTheme(isLight));
    }

    @JavascriptInterface
    public void setPlaying(String playing) {
      final boolean active = "1".equals(playing) || "true".equalsIgnoreCase(playing);
      runOnUiThread(() -> setPlaybackActive(active));
    }

    @JavascriptInterface
    public void download(String url, String filename) {
      if (url == null || url.trim().isEmpty()) return;
      final String rawName = filename == null ? "" : filename.trim();
      runOnUiThread(
          () -> {
            try {
              Uri uri = Uri.parse(url);
              String fileName = rawName.isEmpty() ? URLUtil.guessFileName(url, null, null) : rawName;
              if (fileName == null || fileName.trim().isEmpty()) fileName = "music";
              fileName = fileName.replaceAll("[\\\\/:*?\"<>|]+", "_");

              DownloadManager.Request request = new DownloadManager.Request(uri);
              String userAgent = webView != null ? webView.getSettings().getUserAgentString() : null;
              if (userAgent != null && !userAgent.trim().isEmpty()) {
                request.addRequestHeader("User-Agent", userAgent);
              }
              String cookie = CookieManager.getInstance().getCookie(url);
              if (cookie != null && !cookie.trim().isEmpty()) {
                request.addRequestHeader("Cookie", cookie);
              }
              request.setTitle(fileName);
              request.setNotificationVisibility(
                  DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED);
              request.setDestinationInExternalPublicDir(Environment.DIRECTORY_DOWNLOADS, fileName);

              DownloadManager dm = (DownloadManager) getSystemService(Context.DOWNLOAD_SERVICE);
              if (dm != null) {
                dm.enqueue(request);
              }
            } catch (Exception ignored) {
            }
          });
    }
  }
}
