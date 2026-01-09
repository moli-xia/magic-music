package live.aabb.magicmusic;

import android.annotation.SuppressLint;
import android.app.DownloadManager;
import android.content.Context;
import android.graphics.Color;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
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

  @SuppressLint("SetJavaScriptEnabled")
  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_main);

    webView = findViewById(R.id.webview);

    WebSettings settings = webView.getSettings();
    settings.setJavaScriptEnabled(true);
    settings.setDomStorageEnabled(true);
    settings.setDatabaseEnabled(true);
    settings.setMediaPlaybackRequiresUserGesture(false);
    settings.setLoadWithOverviewMode(true);
    settings.setUseWideViewPort(true);
    settings.setSupportZoom(false);
    settings.setBuiltInZoomControls(false);
    settings.setDisplayZoomControls(false);

    CookieManager cookieManager = CookieManager.getInstance();
    cookieManager.setAcceptCookie(true);
    cookieManager.setAcceptThirdPartyCookies(webView, true);

    webView.setWebChromeClient(new WebChromeClient());
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
          public void onPageFinished(WebView view, String url) {
            super.onPageFinished(view, url);
            injectThemeObserver(view);
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
  protected void onSaveInstanceState(Bundle outState) {
    super.onSaveInstanceState(outState);
    if (webView != null) {
      webView.saveState(outState);
    }
  }

  @Override
  protected void onDestroy() {
    if (webView != null) {
      webView.destroy();
      webView = null;
    }
    super.onDestroy();
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
