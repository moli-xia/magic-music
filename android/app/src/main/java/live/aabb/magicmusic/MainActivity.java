package live.aabb.magicmusic;

import android.annotation.SuppressLint;
import android.os.Bundle;
import android.webkit.CookieManager;
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
    webView.setWebViewClient(
        new WebViewClient() {
          @Override
          public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
            return false;
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
                if (webView != null && webView.canGoBack()) {
                  webView.goBack();
                  return;
                }
                finish();
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
}

