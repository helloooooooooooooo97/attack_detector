import net.rebeyond.behinder.utils.SSLSocketClient;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

/**
 * Baseline "normal" traffic generator.
 *
 * Uses the SAME OkHttp + JSSE TLS stack as the Behinder client (identical
 * JA3), but performs plain HTTPS GET requests instead of encrypted C2 POSTs.
 * This isolates behavioral differences between Behinder and normal browsing.
 */
public class NormalDriver {
    public static void main(String[] args) throws Exception {
        String url = args.length > 0 ? args[0] : "https://127.0.0.1:8443/docs/";
        int n = args.length > 1 ? Integer.parseInt(args[1]) : 10;

        OkHttpClient client = new OkHttpClient.Builder()
                .sslSocketFactory(
                        SSLSocketClient.getSSLSocketFactory(),
                        SSLSocketClient.getX509TrustManager())
                .hostnameVerifier(SSLSocketClient.getHostnameVerifier())
                .build();

        long t0 = System.currentTimeMillis();
        for (int i = 0; i < n; i++) {
            long pause;
            if (i == 3) {
                pause = 6000;   // reading a page
            } else if (i == 6) {
                pause = 400;    // quick click
            } else {
                pause = 1200 + (long) (Math.random() * 2000);
            }
            Thread.sleep(pause);

            long start = System.currentTimeMillis();
            Request req = new Request.Builder().url(url).build();
            try (Response resp = client.newCall(req).execute()) {
                long len = resp.body() != null ? resp.body().bytes().length : 0;
                System.out.println("[normal] op" + i + " t=" + (System.currentTimeMillis() - t0)
                        + "ms status=" + resp.code() + " len=" + len);
            }
        }
        System.out.println("[normal] done");
        System.exit(0);
    }
}
