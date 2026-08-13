import net.rebeyond.behinder.core.ShellService;
import org.json.JSONObject;

/**
 * Headless driver for the Behinder (ice scorpion) client protocol.
 *
 * Uses the real Behinder v4 client classes as a library, talks to a local
 * Tomcat webshell, and prints operation timing so the generated TLS traffic
 * can be captured and analyzed off-line.
 */
public class Driver {
    public static void main(String[] args) throws Exception {
        String url = args.length > 0 ? args[0] : "https://127.0.0.1:8443/shell.jsp";
        String password = args.length > 1 ? args[1] : "rebeyond";
        String type = args.length > 2 ? args[2] : "jsp";
        int ops = args.length > 3 ? Integer.parseInt(args[3]) : 9;

        JSONObject entity = new JSONObject();
        entity.put("url", url);
        entity.put("type", type);
        entity.put("password", password);
        entity.put("transProtocolId", -1); // legacy AES protocol (md5(password) key)
        entity.put("id", 1);
        entity.put("headers", "");

        ShellService svc = new ShellService(entity);
        System.out.println("[driver] connecting to " + url);
        boolean ok = svc.doConnect();
        System.out.println("[driver] doConnect=" + ok);
        if (!ok) {
            System.out.println("[driver] connection failed, aborting");
            System.exit(1);
        }

        String[] cmds = {"id", "whoami", "uname -a", "cat /etc/hostname", "pwd", "ls -la /tmp", "ls -la /", "date"};
        long t0 = System.currentTimeMillis();
        for (int i = 0; i < ops; i++) {
            long pause;
            if (i == 2) {
                pause = 7000;   // operator reads command output
            } else if (i == 5) {
                pause = 400;    // quick successive operation
            } else {
                pause = 1500 + (long) (Math.random() * 2000);
            }
            Thread.sleep(pause);
            long ts = System.currentTimeMillis() - t0;

            JSONObject r;
            if (i % 3 == 0) {
                r = svc.getBasicInfo("1");
            } else {
                r = svc.runCmd(cmds[i % cmds.length], "/tmp");
            }
            String msg = r.has("msg") ? r.getString("msg") : r.toString();
            if (msg.length() > 160) {
                msg = msg.substring(0, 160) + "...";
            }
            System.out.println("[driver] op" + i + " t=" + ts + "ms -> " + msg.replace('\n', '|'));
        }

        Thread.sleep(1500);
        System.out.println("[driver] done");
        System.exit(0);
    }
}
