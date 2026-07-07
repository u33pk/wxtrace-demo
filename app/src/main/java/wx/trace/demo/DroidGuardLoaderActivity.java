package wx.trace.demo;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.database.sqlite.SQLiteDatabase;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

/**
 * DroidGuard loader Activity with separate INIT and EXEC intents.
 *
 * This lets you prepare the DroidGuard environment first, set up trace, then
 * trigger execution separately.
 *
 * Actions:
 *   wx.trace.demo.action.DG_LOAD  - load dex/so only (System.load the native .so) and stop. Maps
 *                                   the .so so its base is known up front — good for tracing the
 *                                   LIGHT per-bytecode init/ss VM. NOTE: loading the .so separately
 *                                   like this SKIPS the fat ~70k-BB bootstrap (see loadSo()); it
 *                                   only fires when a fresh load + init are coupled in one DG_INIT.
 *                                   MainActivity also runs this at startup unless launched with
 *                                   --ez dg_preload false.
 *   wx.trace.demo.action.DG_INIT  - construct DroidGuard + call init() (loads .so first if needed).
 *                                   Launched with dg_preload=false + no prior DG_LOAD, this couples
 *                                   load+init and runs the FAT VM (the case to race-arm/trace).
 *   wx.trace.demo.action.DG_EXEC  - call ss() on the previously initialized VM (~199 BBs)
 *
 * Extras:
 *   bytecode (String) : name or substring of the .bytecode file under assets/droidguard/
 *                       default = dg_attest_0ade...39f.bytecode
 *   flow     (String) : flow name passed to DroidGuard (default "wxtrace-flow")
 *   env      (int)    : runtime environment id (default 2 = IN_APP_STANDALONE)
 *   apsh     (boolean): allow POSIX signal handling (default false)
 *
 * Examples:
 *   # 1. init (loads default bytecode VM)
 *   am start -n wx.trace.demo/.DroidGuardLoaderActivity -a wx.trace.demo.action.DG_INIT
 *
 *   # 2. exec the already-loaded bytecode
 *   am start -n wx.trace.demo/.DroidGuardLoaderActivity -a wx.trace.demo.action.DG_EXEC
 *
 *   # 3. init a specific bytecode
 *   am start -n wx.trace.demo/.DroidGuardLoaderActivity -a wx.trace.demo.action.DG_INIT \
 *            --es bytecode 147a0be7c8c8589e31a352ed69001cfc87f4947be509bafeb9d8ef9edfd8c8cd
 *
 *   # 4. exec a different bytecode (forces re-init)
 *   am start -n wx.trace.demo/.DroidGuardLoaderActivity -a wx.trace.demo.action.DG_EXEC \
 *            --es bytecode 74415f3ef8360d06cb431faa8364e0f1cec80c0e588c0cb2277750b5ee551c9e
 */
public class DroidGuardLoaderActivity extends Activity {

    private static final String TAG = "wxtrace-demo";

    public static final String EXTRA_BYTECODE = "bytecode";
    public static final String EXTRA_FLOW     = "flow";
    public static final String EXTRA_ENV      = "env";
    public static final String EXTRA_APSH     = "apsh";

    public static final String ACTION_LOAD = "wx.trace.demo.action.DG_LOAD";
    public static final String ACTION_INIT = "wx.trace.demo.action.DG_INIT";
    public static final String ACTION_EXEC = "wx.trace.demo.action.DG_EXEC";

    private static final String DEFAULT_BYTECODE =
            "dg_attest_0ade4488c266043ee40fef3bc4473760ec252111272230b4e5f25c4f4d88639f.bytecode";

    private TextView logView;
    private final Handler uiHandler = new Handler(Looper.getMainLooper());
    private final StringBuilder logBuffer = new StringBuilder();

    // Process-wide cached state. DroidGuard's static initializer calls
    // System.load() on its SO; Android refuses to load the same SO twice for
    // the same ClassLoader. Reusing the loader and instance avoids both the
    // "already opened" error and redundant init() work.
    private static dalvik.system.DexClassLoader sLoader;
    private static Class<?> sDgClass;
    private static Object sDgInstance;
    private static String sLoadedBytecode;
    private static final Object LOCK = new Object();

    // VM main dispatcher: fcn @ 0x34694, range [0x34694, 0x34fa4) (radare2 + wxtrace BB trace).
    // Central jump table @ .rodata 0x5030 (6 cases) + `br x9` computed-goto; 16-byte instr stride,
    // opcode at [x28]; register-based ("unknown register" diagnostics). TRACE-CONFIRMED ACTIVE in
    // the offline flow: EXEC +199 BBs, re-INIT +177 BBs (entry PC base+0x34694 hit).
    // Notes: fcn @ 0x4659c is a sibling dispatcher of the same VM family but is NOT hit by this flow
    // (0 BBs); fcn @ 0xbec0 is ARMv8 hardware SHA-256 (a crypto primitive the VM calls), not the VM.
    private static final long DISPATCHER_OFFSET = 0x34694L;
    private static final long DISPATCHER_END_OFFSET = 0x34fa4L;
    private static final String DG_SO_NAME = "libdCBC295A591DF.so";

    // Cached load-base of the DroidGuard native library, updated after init().
    private static long sDgBaseAddr = 0L;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        logView = new TextView(this);
        logView.setTextIsSelectable(true);
        logView.setTextSize(11f);
        logView.setPadding(16, 16, 16, 16);
        logView.setFontFeatureSettings("tnum");

        ScrollView scroll = new ScrollView(this);
        scroll.addView(logView);
        setContentView(scroll);

        Intent intent = getIntent();
        String action = intent.getAction();
        if (action == null || action.isEmpty()) {
            action = ACTION_LOAD; // default: load the .so only; init waits for DG_INIT
        }
        String bytecodeHint = intent.getStringExtra(EXTRA_BYTECODE);
        String flow = intent.getStringExtra(EXTRA_FLOW);
        if (flow == null || flow.isEmpty()) {
            flow = "wxtrace-flow";
        }
        int env = intent.getIntExtra(EXTRA_ENV, 2);
        boolean apsh = intent.getBooleanExtra(EXTRA_APSH, false);

        log("action=" + action + " bytecode=" + bytecodeHint
                + " flow=" + flow + " env=" + env + " apsh=" + apsh);

        final String fAction = action;
        final String fBytecodeHint = bytecodeHint;
        final String fFlow = flow;
        final int fEnv = env;
        final boolean fApsh = apsh;
        new Thread(() -> handleIntent(fAction, fBytecodeHint, fFlow, fEnv, fApsh),
                "droidguard-loader").start();
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);

        String action = intent.getAction();
        if (action == null || action.isEmpty()) {
            action = ACTION_LOAD;
        }
        String bytecodeHint = intent.getStringExtra(EXTRA_BYTECODE);
        String flow = intent.getStringExtra(EXTRA_FLOW);
        if (flow == null || flow.isEmpty()) {
            flow = "wxtrace-flow";
        }
        int env = intent.getIntExtra(EXTRA_ENV, 2);
        boolean apsh = intent.getBooleanExtra(EXTRA_APSH, false);

        log("onNewIntent action=" + action + " bytecode=" + bytecodeHint
                + " flow=" + flow + " env=" + env + " apsh=" + apsh);

        final String fAction = action;
        final String fBytecodeHint = bytecodeHint;
        final String fFlow = flow;
        final int fEnv = env;
        final boolean fApsh = apsh;
        new Thread(() -> handleIntent(fAction, fBytecodeHint, fFlow, fEnv, fApsh),
                "droidguard-loader").start();
    }

    private void handleIntent(String action, String bytecodeHint, String flow,
                              int env, boolean apsh) {
        try {
            if (ACTION_LOAD.equals(action)) {
                boolean ok = loadSo(this);
                log("DG_LOAD: .so loaded = " + ok + " (init waits for DG_INIT)");
            } else if (ACTION_INIT.equals(action)) {
                initDroidGuard(bytecodeHint, flow, env, apsh);
            } else if (ACTION_EXEC.equals(action)) {
                execDroidGuard(bytecodeHint, flow, env, apsh);
            } else {
                // Fallback: init then exec the same bytecode in one shot.
                if (initDroidGuard(bytecodeHint, flow, env, apsh)) {
                    callSs();
                }
            }
        } catch (Throwable e) {
            logE("handleIntent failed", e);
        }
    }

    /**
     * Initialize DroidGuard for a given bytecode. If the same bytecode is
     * already initialized, this is a no-op.
     *
     * @return true if init succeeded (or was already done)
     */
    private boolean initDroidGuard(String bytecodeHint, String flow, int env,
                                   boolean apsh) throws Exception {
        String bytecodeName = resolveBytecodeName(
                bytecodeHint != null && !bytecodeHint.isEmpty() ? bytecodeHint : DEFAULT_BYTECODE);
        log("init bytecode: " + bytecodeName);

        synchronized (LOCK) {
            if (sDgInstance != null && bytecodeName.equals(sLoadedBytecode)) {
                log("already initialized for " + bytecodeName);
                logDispatcherAddrs();
                return true;
            }

            // Ensure the native .so + DroidGuard class are loaded. Idempotent: normally
            // the .so is already mapped at startup (MainActivity -> loadSo), so this is a
            // no-op and only the instance construction + init() below actually runs here.
            if (!loadSo(this)) {
                logE("init aborted: loadSo failed", new RuntimeException("loadSo failed"));
                return false;
            }

            Constructor<?> ctor = sDgClass.getDeclaredConstructor(
                    Context.class, String.class, byte[].class, Object.class, Bundle.class);

            byte[] program = readAssetBytes(this, "droidguard/" + bytecodeName);
            Bundle extras = new Bundle();
            extras.putBoolean("apsh", apsh);

            log("constructing DroidGuard...");
            sDgInstance = ctor.newInstance(
                    getApplicationContext(), flow, program, new Object(), extras);

            ensureDgDatabase();
            log("init() start");

            Method init = sDgClass.getDeclaredMethod("init");
            boolean ok = (Boolean) init.invoke(sDgInstance);
            log("init() = " + ok);

            if (ok) {
                sLoadedBytecode = bytecodeName;
                sDgBaseAddr = findModuleBase(DG_SO_NAME);
                logDispatcherAddrs();
            } else {
                sDgInstance = null;
                sLoadedBytecode = null;
                sDgBaseAddr = 0L;
            }
            return ok;
        }
    }

    /**
     * Execute ss() on the initialized VM. If a different bytecode is requested,
     * re-initialize first. If no bytecode is provided and none is loaded yet,
     * fall back to the default bytecode.
     */
    private void execDroidGuard(String bytecodeHint, String flow, int env,
                                boolean apsh) throws Exception {
        String requestedBytecode = bytecodeHint;
        if (requestedBytecode == null || requestedBytecode.isEmpty()) {
            synchronized (LOCK) {
                if (sLoadedBytecode != null) {
                    requestedBytecode = sLoadedBytecode;
                } else {
                    requestedBytecode = DEFAULT_BYTECODE;
                }
            }
        }

        synchronized (LOCK) {
            if (sDgInstance == null || !requestedBytecode.equals(sLoadedBytecode)) {
                log("need to init before exec");
                if (!initDroidGuard(requestedBytecode, flow, env, apsh)) {
                    logE("exec aborted: init failed", new RuntimeException("init failed"));
                    return;
                }
            }
        }

        callSs();
    }

    private void callSs() throws Exception {
        synchronized (LOCK) {
            if (sDgInstance == null) {
                throw new IllegalStateException("DroidGuard not initialized");
            }
            Method ss = sDgClass.getDeclaredMethod("ss", Map.class);
            Map<String, String> contentBinding = new HashMap<>();
            contentBinding.put("key1", "value1");
            contentBinding.put("key2", "value2");
            Object result = ss.invoke(sDgInstance, contentBinding);
            log("ss() result = " + (result != null ? result.getClass().getName() : "null"));
        }
    }

    /**
     * Close and clear the cached DroidGuard instance. Useful if you want to
     * start fresh without killing the process.
     */
    private void closeDroidGuard() throws Exception {
        synchronized (LOCK) {
            if (sDgInstance != null) {
                Method close = sDgClass.getDeclaredMethod("close");
                close.invoke(sDgInstance);
                sDgInstance = null;
                sLoadedBytecode = null;
                log("close() done");
            }
        }
    }

    /**
     * DroidGuard's native init opens /data/data/<pkg>/databases/dg.db via
     * SQLite. Make sure the file exists before calling init() so the open
     * succeeds (an empty database is enough for the native side to bootstrap).
     */
    private void ensureDgDatabase() {
        try {
            File dbFile = getDatabasePath("dg.db");
            File parent = dbFile.getParentFile();
            if (parent != null && !parent.exists()) {
                parent.mkdirs();
            }
            if (!dbFile.exists()) {
                SQLiteDatabase db = SQLiteDatabase.openOrCreateDatabase(dbFile, null);
                // DroidGuard's native code queries:
                //   SELECT b FROM main WHERE a LIKE 'fast%' ORDER BY b DESC LIMIT 1
                db.execSQL("CREATE TABLE IF NOT EXISTS main (a TEXT, b TEXT);");
                db.execSQL("INSERT INTO main (a, b) VALUES ('fast', '0');");
                db.close();
                log("created dg.db with main(a,b) at " + dbFile);
            }
        } catch (Exception e) {
            logW("ensureDgDatabase failed: " + e.getMessage());
        }
    }

    /**
     * Load ONLY the DroidGuard native .so (and its DroidGuard class) into this
     * process, WITHOUT constructing an instance or calling init(). This:
     *   - copies the dex/so/library.txt assets into app_droidguard/,
     *   - builds the APK-like jar,
     *   - creates the ClassLoader and loadClass()es DroidGuard, whose static
     *     initializer System.load()s the native .so (mapping it into the process),
     *   - resolves and logs the .so base + VM dispatcher range.
     *
     * Idempotent and process-wide (guarded by sLoader). Static so it can be called
     * from MainActivity at startup. Logs go to logcat (tag {@code wxtrace-demo}).
     *
     * IMPORTANT — load and the "fat" VM CANNOT be decoupled (measured):
     * The heavy one-time ~70k-BB VM run through the 0x34694 dispatcher happens inside
     * the native {@code initNative()} (called by init()), but ONLY when that first
     * init is COUPLED with a fresh System.load in the same DG_INIT (empirically: the
     * same worker thread, System.load -> newInstance -> initNative back-to-back).
     * If the .so is loaded SEPARATELY first — by this loadSo() at startup, or by a
     * standalone DG_LOAD — that first-init fat bootstrap does NOT fire and the later
     * DG_INIT runs light (~0 BBs at 0x34694; ss() ~199). So preloading the .so here
     * (or via DG_LOAD) *consumes/skips* the fat bootstrap; it does not move it.
     *
     * Consequence: to TRACE the fat VM, do NOT preload — launch with
     * {@code --ez dg_preload false} and fire a plain DG_INIT (which couples
     * loadSo + initNative), race-arming the dispatcher (the run is ~900ms, so the
     * maps-poll race is winnable). Use this loadSo() preload only when you want the
     * .so base known early for tracing the LIGHT per-bytecode init/ss VM instead.
     *
     * @return true if the .so is mapped and its base was resolved.
     */
    static boolean loadSo(Context ctx) {
        synchronized (LOCK) {
            try {
                if (sLoader == null) {
                    File workDir = ctx.getDir("droidguard", Context.MODE_PRIVATE);
                    File dexFile = new File(workDir, "classes.dex");
                    File soFile = new File(workDir, "libdCBC295A591DF.so");
                    File libNameFile = new File(workDir, "library.txt");
                    copyAsset(ctx, "droidguard/classes.dex", dexFile);
                    copyAsset(ctx, "droidguard/libdCBC295A591DF.so", soFile);
                    copyAsset(ctx, "droidguard/library.txt", libNameFile);
                    if (!soFile.setExecutable(true, false)) {
                        Log.w(TAG, "failed to set executable bit on " + soFile);
                    }
                    File jarFile = new File(workDir, "droidguard.jar");
                    String abi = pickAbi();
                    buildDroidGuardJar(dexFile, soFile, libNameFile, jarFile, abi);
                    File optDir = ctx.getDir("droidguard_opt", Context.MODE_PRIVATE);
                    // Android runtime rejects writable DEX files for security reasons.
                    if (!jarFile.setWritable(false)) {
                        Log.w(TAG, "failed to make jar read-only: " + jarFile);
                    }
                    sLoader = new ResourceAwareDexClassLoader(
                            jarFile.getAbsolutePath(),
                            optDir.getAbsolutePath(),
                            workDir.getAbsolutePath(),
                            ctx.getClassLoader(),
                            jarFile,
                            abi
                    );
                    // Class.forName(..., initialize=true) forces the class's static
                    // initializer to run NOW (loadClass alone does NOT initialize). DroidGuard's
                    // <clinit> is what System.load()s the native .so, mapping it into the process.
                    sDgClass = Class.forName(
                            "com.google.ccc.abuse.droidguard.DroidGuard", true, sLoader);
                    Log.i(TAG, "DroidGuard ClassLoader created and .so loaded (static init done)");
                } else if (sDgClass == null) {
                    sDgClass = Class.forName(
                            "com.google.ccc.abuse.droidguard.DroidGuard", true, sLoader);
                }

                if (sDgBaseAddr == 0L) {
                    sDgBaseAddr = findModuleBase(DG_SO_NAME);
                }
                if (sDgBaseAddr != 0L) {
                    long start = sDgBaseAddr + DISPATCHER_OFFSET;
                    long end = sDgBaseAddr + DISPATCHER_END_OFFSET;
                    Log.i(TAG, DG_SO_NAME + " base=0x" + Long.toHexString(sDgBaseAddr));
                    Log.i(TAG, "VM dispatcher: 0x" + Long.toHexString(start)
                            + " - 0x" + Long.toHexString(end)
                            + " (size " + Long.toHexString(DISPATCHER_END_OFFSET - DISPATCHER_OFFSET) + ")");
                } else {
                    Log.w(TAG, "could not resolve " + DG_SO_NAME + " base address");
                }
                return sDgBaseAddr != 0L;
            } catch (Exception e) {
                Log.e(TAG, "loadSo failed", e);
                return false;
            }
        }
    }

    /**
     * Resolve a bytecode file name from a hint. The hint may be a full file name
     * ending with .bytecode, or any unique substring of the file name.
     */
    private String resolveBytecodeName(String hint) throws IOException {
        if (hint == null || hint.isEmpty()) {
            throw new IllegalArgumentException("missing bytecode hint");
        }
        String target = hint;
        if (!target.endsWith(".bytecode")) {
            target = target + ".bytecode";
        }

        String[] list = getAssets().list("droidguard");
        if (list == null) {
            throw new IOException("cannot list assets/droidguard");
        }

        String match = null;
        for (String name : list) {
            if (!name.endsWith(".bytecode")) continue;
            if (name.equals(target)) {
                return name;
            }
            if (name.contains(hint)) {
                if (match != null) {
                    throw new IllegalArgumentException("ambiguous bytecode hint: " + hint
                            + " matches both " + match + " and " + name);
                }
                match = name;
            }
        }
        if (match != null) {
            return match;
        }
        throw new IllegalArgumentException("no bytecode matching hint: " + hint);
    }

    private static byte[] readAssetBytes(Context context, String assetName) throws IOException {
        try (InputStream in = context.getAssets().open(assetName);
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        }
    }

    private static void copyAsset(Context context, String assetName, File outFile) throws IOException {
        if (outFile.exists() && outFile.length() > 0) {
            return;
        }
        try (InputStream in = context.getAssets().open(assetName);
             FileOutputStream out = new FileOutputStream(outFile)) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
            }
        }
        Log.i(TAG, "copied asset " + assetName + " -> " + outFile);
    }

    private void log(String msg) {
        Log.i(TAG, msg);
        appendLine("I: " + msg);
    }

    private void logW(String msg) {
        Log.w(TAG, msg);
        appendLine("W: " + msg);
    }

    private void logE(String msg, Throwable e) {
        Log.e(TAG, msg, e);
        appendLine("E: " + msg + "\n" + Log.getStackTraceString(e));
    }

    private void appendLine(String line) {
        synchronized (logBuffer) {
            logBuffer.append(line).append('\n');
        }
        uiHandler.post(() -> {
            synchronized (logBuffer) {
                logView.setText(logBuffer.toString());
            }
            logView.getParent().requestLayout();
        });
    }

    /**
     * Log the DroidGuard SO load-base and the VM dispatcher absolute addresses
     * (fcn @ 0x34694 .. 0x34fa4, the trace-confirmed active dispatcher).
     */
    private void logDispatcherAddrs() {
        if (sDgBaseAddr == 0L) {
            sDgBaseAddr = findModuleBase(DG_SO_NAME);
        }
        if (sDgBaseAddr != 0L) {
            long start = sDgBaseAddr + DISPATCHER_OFFSET;
            long end = sDgBaseAddr + DISPATCHER_END_OFFSET;
            log(DG_SO_NAME + " base=0x" + Long.toHexString(sDgBaseAddr));
            log("VM dispatcher: 0x" + Long.toHexString(start)
                    + " - 0x" + Long.toHexString(end)
                    + " (size " + Long.toHexString(DISPATCHER_END_OFFSET - DISPATCHER_OFFSET) + ")");
        } else {
            logW("could not resolve " + DG_SO_NAME + " base address");
        }
    }

    /**
     * Parse /proc/self/maps and return the lowest mapped address for a module
     * whose pathname contains {@code name}. Returns 0 if not found.
     */
    private static long findModuleBase(String name) {
        try (java.io.BufferedReader br = new java.io.BufferedReader(
                new java.io.FileReader("/proc/self/maps"))) {
            long minAddr = Long.MAX_VALUE;
            String line;
            while ((line = br.readLine()) != null) {
                if (!line.contains(name)) {
                    continue;
                }
                int dash = line.indexOf('-');
                if (dash <= 0) {
                    continue;
                }
                try {
                    long start = Long.parseLong(line.substring(0, dash).trim(), 16);
                    if (start < minAddr) {
                        minAddr = start;
                    }
                } catch (NumberFormatException ignored) {
                }
            }
            return minAddr == Long.MAX_VALUE ? 0L : minAddr;
        } catch (IOException e) {
            Log.w(TAG, "findModuleBase failed: " + e.getMessage());
            return 0L;
        }
    }

    /**
     * Package dex/SO/library.txt into a jar that looks enough like an APK for
     * DroidGuard's static loader. The SO is placed under lib/<abi>/ so that
     * System.load("/path/to.jar!/lib/<abi>/libfoo.so") works on Android.
     */
    private static void buildDroidGuardJar(File dexFile, File soFile,
                                           File libNameFile, File jarFile,
                                           String abi) throws IOException {
        if (jarFile.exists() && jarFile.length() > 0) {
            return;
        }
        try (JarOutputStream jos = new JarOutputStream(new FileOutputStream(jarFile))) {
            addJarEntry(jos, "classes.dex", dexFile);
            addJarEntry(jos, "library.txt", libNameFile);
            addJarEntry(jos, "lib/" + abi + "/libdCBC295A591DF.so", soFile);
        }
    }

    private static void addJarEntry(JarOutputStream jos, String entryName, File file) throws IOException {
        JarEntry entry = new JarEntry(entryName);
        entry.setSize(file.length());
        entry.setTime(file.lastModified());
        jos.putNextEntry(entry);
        try (InputStream in = new java.io.FileInputStream(file)) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) {
                jos.write(buf, 0, n);
            }
        }
        jos.closeEntry();
    }

    private static String pickAbi() {
        if (Build.SUPPORTED_ABIS != null && Build.SUPPORTED_ABIS.length > 0) {
            String primary = Build.SUPPORTED_ABIS[0];
            if (primary != null && !primary.isEmpty()) {
                return primary;
            }
        }
        return "arm64-v8a";
    }

    /**
     * DexClassLoader that resolves the native library resource as a
     * "jar:file:/...!/lib/<abi>/libfoo.so" URL. DroidGuard's static loader
     * checks URL.getFile().startsWith("file:") and then passes the path after
     * "file:" to System.load(), which expects an APK-style jar path.
     */
    private static class ResourceAwareDexClassLoader extends dalvik.system.DexClassLoader {
        private final File jarFile;
        private final String abi;

        ResourceAwareDexClassLoader(String dexPath, String optimizedDirectory,
                                    String librarySearchPath, ClassLoader parent,
                                    File jarFile, String abi) {
            super(dexPath, optimizedDirectory, librarySearchPath, parent);
            this.jarFile = jarFile;
            this.abi = abi;
        }

        @Override
        protected URL findResource(String name) {
            if ("libdCBC295A591DF.so".equals(name)) {
                try {
                    String path = "jar:file:" + jarFile.getAbsolutePath()
                            + "!/lib/" + abi + "/libdCBC295A591DF.so";
                    return new URL(path);
                } catch (MalformedURLException e) {
                    // fall through
                }
            }
            return super.findResource(name);
        }
    }
}
