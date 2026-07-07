package wx.trace.demo;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import wx.trace.demo.databinding.ActivityMainBinding;

/**
 * wxtrace demo — native trace testbed.
 *
 * Each button triggers a native workload with a distinct control-flow shape.
 * Workloads can also be triggered without the UI (for automated tracing):
 *
 *   am start -n wx.trace.demo/.MainActivity --es run vm --ei arg 100
 *   am start -n wx.trace.demo/.MainActivity --es run computeValue --ei arg 100000
 *
 * Startup logs each native function's offset within libdemo.so to logcat
 * (tag: wxtrace-demo) so test scripts can resolve addresses dynamically.
 */
public class MainActivity extends AppCompatActivity {

    private static final String TAG = "wxtrace-demo";

    static {
        System.loadLibrary("demo");
    }

    private ActivityMainBinding binding;
    private TextView result;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        result = binding.resultText;
        result.setText(stringFromJNI());

        // Dump native function offsets to logcat + the on-screen info pane.
        String info = funcInfo();
        Log.i(TAG, "native function layout:\n" + info);
        binding.infoText.setText(info);

        // Expose JNIEnv* to logcat so the root controller can register it.
        Log.i(TAG, "jniEnvAddr() = 0x" + Long.toHexString(jniEnvAddr()));

        // Pre-load the DroidGuard native .so at startup (off the UI thread) so its
        // base + VM dispatcher range are mapped/logged BEFORE any DG_INIT/DG_EXEC,
        // letting a tracer arm on the dispatcher before init()/ss() run (no race).
        //
        // IMPORTANT (measured): preloading here SKIPS the "fat" ~70k-BB VM bootstrap.
        // That fat run lives in initNative() but only fires when the FIRST init is
        // coupled with a fresh System.load in the same DG_INIT. Loading the .so early
        // here decouples them, so a later DG_INIT runs light (~0 BBs). Use the preload
        // only for tracing the LIGHT per-bytecode init/ss VM (base known up front).
        // To TRACE the FAT VM, launch with `--ez dg_preload false` (skip this) and
        // fire a plain DG_INIT, race-arming the dispatcher (the run is ~900ms).
        if (getIntent() == null || getIntent().getBooleanExtra("dg_preload", true)) {
            new Thread(() -> DroidGuardLoaderActivity.loadSo(getApplicationContext()),
                    "dg-preload").start();
        } else {
            Log.i(TAG, "dg_preload=false: skipping startup .so load (fire DG_LOAD to trigger it)");
        }

        bind(binding.btnValue,  "computeValue", 100000);
        bind(binding.btnCrc,    "crc32",        0);
        bind(binding.btnVm,     "vm",           100);
        bind(binding.btnFib,    "fib",          24);
        bind(binding.btnSort,   "sort",         64);
        bind(binding.btnMatrix, "matrix",       0);
        binding.btnJni.setOnClickListener(v -> runWorkloadAsync("jni", 8));
        binding.btnHeavy.setOnClickListener(v -> runHeavyAsync());
        binding.btnAll.setOnClickListener(v -> runWorkloadAsync("all", 0));
        binding.btnDroidguard.setOnClickListener(v -> launchDroidGuardLoader(
                DroidGuardLoaderActivity.ACTION_EXEC, null, null));

        binding.btnInfo.setOnClickListener(v -> binding.infoText.setText(funcInfo()));

        // Allow automated triggering via launch intent.
        handleRunIntent(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleRunIntent(intent);
    }

    private void bind(Button b, String workload, int defaultArg) {
        b.setOnClickListener(v -> runWorkloadAsync(workload, defaultArg));
    }

    private void handleRunIntent(Intent intent) {
        if (intent == null) return;
        String run = intent.getStringExtra("run");
        if (run == null || run.isEmpty()) return;
        int arg = intent.getIntExtra("arg", 0);
        if ("heavy".equals(run)) {
            runHeavyAsync();
        } else if ("xxtea".equals(run)) {
            runXxteaAsync(arg > 0 ? arg : 50);
        } else if ("xxteaNative".equals(run)) {
            runXxteaNativeAsync(arg > 0 ? arg : 50);
        } else if ("xxteaVm".equals(run)) {
            runXxteaVmAsync(arg > 0 ? arg : 64);
        } else if ("xxteaCompare".equals(run)) {
            doXxteaCompare(arg > 0 ? arg : 32);
        } else if ("droidguard".equals(run)) {
            String bytecode = intent.getStringExtra("bytecode");
            String action = intent.getStringExtra("dg_action");
            if (action == null || action.isEmpty()) {
                action = DroidGuardLoaderActivity.ACTION_EXEC;
            }
            launchDroidGuardLoader(action, bytecode, intent);
        } else {
            runWorkloadAsync(run, arg);
        }
    }

    private void launchDroidGuardLoader(String action, String bytecode, Intent src) {
        Intent intent = new Intent(this, DroidGuardLoaderActivity.class);
        intent.setAction(action);
        if (bytecode != null && !bytecode.isEmpty()) {
            intent.putExtra(DroidGuardLoaderActivity.EXTRA_BYTECODE, bytecode);
        }
        if (src != null) {
            if (src.hasExtra(DroidGuardLoaderActivity.EXTRA_FLOW)) {
                intent.putExtra(DroidGuardLoaderActivity.EXTRA_FLOW,
                        src.getStringExtra(DroidGuardLoaderActivity.EXTRA_FLOW));
            }
            if (src.hasExtra(DroidGuardLoaderActivity.EXTRA_ENV)) {
                intent.putExtra(DroidGuardLoaderActivity.EXTRA_ENV,
                        src.getIntExtra(DroidGuardLoaderActivity.EXTRA_ENV, 2));
            }
            if (src.hasExtra(DroidGuardLoaderActivity.EXTRA_APSH)) {
                intent.putExtra(DroidGuardLoaderActivity.EXTRA_APSH,
                        src.getBooleanExtra(DroidGuardLoaderActivity.EXTRA_APSH, false));
            }
        }
        startActivity(intent);
    }

    private void runWorkloadAsync(String workload, int arg) {
        new Thread(() -> {
            long t0 = System.nanoTime();
            long r = runWorkload(workload, arg);
            long us = (System.nanoTime() - t0) / 1000;
            String msg = workload + "(" + arg + ") = " + r + "  [" + us + " us]";
            Log.i(TAG, msg);
            runOnUiThread(() -> result.setText(msg));
        }, "wxtrace-work").start();
    }

    private void runHeavyAsync() {
        new Thread(() -> {
            long t0 = System.nanoTime();
            long r = runHeavyWithCallback(500);
            long us = (System.nanoTime() - t0) / 1000;
            String msg = "heavy(500) = " + r + "  [" + us + " us]";
            Log.i(TAG, msg);
            runOnUiThread(() -> result.setText(msg));
        }, "wxtrace-work").start();
    }

    private void runXxteaAsync(int iterations) {
        new Thread(() -> {
            long t0 = System.nanoTime();
            long r = runXxteaWorkload(iterations);
            long us = (System.nanoTime() - t0) / 1000;
            String msg = "xxtea(" + iterations + ") = " + r + "  [" + us + " us]";
            Log.i(TAG, msg);
            runOnUiThread(() -> result.setText(msg));
        }, "wxtrace-work").start();
    }

    private void runXxteaNativeAsync(int iterations) {
        new Thread(() -> {
            long t0 = System.nanoTime();
            long r = runXxteaPureNative(iterations);
            long us = (System.nanoTime() - t0) / 1000;
            String msg = "xxteaNative(" + iterations + ") = " + r + "  [" + us + " us]";
            Log.i(TAG, msg);
            runOnUiThread(() -> result.setText(msg));
        }, "wxtrace-work").start();
    }

    private void runXxteaVmAsync(int nWords) {
        new Thread(() -> {
            long t0 = System.nanoTime();
            long r = runXxteaVm(nWords);
            long us = (System.nanoTime() - t0) / 1000;
            String msg = "xxteaVm(" + nWords + ") = " + r + "  [" + us + " us]";
            Log.i(TAG, msg);
            runOnUiThread(() -> result.setText(msg));
        }, "wxtrace-work").start();
    }

    private void doXxteaCompare(int nWords) {
        String nativeResult = xxteaCompareWithVm(nWords);
        // Also get VM result
        long vmResult = runXxteaVm(nWords);
        String msg = "COMPARE: n=" + nWords + " native=" + nativeResult + " vm=" + vmResult;
        Log.i(TAG, msg);
        runOnUiThread(() -> result.setText(msg));
    }

    // ---- native methods ----
    public native String stringFromJNI();
    public native int    computeValue(int n);
    public native int    computeCrc32(String input);
    public native long   runWorkload(String name, int arg);
    public native String funcInfo();
    public native long   funcAddr(String name);
    public native int    crc32Region(long addr, int len);
    public native long   jniEnvAddr();
    public native long   runHeavyWithCallback(int arg);
    public native String xxteaEncrypt(int strLen);
    public native String xxteaEncryptNative(int strLen);
    public native int    xxteaVerify(String input);
    public native long   runXxteaWorkload(int iterations);
    public native long   runXxteaPureNative(int iterations);
    public native long   runXxteaVm(int nWords);
    public native String xxteaCompareWithVm(int nWords);

    /* ---- Called by native vm_heavy via JNI ---- */
    @SuppressWarnings("unused") /* called from native vm_heavy.cpp */
    public int vmCallback(int opcode, int arg1, int arg2) {
        return (arg1 + arg2) ^ opcode;
    }

    @SuppressWarnings("unused")
    public String vmGetString(int index) {
        switch (index) {
            case 0: return "wxtrace_heavy_test_string";
            case 1: return "JNI_CALLBACK_WORKS";
            default: return "default";
        }
    }

    @SuppressWarnings("unused")
    public void vmLog(String msg) {
        Log.i(TAG, "vm_heavy: " + msg);
    }

    @SuppressWarnings("unused") /* called from native vm_heavy.cpp via JNI */
    public String vmBase64Encode(long value) {
        String hex = Long.toHexString(value);
        // Pad to even length
        if (hex.length() % 2 != 0) hex = "0" + hex;
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP);
    }
}
