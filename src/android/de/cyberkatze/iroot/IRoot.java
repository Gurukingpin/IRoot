package de.cyberkatze.iroot;

import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CallbackContext;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.Map;
import java.util.HashMap;

import java.lang.Exception;
import java.lang.reflect.Method;
import java.io.File;

import java.io.BufferedReader;
import java.io.InputStreamReader;

import android.content.Context;
import dalvik.system.DexClassLoader;

import com.scottyab.rootbeer.RootBeer;

import org.apache.cordova.LOG;
import org.apache.cordova.PluginResult;
import org.apache.cordova.PluginResult.Status;

/**
 * Detect weather device is rooted or not
 *
 * @author Ali Elderov
 */
public class IRoot extends CordovaPlugin {

    private final String LOG_TAG = "IRoot";

    private final boolean WITH = true;
    private Context context;

    private enum Action {
        // Actions
        ACTION_IS_ROOTED("isRooted"),
        ACTION_IS_ROOTED_REDBEER("isRootedRedBeer"),
        ACTION_IS_ROOTED_REDBEER_WITHOUT_BUSYBOX("isRootedRedBeerWithoutBusyBox");

        private final String name;

        private static final Map<String, Action> lookup = new HashMap<String, Action>();

        static {
            for (Action a : Action.values()) {
                lookup.put(a.getName(), a);
            }
        }

        private Action(final String name) {
            this.name = name;
        }

        public String getName() {
            return name;
        }

        public static Action get(final String name) {
            return lookup.get(name);
        }
    }

    /**
     * helper fn that logs the err and then calls the err callback
     */
    private PluginResult error(final String message, final Throwable e) {
        LOG.e(LOG_TAG, message, e);
        return new PluginResult(Status.ERROR, message);
    }

    @Override
    public boolean execute(final String action, final JSONArray args, final CallbackContext callbackContext) throws JSONException {
        // throws JSONException
        Action act = Action.get(action);

        if (act == null) {
            cordova.getActivity().runOnUiThread(new Runnable() {
                public void run() {
                    LOG.e(LOG_TAG, "unknown action");
                    callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, "unknown action"));
                }
            });

            return false;
        }

        switch (act) {
            case ACTION_IS_ROOTED:
                cordova.getThreadPool().execute(new Runnable() {

                    @Override
                    public void run() {
                        PluginResult result;

                        try {
                            result = checkIsRooted(args, callbackContext);
                        } catch (Exception e) {
                            result = new PluginResult(PluginResult.Status.ERROR, e.toString());
                        }

                        callbackContext.sendPluginResult(result);
                    }
                });

                return true;
            case ACTION_IS_ROOTED_REDBEER:
                cordova.getThreadPool().execute(new Runnable() {

                    @Override
                    public void run() {
                        PluginResult result;

                        try {
                            result = checkIsRootedRedBeer(args, callbackContext);
                        } catch (Exception e) {
                            result = new PluginResult(PluginResult.Status.ERROR, e.toString());
                        }

                        callbackContext.sendPluginResult(result);
                    }
                });

                return true;
            case ACTION_IS_ROOTED_REDBEER_WITHOUT_BUSYBOX:
                cordova.getThreadPool().execute(new Runnable() {

                    @Override
                    public void run() {
                        PluginResult result;

                        try {
                            result = checkIsRootedRedBeerWithoutBusyBox(args, callbackContext);
                        } catch (Exception e) {
                            result = new PluginResult(PluginResult.Status.ERROR, e.toString());
                        }

                        callbackContext.sendPluginResult(result);
                    }
                });

                return true;
            default:
                cordova.getActivity().runOnUiThread(new Runnable() {

                    public void run() {
                        LOG.e(LOG_TAG, "unknown action");
                        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, "unknown action"));
                    }
                });
                return false;
        }
    }

    /**
   * Get the current Xposed version installed on the device.
   *
   * @param context
   *     The application context
   * @return The Xposed version or {@code null} if Xposed isn't installed.
   */
  public static boolean getXposedVersion(Context context) {
    try {
      File xposedBridge = new File("/system/framework/XposedBridge.jar");
      if (xposedBridge.exists()) {
        File optimizedDir = context.getDir("dex", Context.MODE_PRIVATE);
        DexClassLoader dexClassLoader = new DexClassLoader(xposedBridge.getPath(),
            optimizedDir.getPath(), null, ClassLoader.getSystemClassLoader());
        Class<?> XposedBridge = dexClassLoader.loadClass("de.robv.android.xposed.XposedBridge");
        Method getXposedVersion = XposedBridge.getDeclaredMethod("getXposedVersion");
        if (!getXposedVersion.isAccessible()) getXposedVersion.setAccessible(true);
        return (boolean) getXposedVersion.invoke(null);
      }
    } catch (Exception ignored) {
    }
    return false;
  }

    private boolean isDeviceRooted() {
     this.context = context;
        return checkBuildTags() || checkRootMethod3() || checkFilePath() || getXposedVersion(context);
    }

    private boolean checkBuildTags() {
        String buildTags = android.os.Build.TAGS;
        return buildTags != null && buildTags.contains("test-keys");
    }

    /*private boolean checkSuperUserApk() {
        return new File("/system/app/Superuser.apk").exists();
    }*/

    private boolean checkFilePath() {
        String[] paths = { "/system/app/Superuser.apk", "/system/app/SuperSU.apk", "/sbin/su", "/system/bin/su", "/system/xbin/su", "/data/local/xbin/su", "/data/local/bin/su", "/system/sd/xbin/su",
                "/system/bin/failsafe/su", "/data/local/su", "/su/bin/su"};

        for (String path : paths) {
            if (new File(path).exists()) {
                return true;
            }
        }

        return false;
    }
    private static boolean checkRootMethod3() {
        Process process = null;
        try {
            process = Runtime.getRuntime().exec(new String[] { "/system/xbin/which", "su" });
            BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
            if (in.readLine() != null) return true;
            return false;
        } catch (Throwable t) {
            return false;
        } finally {
            if (process != null) process.destroy();
        }
    }

    // ************************************************
    // ACTION HANDLERS
    // - return true:
    // - to indicate action was executed with correct arguments
    // - also if the action from sdk has failed.
    // - return false:
    // - arguments were wrong
    // ************************************************

    /**
     * Simple check with rootBeer
     */
    private PluginResult checkIsRootedRedBeer(final JSONArray args, final CallbackContext callbackContext) {
        try {
            RootBeer rootBeer = new RootBeer(this.cordova.getActivity().getApplicationContext());

            return new PluginResult(Status.OK, rootBeer.isRooted());
        } catch (Exception e) {
            return this.error("Error", e);
        }
    }

    /**
     * Simple check with rootBeer without BusyBox
     */
    private PluginResult checkIsRootedRedBeerWithoutBusyBox(final JSONArray args, final CallbackContext callbackContext) {
        try {
            RootBeer rootBeer = new RootBeer(this.cordova.getActivity().getApplicationContext());

            return new PluginResult(Status.OK, rootBeer.isRootedWithoutBusyBoxCheck());
        } catch (Exception e) {
            return this.error("Error", e);
        }
    }

    /**
     * Combine simple check and rootBeer. User can activate check with plugin option ENABLE_BUSYBOX_CHECK -> put argument with
     * TRUE/FALSE.
     */
    private PluginResult checkIsRooted(final JSONArray args, final CallbackContext callbackContext) {
        try {
            RootBeer rootBeer = new RootBeer(this.cordova.getActivity().getApplicationContext());

            boolean check = isDeviceRooted() || ((this.WITH) ? rootBeer.isRootedWithoutBusyBoxCheck() : rootBeer.isRooted());

            return new PluginResult(Status.OK, check);
        } catch (Exception e) {
            return this.error("Error", e);
        }
    }
}
