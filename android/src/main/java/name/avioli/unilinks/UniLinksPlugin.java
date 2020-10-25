package name.avioli.unilinks;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Bundle;
import android.util.Log;

import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Formatter;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

import io.flutter.embedding.engine.plugins.FlutterPlugin;
import io.flutter.embedding.engine.plugins.activity.ActivityAware;
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding;
import io.flutter.plugin.common.BinaryMessenger;
import io.flutter.plugin.common.EventChannel;
import io.flutter.plugin.common.MethodCall;
import io.flutter.plugin.common.MethodChannel;
import io.flutter.plugin.common.PluginRegistry;

public class UniLinksPlugin
        implements FlutterPlugin,
                MethodChannel.MethodCallHandler,
                EventChannel.StreamHandler,
                ActivityAware,
                PluginRegistry.NewIntentListener {

    private static final String MESSAGES_CHANNEL = "uni_links/messages";
    private static final String EVENTS_CHANNEL = "uni_links/events";

    private static final String TAG="UniLinksPlugin";
    private BroadcastReceiver changeReceiver;

    private String initialLink;
    private String latestLink;
    private Context context;
    private boolean initialIntent = true;

    private Activity activity;

    private void handleIntent(Context context, Intent intent) {
        String action = intent.getAction();
        String dataString ;

        if(Intent.ACTION_VIEW.equals(action)) {
            dataString= intent.getDataString();
            if (initialIntent) {
                initialLink = dataString;
                initialIntent = false;
            }
            latestLink = dataString;

        }else{
            dataString= toDataStringFromExtras(intent);
            if (initialIntent) {
                initialLink = dataString;
                initialIntent = false;
            }
            latestLink=dataString;
        }
        if (changeReceiver != null) changeReceiver.onReceive(context, intent);
    }

    private String toDataStringFromExtras(Intent intent){
        StringBuilder sb=new StringBuilder();
        sb.append("https://");
        sb.append(intent.getAction());
        Bundle bundle= intent.getExtras();
        if(bundle==null){
            return sb.toString();
        }

        sb.append("/?");
        for(String key:bundle.keySet()){
            try{
                sb.append(key + "=" + URLEncoder.encode(bundle.get(key).toString(), "utf-8") + "&");
            }catch (UnsupportedEncodingException e){

            }
        }
        sb.deleteCharAt(sb.length()-1);
        return  sb.toString();

    }
    private BroadcastReceiver createChangeReceiver(final EventChannel.EventSink events) {
        return new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                // NOTE: assuming intent.getAction() is Intent.ACTION_VIEW

                // Log.v("uni_links", String.format("received action: %s", intent.getAction()));
                String action = intent.getAction();
                String dataString ;
                if(Intent.ACTION_VIEW.equals(action)){
                    dataString  = intent.getDataString();
                }else{
                    dataString=toDataStringFromExtras(intent);
                }
                if (dataString == null) {
                    events.error("UNAVAILABLE", "Link unavailable", null);
                } else {
                    events.success(dataString);
                }
            }
        };
    }

    @Override
    public void onAttachedToEngine(FlutterPluginBinding flutterPluginBinding) {
        this.context = flutterPluginBinding.getApplicationContext();
        register(flutterPluginBinding.getFlutterEngine().getDartExecutor(), this);
    }

    private static void register(BinaryMessenger messenger, UniLinksPlugin plugin) {
        final MethodChannel methodChannel = new MethodChannel(messenger, MESSAGES_CHANNEL);
        methodChannel.setMethodCallHandler(plugin);

        final EventChannel eventChannel = new EventChannel(messenger, EVENTS_CHANNEL);
        eventChannel.setStreamHandler(plugin);
    }

    /** Plugin registration. */
    public static void registerWith(PluginRegistry.Registrar registrar) {
        // Detect if we've been launched in background
        if (registrar.activity() == null) {
            return;
        }

        final UniLinksPlugin instance = new UniLinksPlugin();
        instance.context = registrar.context();
        instance.activity=registrar.activity();
        register(registrar.messenger(), instance);

        instance.handleIntent(registrar.context(), registrar.activity().getIntent());
        registrar.addNewIntentListener(instance);
    }

    @Override
    public void onDetachedFromEngine(FlutterPluginBinding flutterPluginBinding) {}

    @Override
    public void onListen(Object o, EventChannel.EventSink eventSink) {
        changeReceiver = createChangeReceiver(eventSink);
    }
    public void  setResult(int code,Map<?,?>  params){
        Intent returnIntent = new Intent();
        for(Object key:params.keySet()){
            returnIntent.putExtra(key.toString(),params.get(key).toString());
        }
        activity.setResult(code, returnIntent);
    }

    private Map<?,?> toMap (Object arguments){
        if (arguments == null) {
            return null;
        } else if (arguments instanceof Map) {
            return  ((Map<?, ?>) arguments);
        } else if (arguments instanceof JSONObject) {
            Map<String, String> m= new LinkedHashMap();
            Iterator<String> keys= ((JSONObject) arguments).keys();
            while(keys.hasNext()){
                String key=keys.next();
                try {
                    m.put(key,((JSONObject) arguments).getString(key));
                }catch (Exception e){
                     throw new  IllegalArgumentException("support string argument only");
                }
            }
            return  m;
        } else {
            throw new ClassCastException();
        }
    }
    private void setPackages (Object arguments){
        if (arguments == null) {
            return ;
        } else if (arguments instanceof Map) {
           this.canCallAppPackages.putAll((Map)arguments);
        } else if (arguments instanceof JSONObject) {
            Iterator<String> keys= ((JSONObject) arguments).keys();
            while(keys.hasNext()){
                String key=keys.next();
                try {
                    this.canCallAppPackages.put(key,((JSONObject) arguments).getString(key));
                }catch (Exception e){
                    throw new  IllegalArgumentException("support string argument only");
                }
            }
            return;
        } else {
            throw new ClassCastException();
        }
    }
    @Override
    public void onCancel(Object o) {
        changeReceiver = null;
    }

    @Override
    public void onMethodCall(MethodCall call, MethodChannel.Result result) {
        if (call.method.equals("getInitialLink")) {
            result.success(initialLink);
        } else if (call.method.equals("getLatestLink")) {
            result.success(latestLink);
        } else if(call.method.equals("setResult")) {
            int code=call.argument("code");
            setResult(code,toMap(call.argument("arguments")));
            result.success(true);
        }else if(call.method.equals("setPackages")){
            this.setPackages(call.arguments());
            result.success(true);
        } else {
            result.notImplemented();
        }
    }

    @Override
    public boolean onNewIntent(Intent intent) {
        this.handleIntent(context, intent);
        return false;
    }

    @Override
    public void onAttachedToActivity(ActivityPluginBinding activityPluginBinding) {
        activityPluginBinding.addOnNewIntentListener(this);
        this.activity=activityPluginBinding.getActivity();
        ComponentName callingActivity =activity.getCallingActivity();
        if(callingActivity!=null){
            if(!validateCallingApp(activity.getCallingActivity())){

            }
        }
        this.handleIntent(this.context, activityPluginBinding.getActivity().getIntent());
    }

    @Override
    public void onDetachedFromActivityForConfigChanges() {}

    @Override
    public void onReattachedToActivityForConfigChanges(
            ActivityPluginBinding activityPluginBinding) {
        activityPluginBinding.addOnNewIntentListener(this);
        this.handleIntent(this.context, activityPluginBinding.getActivity().getIntent());
    }

    @Override
    public void onDetachedFromActivity() {}

    private Map<String,Object> canCallAppPackages=new HashMap<>();
    private boolean validateCallingApp(ComponentName callingActivity) {
        if(canCallAppPackages==null||canCallAppPackages.isEmpty()){
            return true;
        }
        if (callingActivity != null) {
            String packageName = callingActivity.getPackageName();
            if (canCallAppPackages.containsKey(packageName)) {//
                Log.d(TAG,packageName);
                try {
                    String fingerPrint = getCertificateFingerprint(context, packageName);
                    Log.d(TAG,fingerPrint);
                    return canCallAppPackages.get(packageName).toString().equalsIgnoreCase(fingerPrint);
                } catch (PackageManager.NameNotFoundException e) {
                    Log.e(TAG, "No such app is installed", e);
                }
            }
        }
        return false;
    }

    //@Nullable
    private String getCertificateFingerprint(Context context, String packageName)
            throws PackageManager.NameNotFoundException {
        PackageManager pm = context.getPackageManager();
        PackageInfo packageInfo = pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES);
        Signature[] signatures = packageInfo.signatures;
        InputStream input = new ByteArrayInputStream(signatures[0].toByteArray());
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(input);
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] publicKey = md.digest(certificate.getEncoded());
            return byte2HexFormatted(publicKey);
        } catch (NoSuchAlgorithmException | CertificateException e) {
            Log.e(TAG, "Failed to process the certificate", e);
        }
        return null;
    }
    private String byte2HexFormatted(byte[] byteArray) {
        Formatter formatter = new Formatter();
        for (int i = 0; i < byteArray.length - 1; i++) {
            formatter.format("%02x:", byteArray[i]);
        }
        formatter.format("%02x", byteArray[byteArray.length - 1]);
        return formatter.toString().toUpperCase();
    }
}
