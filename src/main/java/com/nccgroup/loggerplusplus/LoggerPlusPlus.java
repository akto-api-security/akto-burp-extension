package com.nccgroup.loggerplusplus;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionStateListener;
import com.coreyd97.BurpExtenderUtilities.DefaultGsonProvider;
import com.coreyd97.BurpExtenderUtilities.IGsonProvider;
import com.google.gson.Gson;
import com.nccgroup.loggerplusplus.about.AboutPanel;
import com.nccgroup.loggerplusplus.exports.ExportController;
import com.nccgroup.loggerplusplus.exports.HARExporter;
import com.nccgroup.loggerplusplus.filterlibrary.FilterLibraryController;
import com.nccgroup.loggerplusplus.grepper.GrepperController;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.logging.LoggingController;
import com.nccgroup.loggerplusplus.logview.LogViewController;
import com.nccgroup.loggerplusplus.logview.processor.LogProcessor;
import com.nccgroup.loggerplusplus.preferences.PreferencesController;
import com.nccgroup.loggerplusplus.reflection.ReflectionController;
import com.nccgroup.loggerplusplus.util.Globals;
import com.nccgroup.loggerplusplus.util.userinterface.LoggerMenu;

import org.apache.commons.logging.Log;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.apache.logging.log4j.Level;

import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.Base64;

import static com.nccgroup.loggerplusplus.util.Globals.PREF_RESTRICT_TO_SCOPE;

/**
 * Created by corey on 07/09/17.
 */
public class LoggerPlusPlus implements IBurpExtender, IExtensionStateListener {
    public static LoggerPlusPlus instance;
    public static IBurpExtenderCallbacks callbacks;
    public List<LogEntry> logEntries = new ArrayList<>();

    private final IGsonProvider gsonProvider;
    private LoggingController loggingController;
    private LogProcessor logProcessor;
    private ExportController exportController;
    private PreferencesController preferencesController;
    private LogViewController logViewController;
    private FilterLibraryController libraryController;
    private LoggerContextMenuFactory contextMenuFactory;
    private GrepperController grepperController;
    private MainViewController mainViewController;
    private ReflectionController reflectionController;

    //UX
    private LoggerMenu loggerMenu;


    public LoggerPlusPlus(){
        this.gsonProvider = new DefaultGsonProvider();
    }

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {

        //Fix Darcula's issue with JSpinner UI.
        try {
            Class spinnerUI = Class.forName("com.bulenkov.darcula.ui.DarculaSpinnerUI");
            UIManager.put("com.bulenkov.darcula.ui.DarculaSpinnerUI", spinnerUI);
            Class sliderUI = Class.forName("com.bulenkov.darcula.ui.DarculaSliderUI");
            UIManager.put("com.bulenkov.darcula.ui.DarculaSliderUI", sliderUI);
        } catch (ClassNotFoundException e) {
            //Darcula is not installed.
        }

        //Burp Specific
        LoggerPlusPlus.instance = this;
        LoggerPlusPlus.callbacks = callbacks;
        callbacks.setExtensionName("Akto");
        LoggerPlusPlus.callbacks.registerExtensionStateListener(LoggerPlusPlus.this);

        LoggerPlusPlus.callbacks.printOutput("Akto Burp plugin initialising.....");


        loggingController = new LoggingController(gsonProvider);
        preferencesController = new PreferencesController(this);
        preferencesController.getPreferences().addSettingListener((source, settingName, newValue) -> {
            if (settingName.equals(Globals.PREF_LOG_LEVEL)) {
                loggingController.setLogLevel((Level) newValue);
            }
        });
        reflectionController = new ReflectionController(preferencesController.getPreferences());
        exportController = new ExportController(this, preferencesController.getPreferences());
        libraryController = new FilterLibraryController(this, preferencesController);
        logViewController = new LogViewController(this, libraryController);
        logProcessor = new LogProcessor(this, logViewController.getLogTableController(), exportController);
        grepperController = new GrepperController(this, logViewController.getLogTableController(), preferencesController);
        contextMenuFactory = new LoggerContextMenuFactory(this);

        mainViewController = new MainViewController(this);

        versionString = "5";
        preferencesController.getPreferences().setSetting("AKTO_PLUGIN_VERSION", versionString);
        preferencesController.getPreferences().setSetting("AKTO_COLLECTION_NAME", "Burp");

        startHealthCheckThread();
        startAutoExportToAktoThread();

        LoggerPlusPlus.callbacks.registerContextMenuFactory(contextMenuFactory);


        SwingUtilities.invokeLater(() -> {

            LoggerPlusPlus.callbacks.addSuiteTab(mainViewController);

            //Add menu item to Burp's frame menu.
            JFrame rootFrame = (JFrame) SwingUtilities.getWindowAncestor(mainViewController.getUiComponent());
            try{
                JMenuBar menuBar = rootFrame.getJMenuBar();
                loggerMenu = new LoggerMenu(LoggerPlusPlus.this);
                menuBar.add(loggerMenu, menuBar.getMenuCount() - 1);
            }catch (NullPointerException nPException){
                loggerMenu = null;
            }
        });

    }

    public static CloseableHttpClient httpClient = HttpClientBuilder.create().setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE).build();

    public void startAutoExportToAktoThread() {
        scheduler.scheduleAtFixedRate(() -> {
            try {
                String akto_ip = preferencesController.getPreferences().getSetting("AKTO_IP");
                String akto_token = preferencesController.getPreferences().getSetting("AKTO_TOKEN");
                if (akto_ip == null || akto_ip.trim().isEmpty() || akto_token == null || akto_token.trim().isEmpty()) return;

                sendDataToAkto();
            } catch (Exception e) {
                LoggerPlusPlus.callbacks.printError("ERROR while sending data to akto: "  + Arrays.toString(e.getStackTrace()));
            }
        }, 0, 10, TimeUnit.SECONDS);
    }


    public void sendDataToAkto() {
        if (instance.logEntries.size() > 0) {
            List<LogEntry> data = new ArrayList<>(instance.logEntries);
            instance.logEntries = new ArrayList<>();
            callbacks.printOutput("Sending data...");

            String collectionName = instance.getPreferencesController().getPreferences().getSetting("AKTO_COLLECTION_NAME");
            String aktoIp = instance.getPreferencesController().getPreferences().getSetting("AKTO_IP");
            String aktoToken = instance.getPreferencesController().getPreferences().getSetting("AKTO_TOKEN");
            String akto_proxy_ip = instance.getPreferencesController().getPreferences().getSetting("AKTO_PROXY_IP");
            String akto_proxy_username = instance.getPreferencesController().getPreferences().getSetting("AKTO_PROXY_USERNAME");
            String akto_proxy_password = instance.getPreferencesController().getPreferences().getSetting("AKTO_PROXY_PASSWORD");
            
            HARExporter.sendBatch(data.subList(0,Math.min(100, data.size())), 0, aktoIp, aktoToken, collectionName, akto_proxy_ip, akto_proxy_username, akto_proxy_password);
        }
    }
    ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(10);

    public void startHealthCheckThread() {
        try {
            sendHealthCheck(true);
        } catch (Exception e) {
            LoggerPlusPlus.callbacks.printError("ERROR while sending health check to akto: "  + Arrays.toString(e.getStackTrace()));
        }
        scheduler.scheduleAtFixedRate(() -> {
            try {
                sendHealthCheck(false);
            } catch (Exception e) {
                LoggerPlusPlus.callbacks.printError("ERROR while sending health check to akto: "  + Arrays.toString(e.getStackTrace()));
            }
        }, 5, 1, TimeUnit.MINUTES);
    }

    private static final Gson gson = new Gson();

    private static String versionString = null;

    public void sendHealthCheck(boolean initialCall) {
        CloseableHttpResponse response;
        String akto_ip = preferencesController.getPreferences().getSetting("AKTO_IP");
        String akto_token = preferencesController.getPreferences().getSetting("AKTO_TOKEN");
        String akto_proxy_ip = preferencesController.getPreferences().getSetting("AKTO_PROXY_IP");
        String akto_proxy_username = preferencesController.getPreferences().getSetting("AKTO_PROXY_USERNAME");
        String akto_proxy_password = preferencesController.getPreferences().getSetting("AKTO_PROXY_PASSWORD");

        if (akto_ip == null || akto_ip.trim().isEmpty() || akto_token == null || akto_token.trim().isEmpty()) {
            return;
        }

        if (versionString == null) versionString = "-1";

        Map<String, String> request = new HashMap<>();
        request.put("version", versionString);
        String requestString = gson.toJson(request);

        LoggerPlusPlus.callbacks.printOutput("REQUEST: " + requestString);

        HttpClientBuilder clientbuilder = HttpClients.custom();
        RequestConfig.Builder reqconfigconbuilder= RequestConfig.custom();
        int proxy_needed = 0;

        String protocol = "";
        String hostname = "";
        try {
            URL akto_url = new URL(akto_ip);
            protocol = akto_url.getProtocol();
            hostname = akto_url.getHost();
        } catch (Exception e) {
            e.printStackTrace();
        }

        HttpHost target  = new HttpHost(hostname,0, protocol);

        if (akto_proxy_ip.length() != 0 && akto_proxy_username.length() != 0 && akto_proxy_password.length() != 0) {
            proxy_needed = 1;
            // LoggerPlusPlus.callbacks.printOutput("testing heath check: " + akto_proxy_ip);
            String akto_proxy_protocol = "";
            String akto_proxy_hostname = "";
            int akto_proxy_port = 0;
            try {
                URL akto_proxy_url = new URL(akto_proxy_ip);
                akto_proxy_protocol = akto_proxy_url.getProtocol();
                akto_proxy_hostname = akto_proxy_url.getHost();
                akto_proxy_port = akto_proxy_url.getPort();
            } catch (Exception e) {
                e.printStackTrace();
            }


            CredentialsProvider credentialsPovider = new BasicCredentialsProvider();
            credentialsPovider.setCredentials(new AuthScope(akto_proxy_hostname,akto_proxy_port), new
            UsernamePasswordCredentials(akto_proxy_username, akto_proxy_password));
            
            clientbuilder = clientbuilder.setDefaultCredentialsProvider(credentialsPovider);
            HttpHost proxy = new HttpHost(akto_proxy_hostname, akto_proxy_port, akto_proxy_protocol);
            reqconfigconbuilder = reqconfigconbuilder.setProxy(proxy);
        }

        RequestConfig config = reqconfigconbuilder.build();
        CloseableHttpClient httpClient = clientbuilder.setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE).build();

        try {

            HttpPost post = new HttpPost(akto_ip+"/api/sendHealthCheck");
            post.setHeader("X-API-KEY", akto_token);
            post.setHeader("Content-type", "application/json");
            post.setEntity(new StringEntity(requestString));
            
            if (proxy_needed==1) {
                String encodedString = Base64.getEncoder().encodeToString((akto_proxy_username+ ":"+ akto_proxy_password).getBytes());
                post.setHeader("Authorization", "Basic " + encodedString);
                post.setConfig(config);
                response =  httpClient.execute( target ,post);
            }
            else
            {
                response = httpClient.execute(post);
            }

            int statusCode = response.getStatusLine().getStatusCode();
            LoggerPlusPlus.callbacks.printOutput("The status code is: " + (statusCode));

            if (initialCall) {
                if (response != null && response.getEntity() != null) {
                    String responseString = EntityUtils.toString(response.getEntity(), "UTF-8");
                    Map<String, Object> responseMap = gson.fromJson(responseString, Map.class);
                    Double latestVersionDouble = (Double) responseMap.get("latestVersion");
                    int latestVersion = latestVersionDouble.intValue();

                    try {
                        int currentVersion = Integer.parseInt(versionString);
                        if (currentVersion < latestVersion) {
                            String message = "This is old an plugin!! Download the newer one from " + akto_ip;
                             JOptionPane.showMessageDialog(JOptionPane.getFrameForComponent(
                                 LoggerPlusPlus.instance.getMainViewController().getUiComponent()), message);
                        }
                    } catch (Exception e) {
                        LoggerPlusPlus.callbacks.printError("Invalid version: " + versionString);
                    }
                }
            }
        } catch (Exception e) {
            LoggerPlusPlus.callbacks.printError("Error in sending health checkup: " + e.getLocalizedMessage());
        }

    }

    @Override
    public void extensionUnloaded() {
        if(loggerMenu != null && loggerMenu.getParent() != null){
            loggerMenu.getParent().remove(loggerMenu);
        }
        if(mainViewController.getPopOutWrapper().isPoppedOut()) {
            mainViewController.getPopOutWrapper().getPopoutFrame().dispose();
        }
        if(logViewController.getRequestViewerController().getRequestViewerPanel().isPoppedOut()) {
            logViewController.getRequestViewerController().getRequestViewerPanel().getPopoutFrame().dispose();
        }

        //Stop log processor executors and pending tasks.
        logProcessor.shutdown();

        //Null out static variables so not leftover.
        LoggerPlusPlus.instance = null;
        LoggerPlusPlus.callbacks = null;
    }

    public static boolean isUrlInScope(URL url){
        return (!(Boolean) instance.getPreferencesController().getPreferences().getSetting(PREF_RESTRICT_TO_SCOPE)
                || callbacks.isInScope(url));
    }


    public LogViewController getLogViewController() {
        return logViewController;
    }

    public IGsonProvider getGsonProvider() {
        return gsonProvider;
    }

    public GrepperController getGrepperController() {
        return grepperController;
    }

    public MainViewController getMainViewController() {
        return mainViewController;
    }

    public FilterLibraryController getLibraryController() {
        return libraryController;
    }

    public LoggingController getLoggingController() {
        return loggingController;
    }

    public PreferencesController getPreferencesController() {
        return preferencesController;
    }

    public LogProcessor getLogProcessor() {
        return logProcessor;
    }

    public ReflectionController getReflectionController() {
        return reflectionController;
    }

    public LoggerMenu getLoggerMenu() {
        return loggerMenu;
    }

    public List<LogEntry> getLogEntries(){
        return logViewController.getLogTableController().getLogTableModel().getData();
    }

    public ExportController getExportController() {
        return exportController;
    }

    public Frame getLoggerFrame() {
        if (mainViewController == null) {
            return Arrays.stream(JFrame.getFrames()).filter(frame -> {
                return frame.getTitle().startsWith("Burp Suite") && frame.isVisible();
            }).findFirst().orElse(null);
        }
        return JOptionPane.getFrameForComponent(mainViewController.getTabbedPanel());
    }
}
