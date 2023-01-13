package com.nccgroup.loggerplusplus.exports;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.util.Globals;
import com.nccgroup.loggerplusplus.util.MoreHelp;
import com.nccgroup.loggerplusplus.util.SwingWorkerWithProgressDialog;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;

public class HARExporter extends LogExporter implements ExportPanelProvider, ContextMenuExportProvider {

    private final HARExporterControlPanel controlPanel;

    public HARExporter(ExportController exportController, Preferences preferences) {
        super(exportController, preferences);
        this.controlPanel = new HARExporterControlPanel(this);
    }

    @Override
    public JComponent getExportPanel() {
        return this.controlPanel;
    }

    public void exportEntries(List<LogEntry> entries) {
        try {
            SwingWorkerWithProgressDialog<Void> importWorker = new SwingWorkerWithProgressDialog<Void>(
                    JOptionPane.getFrameForComponent(this.controlPanel), "HAR Export", "Exporting as HAR...",
                    entries.size()) {
                @Override
                protected Void doInBackground() throws Exception {
                    super.doInBackground();
                    sendRequestToAkto(entries);
                    return null;
                }

                @Override
                protected void done() {
                    super.done();
                    String message = "Export to Akto Completed! Batches Failed: " + failedRequests.size() + "\n";
                    JOptionPane.showMessageDialog(controlPanel, message, "HAR Export",
                            JOptionPane.INFORMATION_MESSAGE);
                }
            };

            importWorker.execute();

        } catch (Exception e) {
            // Cancelled.
        }
    }

    List<Integer> failedRequests = new ArrayList<>();

    public void sendRequestToAkto(List<LogEntry> entries) {
        failedRequests = new ArrayList<>();
        String JSON_CONTENT_TYPE = "application/json";
        int batchSize = 100;
        List<LogEntry> batch = new ArrayList<>();

        String akto_ip = preferences.getSetting("AKTO_IP");
        String akto_token = preferences.getSetting("AKTO_TOKEN");
        String apiCollectionName = preferences.getSetting("AKTO_COLLECTION_NAME");
        
        int batchNum = 1;
        for (LogEntry entry: entries) {
            boolean shouldSend = false;
            try {
                shouldSend = HarSerializer.shouldSend(entry);
            } catch (Exception e) {
                shouldSend = false;
                LoggerPlusPlus.callbacks.printError("ERROR FOUND SKIP: " + e.getMessage());
            }
            if (!shouldSend) {
                continue;
            }

            batch.add(entry);

            if (batch.size() >= batchSize) {
                boolean shouldStop = sendBatch(batch,batchNum, akto_ip, akto_token, apiCollectionName);
                if (shouldStop) {
                    return;
                }
                batch = new ArrayList<>();
                LoggerPlusPlus.callbacks.printOutput("Batch " + batchNum + " Done");
                batchNum += 1;
            }
        }
        LoggerPlusPlus.callbacks.printOutput("entries pending " + batch.size());
        
        if (batch.size() != 0) {
            sendBatch(batch,batchNum, akto_ip, akto_token, apiCollectionName);
            LoggerPlusPlus.callbacks.printOutput("BATCH " + batchNum + " Done");
            batchNum += 1;
            batch = new ArrayList<>();
        }
        
        LoggerPlusPlus.callbacks.printOutput("ALL DONE");

        Type logEntryListType = new TypeToken<List<LogEntry>>(){}.getType();
        Gson gson = new GsonBuilder().registerTypeAdapter(logEntryListType, new HarSerializer(String.valueOf(Globals.VERSION), "Akto")).create();
        try {
            File file = MoreHelp.getSaveFile(apiCollectionName+ ".har", "HAR Format", "har");
            FileWriter fileWriter = new FileWriter(file, false);
            gson.toJson(entries, logEntryListType, fileWriter);
            fileWriter.flush();
            fileWriter.close();
        } catch (Exception e1) {
            e1.printStackTrace();
        }


    }

    public static CloseableHttpClient httpClient = HttpClientBuilder.create().setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE).build();
    public boolean sendBatch(List<LogEntry> entries, int batchCode, String akto_ip, String akto_token, String apiCollectionName) {
        Type logEntryListType = new TypeToken<List<LogEntry>>(){}.getType();
        Gson gson = new GsonBuilder().registerTypeAdapter(logEntryListType, new HarSerializer(String.valueOf(Globals.VERSION), "Akto")).create();
        CloseableHttpResponse response;

        try {

            Map<String, List<LogEntry>> finalMap = new HashMap<>();
            finalMap.put("content", entries);
            String body = gson.toJson(finalMap, new TypeToken<Map<String,List<LogEntry>>>(){}.getType());

            Gson gson1 = new Gson();
            Map<String,String> gg = gson1.fromJson(body, Map.class);
            gg.put("apiCollectionName", apiCollectionName);
            String body1 = gson.toJson(gg);

            HttpPost post = new HttpPost(akto_ip+"/api/uploadHar");
            post.setEntity(new StringEntity(body1));
            post.setHeader("Content-type", "application/json");
            post.setHeader("X-API-KEY", akto_token);

            LoggerPlusPlus.callbacks.printOutput("sending batch " + batchCode);
            response =  httpClient.execute(post);
            LoggerPlusPlus.callbacks.printOutput("sent batch " + batchCode);
            String responseString = EntityUtils.toString(response.getEntity());
            try {
                int statusCode = response.getStatusLine().getStatusCode();

                if (statusCode == 422) {
                    JsonObject jsonResp = new Gson().fromJson(responseString, JsonObject.class); // String to JSONObject
                    if (jsonResp.has("actionErrors")) {
                        String err;
                        JsonArray errArray = jsonResp.getAsJsonArray("actionErrors");
                        if (errArray.size() > 0) {
                            err = errArray.get(0).toString().replace("\"", "");
                        } else {
                            err = "422 error code";
                        }
                        JOptionPane.showMessageDialog(controlPanel, err, "Akto", JOptionPane.INFORMATION_MESSAGE);
                    }
                } else if (statusCode == 403) {
                    JOptionPane.showMessageDialog(controlPanel,"Invalid API key", "Akto",
                            JOptionPane.INFORMATION_MESSAGE);
                } 

                if (statusCode < 200 || statusCode >= 300) {
                    failedRequests.add(batchCode);
                }

                LoggerPlusPlus.callbacks.printError(responseString);

                List<Integer> stopList = Arrays.asList(403,422);
                return stopList.contains(statusCode);

            } catch (Exception e) {
                return true;

            } finally {
                response.close();
            }

        } catch(Exception e) {
            LoggerPlusPlus.callbacks.printError(e.getMessage());
            JOptionPane.showMessageDialog(controlPanel, e.toString(), "Akto",
                JOptionPane.INFORMATION_MESSAGE);
            return true;
        } finally {
        }


    }

    @Override
    public JMenuItem getExportEntriesMenuItem(List<LogEntry> entries) {
        return new JMenuItem(new AbstractAction(
                String.format("Export %d %s to Akto", entries.size(), entries.size() != 1 ? "entries" : "entry")) {
            @Override
            public void actionPerformed(ActionEvent e) {
                exportEntries(entries);
            }
        });
    }

    public ExportController getExportController() {
        return this.exportController;
    }
}