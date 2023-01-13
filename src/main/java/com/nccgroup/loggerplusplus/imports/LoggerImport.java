//
// Burp Suite Logger++
// 
// Released as open source by NCC Group Plc - https://www.nccgroup.trust/
// 
// Originally Developed by Soroush Dalili (@irsdl)
// Maintained by Corey Arthur (@CoreyD97)
//
// Project link: http://www.github.com/nccgroup/BurpSuiteLoggerPlusPlus
//
// Released under AGPL see LICENSE for more information
//

package com.nccgroup.loggerplusplus.imports;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import com.google.gson.*;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.logview.processor.EntryImportWorker;
import com.nccgroup.loggerplusplus.util.SwingWorkerWithProgressDialog;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;

import javax.swing.*;
import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class LoggerImport {

    public static String getLoadFile() {
        JFileChooser chooser = null;
        chooser = new JFileChooser();
        chooser.setDialogTitle("Import File");
        int val = chooser.showOpenDialog(null);

        if (val == JFileChooser.APPROVE_OPTION) {
            return chooser.getSelectedFile().getAbsolutePath();
        }

        return "";
    }

    public static ArrayList<String> readFile(String filename) {
        BufferedReader reader;
        ArrayList<String> lines = new ArrayList<String>();

        try {
            reader = new BufferedReader(new FileReader(filename));
        } catch (FileNotFoundException e) {
            LoggerPlusPlus.callbacks.printError("LoggerImport-readFile: Error Opening File " + filename);
            return new ArrayList<String>();
        }
        try {
            String line;
            while ( (line = reader.readLine()) != null ) {
                lines.add(line);
            }
        } catch (IOException e) {
            LoggerPlusPlus.callbacks.printError("LoggerImport-readFile: Error Reading Line");
            return new ArrayList<String>();
        }

        return lines;
    }

    public static ArrayList<IHttpRequestResponse> importWStalker() {
        ArrayList<String> lines;
        ArrayList<IHttpRequestResponse> requests = new ArrayList<>();
        IExtensionHelpers helpers = LoggerPlusPlus.callbacks.getHelpers();
        
        String filename = getLoadFile();
        if ( filename.length() == 0 ) { // exit if no file selected
            return new ArrayList<>();
        }

        lines = readFile(filename);
        Iterator<String> i = lines.iterator();
        
        while (i.hasNext()) {
            try {
                String line = i.next();
                String[] v = line.split(","); // Format: "base64(request),base64(response),url"

                byte[] request = helpers.base64Decode(v[0]);
                byte[] response = helpers.base64Decode(v[1]);
                String url = v[3];

                ImportRequestResponse x = new ImportRequestResponse(url, request, response);
                requests.add(x);

            } catch (Exception e) {
                LoggerPlusPlus.callbacks.printError("LoggerImport-importWStalker: Error Parsing Content");
                return new ArrayList<IHttpRequestResponse>();
            }
        }

        return requests;
    }

    public static void importAktoMain(String collectionName, String apiKey, String url) {
        try {
            Thread newThread = new Thread(() -> {
                String lastMethodFetched = null;
                String lastUrlFetched = null;
                int i = 0;
                try {
                    while ( i < 30 ) {
                        i += 1;
                        LoggerPlusPlus.callbacks.printOutput(i+"");
                        Map<String, String> result = importAkto(collectionName, apiKey, url, lastUrlFetched,  lastMethodFetched);
                        lastMethodFetched = result.get("lastMethodFetched");
                        lastUrlFetched = result.get("lastUrlFetched");
                        if (lastUrlFetched == null) break;
                    }
                } catch (Exception ex) {
                    LoggerPlusPlus.callbacks.printError(ex.getMessage());
                    LoggerPlusPlus.callbacks.printError(Arrays.toString(ex.getStackTrace()));
                }
            });
            newThread.start();

        } catch (Exception e) {
            // Cancelled.
        }
    }


    public static Map<String, String> importAkto(String collectionName, String apiKey, String url, String lastUrlFetched,
                                                 String lastMethodFetched) throws Exception {
        LoggerPlusPlus.callbacks.printOutput("IMPORT from akto " + collectionName + " " + apiKey);

        ArrayList<IHttpRequestResponse> requests = new ArrayList<>();

        HttpPost post = new HttpPost(url + "/api/importInBurp");
        Map<String, String> body = new HashMap<>();
        body.put("collectionName", collectionName);
        body.put("lastUrlFetched", lastUrlFetched);
        body.put("lastMethodFetched", lastMethodFetched);
        String json = new Gson().toJson(body);
        HttpEntity e = new StringEntity(json);
        post.setEntity(e);
        post.setHeader("Content-type", "application/json");
        post.setHeader("X-API-KEY", apiKey);

        CloseableHttpClient httpClient = HttpClientBuilder.create().setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE).build();
        CloseableHttpResponse response =  httpClient.execute(post);
        String responseString = EntityUtils.toString(response.getEntity());

        JsonObject jsonResp = new Gson().fromJson(responseString, JsonObject.class); // String to JSONObject
        JsonArray importInBurpResult = jsonResp.get("importInBurpResult").getAsJsonArray();

        JsonElement lastUrlFetchedElement = jsonResp.get("lastUrlFetched");
        if (!lastUrlFetchedElement.isJsonNull()) {
            lastUrlFetched = lastUrlFetchedElement.getAsString();
        } else {
            lastUrlFetched = null;
        }

        JsonElement lastMethodFetchedElement = jsonResp.get("lastMethodFetched");
        if (!lastMethodFetchedElement.isJsonNull()) {
            lastMethodFetched = lastMethodFetchedElement.getAsString();
        } else {
            lastMethodFetched = null;
        }

        LoggerPlusPlus.callbacks.printOutput("size: " + importInBurpResult.size());

        for (JsonElement o: importInBurpResult) {
            JsonObject j = o.getAsJsonObject();
            String reqUrl = j.get("url").getAsString();
            String req = j.get("req").getAsString();
            String res = j.get("res").getAsString();

            ImportRequestResponse x = new ImportRequestResponse(reqUrl, req.getBytes(StandardCharsets.UTF_8), res.getBytes(StandardCharsets.UTF_8));
            requests.add(x);
        }

        LoggerPlusPlus.callbacks.printOutput("count: " + requests.size());

        LoggerImport.loadImported(requests, false);

        Map<String, String> result = new HashMap<>();
        result.put("lastUrlFetched", lastUrlFetched);
        result.put("lastMethodFetched", lastMethodFetched);
        return result;
    }

    public static ArrayList<IHttpRequestResponse> importZAP() {
        ArrayList<String> lines = new ArrayList<String>();
        ArrayList<IHttpRequestResponse> requests = new ArrayList<IHttpRequestResponse>();
        IExtensionHelpers helpers = LoggerPlusPlus.callbacks.getHelpers();
        
        String filename = getLoadFile();
        if ( filename.length() == 0 ) { // exit if no file selected
            return new ArrayList<IHttpRequestResponse>();
        }

        lines = readFile(filename);
        Iterator<String> i = lines.iterator();

        // Format:
        // ==== [0-9]+ ==========
        // REQUEST
        // <empty>
        // RESPONSE
        String reSeparator = "^==== [0-9]+ ==========$";
        String reResponse = "^HTTP/[0-9]\\.[0-9] [0-9]+ .*$";

        // Ignore first line, since it should be a separator
        if ( i.hasNext() ) {
            i.next();
        }

        boolean isRequest = true;
        String requestBuffer = "";
        String responseBuffer = "";
        String url = "";

        // Loop lines
        while (i.hasNext()) {
            String line = i.next();

            // Request and Response Ready
            if ( line.matches(reSeparator) || !i.hasNext() ) {
                // TODO: Remove one or two \n at the end of requestBuffer

                byte[] req = helpers.stringToBytes(requestBuffer);
                byte[] res = helpers.stringToBytes(responseBuffer);

                // Add IHttpRequestResponse Object
                ImportRequestResponse x = new ImportRequestResponse(url, req, res);
                requests.add(x);

                // Reset content
                isRequest = true;
                requestBuffer = "";
                responseBuffer = "";
                url = "";

                continue;
            }

            // It's the beginning of a request
            if ( requestBuffer.length() == 0 ) {
                try {
                    // Expected format: "GET https://whatever/whatever.html HTTP/1.1"
                    String[] x = line.split(" ");
                    url = x[1];

                    URL u = new URL(url);
                    String path = u.getPath();
                    line = x[0] + " " + path + " " + x[2]; // fix the path in the request

                } catch (Exception e) {
                    LoggerPlusPlus.callbacks.printError("importZAP: Wrong Path Format");
                    return new ArrayList<>();
                } 
            }

            // It's the beginning of a response
            if ( line.matches(reResponse) ) {
                isRequest = false;
            }

            // Add line to the corresponding buffer
            if ( isRequest ) {
                requestBuffer += line;
                requestBuffer += "\n";
            } else {
                responseBuffer += line;
                responseBuffer += "\n";
            }
        }

        return requests;
    }

    public static boolean loadImported(ArrayList<IHttpRequestResponse> requests, Boolean sendToAutoExporters) {
        EntryImportWorker importWorker = LoggerPlusPlus.instance.getLogProcessor().createEntryImportBuilder()
                .setOriginatingTool(IBurpExtenderCallbacks.TOOL_EXTENDER)
                .setEntries(requests)
                .setInterimConsumer(integers -> {
                    //Optional
                    //Outputs chunks of integers representing imported indices
                    //May be used to update progress bar for example
                })
                .setCallback(() -> {
                    //Optional
                //Called when all entries have been imported.
            }).build();
        importWorker.execute();

        return true;
    }
}