/*
 * Copyright 2017 ELIXIR EGA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.elixir.ega.ebi.reencryptionmvc.config;

import com.google.common.io.CountingInputStream;
import eu.elixir.ega.ebi.reencryptionmvc.dto.CachePage;
import eu.elixir.ega.ebi.reencryptionmvc.dto.EgaAESFileHeader;
import eu.elixir.ega.ebi.reencryptionmvc.dto.MyAwsConfig;
import eu.elixir.ega.ebi.reencryptionmvc.service.KeyService;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClientBuilder;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.cache2k.Cache;

import java.io.DataInputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;

/**
 * @author asenf
 */
public class ObjectLoaderPlain implements Runnable {

    private byte[] buffer;
    private int bytesRead;

    private final String url;
    private final String auth;
    private final int BUFFER_SIZE;
    private final String id;
    private long startCoordinate, endCoordinate;

    private HttpClient httpclient;
    private Cache<String, CachePage> object;   // Global Cache
    private int cachePage;

    private final MyAwsConfig myAwsConfig;
    private final KeyService keyService;

    private EgaAESFileHeader header;

    /**
     * Bouncy Castle code for Public Key encrypted Files
     */
    private static final KeyFingerPrintCalculator fingerPrintCalculater = new BcKeyFingerprintCalculator();
    private static final BcPGPDigestCalculatorProvider calc = new BcPGPDigestCalculatorProvider();

    /**
     * Cache unencrypted Data in Memory
     *
     * @param url
     * @param auth
     * @param bufSize
     * @param myCache
     * @param id
     * @param startCoordinate
     * @param endCoordinate
     * @param myAwsConfig
     * @param keyService
     * @param header
     */
    public ObjectLoaderPlain(String url, String auth, int bufSize,
                             Cache<String, CachePage> myCache,
                             String id, long startCoordinate, long endCoordinate,
                             MyAwsConfig myAwsConfig, KeyService keyService,
                             EgaAESFileHeader header) {
        this.url = url;

        URL url_ = null;
        try {
            url_ = new URL(url);
        } catch (MalformedURLException ex) {
        }
        if (url_ != null && url_.getUserInfo() != null) {
            String encoding = new sun.misc.BASE64Encoder().encode(url_.getUserInfo().getBytes());
            encoding = encoding.replaceAll("\n", "");
            this.auth = "Basic " + encoding;
        } else if (auth != null && auth.length() > 0) {
            String encoding = new sun.misc.BASE64Encoder().encode(auth.getBytes());
            encoding = encoding.replaceAll("\n", "");
            this.auth = "Basic " + encoding;
        } else {
            this.auth = null;
        }

        // Buffer Size - Customize
        long buf_endCoordinate = ((endCoordinate) > header.getSize() ? header.getSize() : (endCoordinate));
        long buf_startCoordinate = startCoordinate;
        long buf_size = (buf_endCoordinate - buf_startCoordinate) < bufSize ? (buf_endCoordinate - buf_startCoordinate) : bufSize;
        this.BUFFER_SIZE = (int) buf_size; // bufSize
        this.id = id;
        this.startCoordinate = startCoordinate;
        this.endCoordinate = endCoordinate;

        this.myAwsConfig = myAwsConfig;
        this.keyService = keyService;

        this.buffer = new byte[this.BUFFER_SIZE];
        this.bytesRead = 0;
        this.httpclient = HttpClientBuilder.create().build();
        this.cachePage = (int) (startCoordinate / bufSize);

        this.object = myCache;

        this.header = header;
    }

    @Override
    public void run() {
        // Sanity Check
        if (object == null) return; // Should throw error
        String key = this.id + "_" + this.cachePage; // Page Key
        if (object.containsKey(key)) {
            return;
        } // If page is already loaded; nothing to do

        // Prepare Request (containd query parameters
        HttpGet request = new HttpGet(this.url);

        // Add request header for Basic Auth (for CleverSafe)
        if (auth != null && auth.length() > 0)
            request.addHeader("Authorization", this.auth);

        // Add range header - logical (unencrypted) coordinates to file coordinates
        String byteRange = "bytes=" + (startCoordinate + 16) + "-" + ((endCoordinate + 16) > header.getSize() ? header.getSize() : (endCoordinate + 16));
        request.addHeader("Range", byteRange);

        synchronized (this) {
            try {

                // Run the request
                HttpResponse response = this.httpclient.execute(request);

                // Read response from HTTP call, count bytes read (encrypted Data)
                CountingInputStream cIn = new CountingInputStream(response.getEntity().getContent());
                DataInputStream dis = new DataInputStream(cIn);
                dis.readFully(buffer);
                this.bytesRead = (int) cIn.getCount(); // Cache Page will be in Integer range

                this.object.put(key, new CachePage(buffer));
            } catch (IOException | UnsupportedOperationException th) {
                System.out.println("HTTP GET ERROR " + th.toString());
            } catch (Exception ex) {
                System.out.println("HTTP GET ERROR " + ex.toString());
            } finally {
                request.releaseConnection();
            }
        }
    }

    public byte[] getBuffer() {
        return this.buffer;
    }

    public int getBytesRead() {
        return this.bytesRead;
    }

}
