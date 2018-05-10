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

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.google.common.io.CountingInputStream;
import eu.elixir.ega.ebi.reencryptionmvc.dto.CachePage;
import eu.elixir.ega.ebi.reencryptionmvc.dto.EgaAESFileHeader;
import eu.elixir.ega.ebi.reencryptionmvc.dto.MyAwsConfig;
import eu.elixir.ega.ebi.reencryptionmvc.service.KeyService;
import htsjdk.samtools.seekablestream.FakeSeekableStream;
import htsjdk.samtools.seekablestream.SeekableHTTPStream;
import htsjdk.samtools.seekablestream.SeekablePathStream;
import htsjdk.samtools.seekablestream.SeekableStream;
import htsjdk.samtools.seekablestream.cipher.ebi.GPGStream;
import htsjdk.samtools.seekablestream.cipher.ebi.Glue;
import htsjdk.samtools.seekablestream.cipher.ebi.RemoteSeekableCipherStream;
import htsjdk.samtools.seekablestream.cipher.ebi.SeekableCipherStream;
import htsjdk.samtools.seekablestream.ebi.AsyncBufferedSeekableHTTPStream;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClientBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.cache2k.Cache;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author asenf
 */
public class ObjectLoaderAES implements Runnable {

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
    private String sourceFormat;
    private String sourceKey;

    //private ConcurrentHashMap ledge;

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
     * @param sourceFormat
     * @param sourceKey
     */
    public ObjectLoaderAES(String url, String auth, int bufSize,
                           Cache<String, CachePage> myCache,
                           String id, long startCoordinate, long endCoordinate,
                           MyAwsConfig myAwsConfig, KeyService keyService,
                           EgaAESFileHeader header,
                           String sourceFormat, String sourceKey,
                           ConcurrentHashMap ledge) {
        this.url = url;

        URL url_ = null;
        try {
            url_ = new URL(url);
        } catch (MalformedURLException ex) {
        }
        if (url_ != null && url_.getUserInfo() != null) {
            //String encoding = new sun.misc.BASE64Encoder().encode(url_.getUserInfo().getBytes());
            //encoding = encoding.replaceAll("\n", "");
            String encoding = java.util.Base64.getEncoder().encodeToString(url_.getUserInfo().getBytes());
            this.auth = "Basic " + encoding;
        } else if (auth != null && auth.length() > 0) {
            //String encoding = new sun.misc.BASE64Encoder().encode(auth.getBytes());
            //encoding = encoding.replaceAll("\n", "");
            String encoding = java.util.Base64.getEncoder().encodeToString(auth.getBytes());
            this.auth = "Basic " + encoding;
        } else {
            this.auth = null;
        }

        // Buffer Size - Customize
        long buf_endCoordinate = ((endCoordinate + 16) > header.getSize() ? header.getSize() : (endCoordinate + 16));
        long buf_startCoordinate = startCoordinate + 16;
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
        this.sourceFormat = sourceFormat;
        this.sourceKey = sourceKey;

        //this.ledge = ledge;
    }

    @Override
    public void run() {
        // Sanity Check
        if (object == null) return; // Should throw error
        String key = this.id + "_" + this.cachePage; // Page Key
        if (object.containsKey(key)) {
            return;
        } // If page is already loaded; nothing to do
//System.out.println("Gettign Cache Page " + key);

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
                if (object.containsKey(key)) {
                    return;
                } // If page is already loaded; nothing to do
                HttpResponse response = this.httpclient.execute(request);
                if (object.containsKey(key)) {
                    return;
                } // If page is already loaded; nothing to do

                // Read response from HTTP call, count bytes read (encrypted Data)
                CountingInputStream cIn = new CountingInputStream(response.getEntity().getContent());
                DataInputStream dis = new DataInputStream(cIn);
                if (object.containsKey(key)) {
                    return;
                } // If page is already loaded; nothing to do
                dis.readFully(buffer);
                this.bytesRead = (int) cIn.getCount(); // Cache Page will be in Integer range

                // Decrypt, store plain in cache
                byte[] newIV = new byte[16]; // IV always 16 bytes long
                System.arraycopy(header.getIV(), 0, newIV, 0, 16); // preserved start value
                if (this.startCoordinate > 0) byte_increment_fast(newIV, this.startCoordinate);
                if (object.containsKey(key)) {
                    return;
                } // If page is already loaded; nothing to do
                byte[] decrypted = decrypt(buffer, sourceKey, newIV);

                this.object.put(key, new CachePage(decrypted));
                //this.ledge.remove(key);
            } catch (IOException | UnsupportedOperationException th) {
                System.out.println("HTTP GET ERROR " + th.toString());
            } catch (IllegalBlockSizeException ex) {
                System.out.println("HTTP GET ERROR " + ex.toString());
            } catch (BadPaddingException ex) {
                System.out.println("HTTP GET ERROR " + ex.toString());
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

    /*
     * Decryption Function
     */
    private byte[] decrypt(byte[] cipherText, String encryptionKey, byte[] IV) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        SecretKey key_ = Glue.getInstance().getKey(encryptionKey.toCharArray(), 256);
        cipher.init(Cipher.DECRYPT_MODE, key_, new IvParameterSpec(IV));
        return cipher.doFinal(cipherText);
    }

    /*
     * Archive Related Helper Functions -- AES
     */

    // Return Unencrypted Seekable Stream from Source
//    @HystrixCommand
    private SeekableStream getSource(String sourceFormat,
                                     String sourceKey,
                                     String fileLocation,
                                     String httpAuth,
                                     long fileSize) {

        SeekableStream fileIn = null; // Source of File
        SeekableStream plainIn = null; // Return Stream - a Decrypted File
        try {
            // Obtain Input Stream - from a File or an HTTP server; or an S3 Bucket
            if (fileLocation.toLowerCase().startsWith("http")) { // Access Cleversafe Need Basic Auth here!
                URL url = new URL(fileLocation);
                //fileIn = httpAuth==null?new SeekableHTTPStream(url):
                //                        new EgaSeekableHTTPStream(url, null, httpAuth, fileSize);
                /** start cache code **/
                fileIn = httpAuth == null ? new AsyncBufferedSeekableHTTPStream(url) :
                        new AsyncBufferedSeekableHTTPStream(url, null, httpAuth, fileSize);
                /** end cache code **/
            } else if (fileLocation.toLowerCase().startsWith("s3")) { // S3
                String awsPath = fileLocation.substring(23); // Strip "S3://"
                String bucket = fileLocation.substring(5, 20);
                AWSCredentials credentials = new BasicAWSCredentials(myAwsConfig.getAwsAccessKeyId(), myAwsConfig.getAwsSecretAccessKey());
                AmazonS3 s3 = new AmazonS3Client(credentials);
                //S3Object object = s3.getObject(bucket, awsPath);
                //fileIn = new EgaFakeSeekableStream(object.getObjectContent()); // ??                
                URL url = s3.getUrl(bucket, awsPath);
                fileIn = new SeekableHTTPStream(url);
            } else { // No Protocol -- Assume File Path
                fileLocation = "file://" + fileLocation;
                Path filePath = Paths.get(new URI(fileLocation));
                fileIn = new SeekablePathStream(filePath);
            }

            // Obtain Plain Input Stream
            if (sourceFormat.equalsIgnoreCase("plain")) {
                plainIn = fileIn; // No Decryption Necessary
            } else if (sourceFormat.equalsIgnoreCase("aes128")) {
                plainIn = new SeekableCipherStream(fileIn, sourceKey.toCharArray(), BUFFER_SIZE, 128);
            } else if (sourceFormat.equalsIgnoreCase("aes256")) {
                //plainIn = new EgaSeekableCipherStream(fileIn, sourceKey.toCharArray(), BUFFER_SIZE, 256);
                plainIn = new RemoteSeekableCipherStream(fileIn, sourceKey.toCharArray(), BUFFER_SIZE, 256);
            } else if (sourceFormat.equalsIgnoreCase("symmetricgpg")) {
                plainIn = getSymmetricGPGDecryptingInputStream(fileIn, sourceKey);
            } else if (sourceFormat.toLowerCase().startsWith("publicgpg")) {
                plainIn = getAsymmetricGPGDecryptingInputStream(fileIn, sourceKey, sourceFormat);
            }
        } catch (IOException | URISyntaxException ex) {
            System.out.println(" ** " + ex.toString());
        }

        return plainIn;
    }

    /*
     * Archive Related Helper Functions -- GPG
     */

    //    @HystrixCommand
    private SeekableStream getSymmetricGPGDecryptingInputStream(InputStream c_in, String sourceKey) {
        Security.addProvider(new BouncyCastleProvider());
        InputStream in = c_in;

        try {
            // Load key, if not provided. Details in config XML file
            if (sourceKey == null || sourceKey.length() == 0) {
                String[] keyPath = keyService.getKeyPath("SymmetricGPG");
                BufferedReader br = new BufferedReader(new FileReader(keyPath[0]));
                sourceKey = br.readLine();
                br.close();
            }

            in = GPGStream.getDecodingGPGInoutStream(in, sourceKey.toCharArray());

        } catch (IOException | PGPException | NoSuchProviderException ex) {
            System.out.println("GOPG Error " + ex.toString());
        }

        return new FakeSeekableStream(in);
    }

    //    @HystrixCommand
    private SeekableStream getAsymmetricGPGDecryptingInputStream(InputStream c_in, String sourceKey, String sourceFormat) {
        Security.addProvider(new BouncyCastleProvider());
        InputStream in = null;

        try {
            String[] keyPath = sourceFormat.equalsIgnoreCase("publicgpg_sanger") ?
                    keyService.getKeyPath("PrivateGPG_Sanger") :
                    keyService.getKeyPath("PrivateGPG");

            String key = keyPath[2]; // password for key file, not password itself
            if (key == null || key.length() == 0) {
                BufferedReader br = new BufferedReader(new FileReader(keyPath[1]));
                key = br.readLine();
                br.close();
            }

            InputStream keyIn = new BufferedInputStream(new FileInputStream(keyPath[0]));

            PGPObjectFactory pgpF = new PGPObjectFactory(c_in, fingerPrintCalculater);
            PGPEncryptedDataList enc;

            Object o = pgpF.nextObject();
            //
            // the first object might be a PGP marker packet.
            //
            if (o instanceof PGPEncryptedDataList) {
                enc = (PGPEncryptedDataList) o;
            } else {
                enc = (PGPEncryptedDataList) pgpF.nextObject();
            }

            //
            // find the secret key
            //
            Iterator<PGPPublicKeyEncryptedData> it = enc.getEncryptedDataObjects();
            PGPPrivateKey sKey = null;
            PGPPublicKeyEncryptedData pbe = null;
            PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
                    PGPUtil.getDecoderStream(keyIn), fingerPrintCalculater);

            while (sKey == null && it.hasNext()) {
                try {
                    pbe = it.next();

                    PGPSecretKey pgpSecKey = pgpSec.getSecretKey(pbe.getKeyID());
                    if (pgpSecKey == null) {
                        sKey = null;
                    } else {
                        PBESecretKeyDecryptor decryptor = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(key.toCharArray());
                        //sKey = pgpSecKey.extractPrivateKey(key.toCharArray(), "BC");
                        sKey = pgpSecKey.extractPrivateKey(decryptor);
                    }
                } catch (Throwable t) {
                    System.out.println("Error -- " + t.getLocalizedMessage());
                }
            }

            if (sKey == null) {
                throw new IllegalArgumentException("secret key for message not found.");
            }

            BcPublicKeyDataDecryptorFactory pkddf = new BcPublicKeyDataDecryptorFactory(sKey);
            //InputStream         clear = pbe.getDataStream(sKey, "BC");
            InputStream clear = pbe.getDataStream(pkddf);


            PGPObjectFactory plainFact = new PGPObjectFactory(clear, fingerPrintCalculater);

            Object message = plainFact.nextObject();

            if (message instanceof PGPCompressedData) {
                PGPCompressedData cData = (PGPCompressedData) message;
                PGPObjectFactory pgpFact = new PGPObjectFactory(cData.getDataStream(), fingerPrintCalculater);

                message = pgpFact.nextObject();
            }

            if (message instanceof PGPLiteralData) {
                PGPLiteralData ld = (PGPLiteralData) message;
                in = ld.getInputStream();
            }
        } catch (IOException | PGPException ex) {
            System.out.println(" *** " + ex.toString());
        }

        return new FakeSeekableStream(in);
    }

    private static void byte_increment_fast(byte[] data, long increment) {
        long countdown = increment / 16; // Count number of block updates

        ArrayList<Integer> digits_ = new ArrayList<>();
        int cnt = 0;
        long d = 256, cn = 0;
        while (countdown > cn && d > 0) {
            int l = (int) ((countdown % d) / (d / 256));
            digits_.add(l);
            cn += (l * (d / 256));
            d *= 256;
        }
        int size = digits_.size();
        int[] digits = new int[size];
        for (int i = 0; i < size; i++) {
            digits[size - 1 - i] = digits_.get(i); // intValue()
        }

        int cur_pos = data.length - 1, carryover = 0, delta = data.length - digits.length;

        for (int i = cur_pos; i >= delta; i--) { // Work on individual digits
            int digit = digits[i - delta] + carryover; // convert to integer
            int place = (int) (data[i] & 0xFF); // convert data[] to integer
            int new_place = digit + place;
            if (new_place >= 256) carryover = 1;
            else carryover = 0;
            data[i] = (byte) (new_place % 256);
        }

        // Deal with potential last carryovers
        cur_pos -= digits.length;
        while (carryover == 1 && cur_pos >= 0) {
            data[cur_pos]++;
            if (data[cur_pos] == 0) carryover = 1;
            else carryover = 0;
            cur_pos--;
        }
    }

}
