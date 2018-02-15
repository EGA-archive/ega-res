/*
 * Copyright 2017 ELIXIR EBI
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
import eu.elixir.ega.ebi.reencryptionmvc.dto.MyAwsConfig;
import eu.elixir.ega.ebi.reencryptionmvc.service.KeyService;
import htsjdk.samtools.seekablestream.*;
import htsjdk.samtools.seekablestream.cipher.ebi.GPGStream;
import htsjdk.samtools.seekablestream.cipher.ebi.RemoteSeekableCipherStream;
import htsjdk.samtools.seekablestream.cipher.ebi.SeekableCipherStream;
import org.apache.http.client.HttpClient;
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

import java.io.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Iterator;

/**
 * @author asenf
 */
public class ObjectLoaderGPG implements Runnable {

    private byte[] buffer;
    private int bytesRead;

    private SeekableStream sIn;

    private final int BUFFER_SIZE;
    private final String id;
    private long startCoordinate, endCoordinate;

    private HttpClient httpclient;
    private Cache<String, CachePage> object;   // Global Cache
    private int cachePage;

    private final MyAwsConfig myAwsConfig;
    private final KeyService keyService;

    private long fileSize;

    /**
     * Bouncy Castle code for Public Key encrypted Files
     */
    private static final KeyFingerPrintCalculator fingerPrintCalculater = new BcKeyFingerprintCalculator();
    private static final BcPGPDigestCalculatorProvider calc = new BcPGPDigestCalculatorProvider();

    /**
     * Cache unencrypted Data in Memory
     *
     * @param bufSize
     * @param myCache
     * @param id
     * @param startCoordinate
     * @param endCoordinate
     * @param myAwsConfig
     * @param keyService
     */
    public ObjectLoaderGPG(SeekableStream sIn, int bufSize,
                           Cache<String, CachePage> myCache,
                           String id, long startCoordinate, long endCoordinate,
                           MyAwsConfig myAwsConfig, KeyService keyService,
                           long fileSize) {

        this.sIn = sIn;

        // Buffer Size - Customize
        long buf_endCoordinate = (endCoordinate > fileSize ? fileSize : endCoordinate);
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

        this.fileSize = fileSize;
    }

    @Override
    public void run() {
        String key = this.id + "_" + this.cachePage; // Page Key
        if (this.object.containsKey(key)) return;

        synchronized (this) {
            try {
                // Read response from HTTP call, count bytes read (encrypted Data)
                CountingInputStream cIn = new CountingInputStream(this.sIn);
                DataInputStream dis = new DataInputStream(cIn);
                dis.readFully(buffer);
                this.bytesRead = (int) cIn.getCount(); // Cache Page will be in Integer range

                this.object.put(key, new CachePage(buffer));
            } catch (IOException | UnsupportedOperationException th) {
                System.out.println("HTTP GET ERROR " + th.toString());
            } catch (Exception ex) {
                System.out.println("HTTP GET ERROR " + ex.toString());
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
                fileIn = httpAuth == null ? new SeekableHTTPStream(url) : new SeekableBasicAuthHTTPStream(url, httpAuth);
            } else if (fileLocation.toLowerCase().startsWith("s3")) { // S3
                String awsPath = fileLocation.substring(23); // Strip "S3://"
                String bucket = fileLocation.substring(5, 20);
                AWSCredentials credentials = new BasicAWSCredentials(myAwsConfig.getAwsAccessKeyId(), myAwsConfig.getAwsSecretAccessKey());
                AmazonS3 s3 = new AmazonS3Client(credentials);
                //S3Object object = s3.getObject(bucket, awsPath);
                //fileIn = new FakeSeekableStream(object.getObjectContent()); // ??                
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
                //plainIn = new SeekableCipherStream(fileIn, sourceKey.toCharArray(), BUFFER_SIZE, 256);
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

}
