/*
 * Copyright 2016 ELIXIR EGA
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
package eu.elixir.ega.ebi.reencryptionmvc.service.internal;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.google.common.io.ByteStreams;
import eu.elixir.ega.ebi.reencryptionmvc.config.GeneralStreamingException;
import eu.elixir.ega.ebi.reencryptionmvc.domain.entity.Transfer;
import eu.elixir.ega.ebi.reencryptionmvc.dto.MyAwsConfig;
import eu.elixir.ega.ebi.reencryptionmvc.service.KeyService;
import eu.elixir.ega.ebi.reencryptionmvc.service.ResService;
import eu.elixir.ega.ebi.reencryptionmvc.util.validation.EgaByteStreams;
import htsjdk.samtools.seekablestream.FakeSeekableStream;
import htsjdk.samtools.seekablestream.SeekableHTTPStream;
import htsjdk.samtools.seekablestream.SeekablePathStream;
import htsjdk.samtools.seekablestream.SeekableStream;
import htsjdk.samtools.seekablestream.cipher.ebi.*;
import htsjdk.samtools.seekablestream.ebi.AsyncBufferedSeekableHTTPStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Calendar;
import java.util.Iterator;
import java.util.UUID;


/**
 * @author asenf
 */
@Service
@Profile("test")
@EnableDiscoveryClient
public class RandomAccessResServiceImpl implements ResService {

    @Autowired
    private KeyService keyService;

    //@Autowired
    //private TransferRepository transferRepository;

    @Autowired
    private MyAwsConfig myAwsConfig;

    /**
     * Size of a byte buffer to read/write file (for Random Stream)
     */
    //private static final int BUFFER_SIZE = 4096;
    private static final int BUFFER_SIZE = 512 * 1024;

    /**
     * Bouncy Castle code for Public Key encrypted Files
     */
    private static final KeyFingerPrintCalculator fingerPrintCalculater = new BcKeyFingerprintCalculator();
    private static final BcPGPDigestCalculatorProvider calc = new BcPGPDigestCalculatorProvider();

    /*
     * Perform Data Transfer Requested by File Controller
     */

    @Override
//    @HystrixCommand
    public void transfer(String sourceFormat,
                         String sourceKey,
                         String destinationFormat,
                         String destinationKey,
                         String destinationIV,
                         String fileLocation,
                         long startCoordinate,
                         long endCoordinate,
                         long fileSize,
                         String httpAuth,
                         String id,
                         HttpServletRequest request,
                         HttpServletResponse response) {

        // Streams and Digests for this data transfer
        MessageDigest plainDigest = null;
        DigestInputStream plainDigestIn = null;
        MessageDigest encryptedDigest = null;
        DigestOutputStream encryptedDigestOut = null;
        OutputStream eOut = null;

        // Build Header - Specify UUID (Allow later stats query regarding this transfer)
        UUID dlIdentifier = UUID.randomUUID();
        String headerValue = dlIdentifier.toString();

        long bytes = 0; // Obtained in unencrypted step - counts "true" file size
        try {
            // Build Plain (Decrypting) Input Stream from Source, seek and wrap it in MD5 stream
            SeekableStream cIn;
            cIn = getSource(sourceFormat,
                    sourceKey,
                    fileLocation,
                    httpAuth,
                    fileSize);
            if (cIn == null) {
                throw new GeneralStreamingException("Input Stream (Decryption Stage) Null", 1);
            }
            // Handle start coordinate - seek input stream to specified position
            if (startCoordinate > 0) {
                cIn.seek(startCoordinate);
            }
            // Handle end coordinate - either read entire stream, or stop at specified coordinate
            InputStream in;
            if (endCoordinate > startCoordinate) {
                long delta = endCoordinate - startCoordinate;
                in = ByteStreams.limit(cIn, delta);
            } else {
                in = cIn;
            }
            // Wrap prepared input stream in MD5 Stream
            plainDigest = MessageDigest.getInstance("MD5");
            plainDigestIn = new DigestInputStream(in, plainDigest);

            // Set headers for the response
            String headerKey = "X-Session";
            response.setHeader(headerKey, headerValue);

            // get MIME type of the file (actually, it's always this for now)
            String mimeType = "application/octet-stream";
            System.out.println("MIME type: " + mimeType);

            // set content attributes for the response
            response.setContentType(mimeType);

            // Get Send Stream - http Response, wrap in Digest Stream
            OutputStream outStream = response.getOutputStream();
            encryptedDigest = MessageDigest.getInstance("MD5");
            encryptedDigestOut = new DigestOutputStream(outStream, encryptedDigest);

            // Generate Encrypting OutputStream
            eOut = getTarget(encryptedDigestOut,
                    destinationFormat,
                    destinationKey);
            if (eOut == null) {
                throw new GeneralStreamingException("Output Stream (ReEncryption Stage) Null", 2);
            }

            // Experimental: Add Multiple Output objects and perform Validation in one of them
//            CircularByteBuffer cbb = new CircularByteBuffer(); // Buffer to turn Output into Input Stream
//            MyTeeOutputStream mOut = new MyTeeOutputStream(eOut, cbb); // Multiplex Output Streams
//            EmptyValidation eVal = new EmptyValidation(cbb.getInputStream()); 
//            Thread eValThread = new Thread(eVal);
//            eValThread.start(); // Validation Thread

            // Copy the specified contents - decrypting through input, encrypting through output
            InputStream in_ = null;
            in_ = ByteStreams.limit(plainDigestIn, fileSize);
            bytes = EgaByteStreams.copy(in_, eOut, 65535); // mOut <-- for validation
            //bytes = ByteStreams.copy(plainDigestIn, eOut); // mOut <-- for validation
            System.out.println("Copied Bytes: " + bytes);

//            cbb.getOutputStream().close(); // Effectively end Validation Thread
        } catch (IOException | NoSuchAlgorithmException ex) {
            throw new GeneralStreamingException(ex.toString(), 3);
        } catch (NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException ex) {
            throw new GeneralStreamingException(ex.toString(), 4);
        } finally {
            try {
                // Close all Streams in reverse order (theoretically only the first should be necessary)
                eOut.close();
                encryptedDigestOut.close();
                plainDigestIn.close();

                // Compute Digests
                byte[] plainDigest_ = plainDigest.digest();
                BigInteger bigIntPlain = new BigInteger(1, plainDigest_);
                String plainHashtext = bigIntPlain.toString(16);
                while (plainHashtext.length() < 32) {
                    plainHashtext = "0" + plainHashtext;
                }

                byte[] encryptedDigest_ = encryptedDigest.digest();
                BigInteger bigIntEncrypted = new BigInteger(1, encryptedDigest_);
                String encryptedHashtext = bigIntEncrypted.toString(16);
                while (encryptedHashtext.length() < 32) {
                    encryptedHashtext = "0" + encryptedHashtext;
                }

                // Store with UUID for later retrieval
                Transfer transfer = new Transfer(headerValue,
                        new java.sql.Timestamp(Calendar.getInstance().getTime().getTime()),
                        plainHashtext,
                        encryptedHashtext,
                        0,
                        bytes,
                        "RES");
                //Transfer save = transferRepository.save(transfer);

            } catch (Exception ex) {
                throw new GeneralStreamingException(ex.toString(), 5);
            }
        }
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
                plainIn = new SeekableCipherStream(fileIn, sourceKey.toCharArray(), BUFFER_SIZE, 256);
                //plainIn = new RemoteSeekableCipherStream(fileIn, sourceKey.toCharArray(), BUFFER_SIZE, 256);
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

    // Return ReEncrypted Output Stream for Target
//    @HystrixCommand
    private OutputStream getTarget(OutputStream outStream,
                                   String destinationFormat,
                                   String destinationKey) throws NoSuchAlgorithmException,
            NoSuchPaddingException,
            InvalidKeyException,
            InvalidAlgorithmParameterException,
            IOException {
        OutputStream out = null; // Return Stream - an Encrypted File

        if (destinationFormat.equalsIgnoreCase("plain")) {
            out = outStream; // No Encryption Necessary

        } else if (destinationFormat.equalsIgnoreCase("aes128")) {
            SecretKey secret = Glue.getInstance().getKey(destinationKey.toCharArray(), 128);
            byte[] random_iv = new byte[16];
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            random.nextBytes(random_iv);
            AlgorithmParameterSpec paramSpec = new IvParameterSpec(random_iv);
            outStream.write(random_iv);
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding"); // load a cipher AES / Segmented Integer Counter
            cipher.init(Cipher.ENCRYPT_MODE, secret, paramSpec);
            out = new CipherOutputStream(outStream, cipher);

        } else if (destinationFormat.equalsIgnoreCase("aes256")) {
            SecretKey secret = Glue.getInstance().getKey(destinationKey.toCharArray(), 256);
            byte[] random_iv = new byte[16];
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            random.nextBytes(random_iv);
            AlgorithmParameterSpec paramSpec = new IvParameterSpec(random_iv);
            outStream.write(random_iv);
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding"); // load a cipher AES / Segmented Integer Counter
            cipher.init(Cipher.ENCRYPT_MODE, secret, paramSpec);
            out = new CipherOutputStream(outStream, cipher);

        } else if (destinationFormat.toLowerCase().startsWith("publicgpg")) {
            PGPPublicKey gpgKey = getPublicGPGKey(destinationFormat);
            out = new GPGOutputStream(outStream, gpgKey); // Public Key GPG

        }

        return out;
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

    // *************************************************************************
    // ** Get Public Key fo Encryption
//    @HystrixCommand
    public PGPPublicKey getPublicGPGKey(String destinationFormat) throws IOException {
        PGPPublicKey pgKey = null;
        Security.addProvider(new BouncyCastleProvider());

        // Paths (file containing the key - no paswords for public GPG Keys)
        String[] vals = keyService.getKeyPath(destinationFormat);
        if (vals == null) {
            throw new GeneralStreamingException("Can't Read Destination Key: " + destinationFormat, 10);
        }
        String path = vals[0];
        InputStream in = new FileInputStream(path);

        // Two types of public GPG key files - pick the correct one! (through trial-and-error)
        boolean error = false;
        try {
            pgKey = readPublicKey(in); // key ring file (e.g. EBI key) -- TODO remove!
        } catch (IOException | PGPException ex) {
            in.reset();
            error = true;
        }
        if (pgKey == null || error) {
            try {
                pgKey = getEncryptionKey(getKeyring(in)); // exported key file (should be standard)
            } catch (IOException ex) {
                ;
            }
        }
        in.close();

        return pgKey;
    }

    // Getting a public GPG key from a keyring
//    @HystrixCommand
    private PGPPublicKey readPublicKey(InputStream in)
            throws IOException, PGPException {
        in = PGPUtil.getDecoderStream(in);

        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(in, fingerPrintCalculater);

        //
        // we just loop through the collection till we find a key suitable for encryption, in the real
        // world you would probably want to be a bit smarter about this.
        //
        PGPPublicKey key = null;

        //
        // iterate through the key rings.
        //
        Iterator rIt = pgpPub.getKeyRings();

        while (key == null && rIt.hasNext()) {
            PGPPublicKeyRing kRing = (PGPPublicKeyRing) rIt.next();
            Iterator kIt = kRing.getPublicKeys();

            while (key == null && kIt.hasNext()) {
                PGPPublicKey k = (PGPPublicKey) kIt.next();

                if (k.isEncryptionKey()) {
                    key = k;
                }
            }
        }

        if (key == null) {
            throw new IllegalArgumentException("Can't find encryption key in key ring.");
        }

        return key;
    }

    //    @HystrixCommand
    private static PGPPublicKeyRing getKeyring(InputStream keyBlockStream) throws IOException {
        // PGPUtil.getDecoderStream() will detect ASCII-armor automatically and decode it,
        // the PGPObject factory then knows how to read all the data in the encoded stream
        PGPObjectFactory factory = new PGPObjectFactory(PGPUtil.getDecoderStream(keyBlockStream), fingerPrintCalculater);

        // these files should really just have one object in them,
        // and that object should be a PGPPublicKeyRing.
        Object o = factory.nextObject();
        if (o instanceof PGPPublicKeyRing) {
            return (PGPPublicKeyRing) o;
        }
        throw new IllegalArgumentException("Input text does not contain a PGP Public Key");
    }

    // -------------------------------------------------------------------------
//    @HystrixCommand
    private static PGPPublicKey getEncryptionKey(PGPPublicKeyRing keyRing) {
        if (keyRing == null)
            return null;

        // iterate over the keys on the ring, look for one
        // which is suitable for encryption.
        Iterator keys = keyRing.getPublicKeys();
        PGPPublicKey key;
        while (keys.hasNext()) {
            key = (PGPPublicKey) keys.next();
            if (key.isEncryptionKey()) {
                return key;
            }
        }
        return null;
    }

}
