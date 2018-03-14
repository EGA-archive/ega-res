/*
 * Copyright 2018 ELIXIR EGA
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

import com.google.common.io.ByteStreams;
import eu.elixir.ega.ebi.reencryptionmvc.domain.Format;
import eu.elixir.ega.ebi.reencryptionmvc.service.KeyService;
import eu.elixir.ega.ebi.reencryptionmvc.service.ResService;
import htsjdk.samtools.seekablestream.ISeekableStreamFactory;
import htsjdk.samtools.seekablestream.SeekableStream;
import htsjdk.samtools.seekablestream.cipher.GPGAsymmetricCipherStream;
import htsjdk.samtools.seekablestream.cipher.GPGSymmetricCipherStream;
import htsjdk.samtools.seekablestream.cipher.SeekableAESCipherStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.PostConstruct;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.io.input.BoundedInputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

/**
 *
 * @author asenf
 */
@Service
@Profile("LocalEGA")
@EnableDiscoveryClient
public class LocalEgaServiceImpl implements ResService {

    @Autowired
    private ISeekableStreamFactory seekableStreamFactory;

    @Autowired
    private KeyService keyService;
    
    // This should be in DataEdge
    //private static final String CONTENT_DISPOSITION_PREFIX = "attachment; filename=";
    
    @PostConstruct
    private void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Override
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

        InputStream inputStream = null;
        OutputStream outputStream = null;
        try {
            outputStream = response.getOutputStream();
            
            inputStream = getInputStream(Format.valueOf(sourceFormat.toUpperCase()),
                    sourceKey,
                    Format.valueOf(destinationFormat.toUpperCase()),
                    destinationKey,
                    fileLocation,
                    startCoordinate,
                    endCoordinate);
        } catch (IOException | NoSuchPaddingException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException | NoSuchProviderException | InvalidKeyException | InvalidKeySpecException | PGPException | DecoderException ex) {
            Logger.getLogger(LocalEgaServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
        }
                
        response.setStatus(200);
        response.addHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_OCTET_STREAM_VALUE);
        // This should be in DataEdge!
        //response.addHeader(HttpHeaders.CONTENT_DISPOSITION, CONTENT_DISPOSITION_PREFIX + StringUtils.getFilename(fileLocation));

        try {
            // Copy
            long bytes = ByteStreams.copy(inputStream, outputStream);
            
        } catch (IOException ex) {
            Logger.getLogger(LocalEgaServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                outputStream.close();
                inputStream.close();
            } catch (IOException ex) {}
        }
    }

    /* 
     * Recommendation: Split decrypting and encrypting into separate input and output streams
     */
    public InputStream getInputStream(Format sourceFormat,
                                      String sourceKeyId,
                                      Format targetFormat,
                                      String targetKeyId,
                                      String fileLocation,
                                      long startCoordinate,
                                      long endCoordinate) throws IOException, 
                                                                 NoSuchPaddingException, 
                                                                 InvalidAlgorithmParameterException, 
                                                                 NoSuchAlgorithmException, 
                                                                 IllegalBlockSizeException, 
                                                                 BadPaddingException, 
                                                                 NoSuchProviderException, 
                                                                 InvalidKeyException, 
                                                                 InvalidKeySpecException, 
                                                                 PGPException, 
                                                                 DecoderException {

        SeekableStream seekableStream = seekableStreamFactory.getStreamFor(fileLocation);
        if (Format.AES.equals(sourceFormat)) {
            if (StringUtils.isEmpty(sourceKeyId)) {
                seekableStream.seek(0);
                InputStreamReader inputStreamReader = new InputStreamReader(seekableStream);
                BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
                String header = bufferedReader.readLine();
                sourceKeyId = header.split("\\|")[0];
            }
            seekableStream = new SeekableAESCipherStream(seekableStream, Objects.requireNonNull(keyService.getRSAKeyById(sourceKeyId)));
        }
        seekableStream.seek(startCoordinate);
        InputStream inputStream = endCoordinate != 0 && endCoordinate > startCoordinate ?
                new BoundedInputStream(seekableStream, endCoordinate - startCoordinate) :
                seekableStream;
        if (Format.GPG_SYMMETRIC.equals(targetFormat)) {
            inputStream = new GPGSymmetricCipherStream(inputStream, Objects.requireNonNull(targetKeyId), StringUtils.getFilename(fileLocation));
        } else if (Format.GPG_ASYMMETRIC.equals(targetFormat)) {
            inputStream = new GPGAsymmetricCipherStream(inputStream, Objects.requireNonNull(keyService.getPGPPublicKeyById(targetKeyId)), StringUtils.getFilename(fileLocation));
        }
        return inputStream;
    }
    
}
