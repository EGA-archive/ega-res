package eu.elixir.ega.ebi.reencryptionmvc.service;

import eu.elixir.ega.ebi.reencryptionmvc.domain.Format;
import htsjdk.samtools.seekablestream.ISeekableStreamFactory;
import htsjdk.samtools.seekablestream.SeekableStream;
import htsjdk.samtools.seekablestream.cipher.GPGAsymmetricCipherStream;
import htsjdk.samtools.seekablestream.cipher.GPGSymmetricCipherStream;
import htsjdk.samtools.seekablestream.cipher.SeekableAESCipherStream;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.io.input.BoundedInputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import javax.annotation.PostConstruct;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Objects;

@Service
public class ReencryptionService {

    private ISeekableStreamFactory seekableStreamFactory;
    private KeyRepository keyRepository;

    @PostConstruct
    private void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public InputStream getInputStream(Format sourceFormat,
                                      String sourceKeyId,
                                      Format targetFormat,
                                      String targetKeyId,
                                      String fileLocation,
                                      long startCoordinate,
                                      long endCoordinate) throws IOException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidKeyException, InvalidKeySpecException, PGPException, DecoderException {
        SeekableStream seekableStream = seekableStreamFactory.getStreamFor(fileLocation);
        if (Format.AES.equals(sourceFormat)) {
            if (StringUtils.isEmpty(sourceKeyId)) {
                seekableStream.seek(0);
                InputStreamReader inputStreamReader = new InputStreamReader(seekableStream);
                BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
                String header = bufferedReader.readLine();
                sourceKeyId = header.split("\\|")[0];
            }
            seekableStream = new SeekableAESCipherStream(seekableStream, Objects.requireNonNull(keyRepository.getRSAKeyById(sourceKeyId)));
        }
        seekableStream.seek(startCoordinate);
        InputStream inputStream = endCoordinate != 0 && endCoordinate > startCoordinate ?
                new BoundedInputStream(seekableStream, endCoordinate - startCoordinate) :
                seekableStream;
        if (Format.GPG_SYMMETRIC.equals(targetFormat)) {
            inputStream = new GPGSymmetricCipherStream(inputStream, Objects.requireNonNull(targetKeyId), StringUtils.getFilename(fileLocation));
        } else if (Format.GPG_ASYMMETRIC.equals(targetFormat)) {
            inputStream = new GPGAsymmetricCipherStream(inputStream, Objects.requireNonNull(keyRepository.getPGPPublicKeyById(targetKeyId)), StringUtils.getFilename(fileLocation));
        }
        return inputStream;
    }

    @Autowired
    public void setSeekableStreamFactory(ISeekableStreamFactory seekableStreamFactory) {
        this.seekableStreamFactory = seekableStreamFactory;
    }

    @Autowired
    public void setKeyRepository(KeyRepository keyRepository) {
        this.keyRepository = keyRepository;
    }

}
