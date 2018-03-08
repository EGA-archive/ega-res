package eu.elixir.ega.ebi.reencryptionmvc.service;

import eu.elixir.ega.ebi.reencryptionmvc.domain.Format;
import htsjdk.samtools.seekablestream.ISeekableStreamFactory;
import htsjdk.samtools.seekablestream.SeekableStream;
import htsjdk.samtools.seekablestream.cipher.GPGCipherStream;
import htsjdk.samtools.seekablestream.cipher.SeekableAESCipherStream;
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
import java.io.IOException;
import java.io.InputStream;
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
                                      long endCoordinate) throws IOException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidKeyException, InvalidKeySpecException, PGPException {
        SeekableStream seekableStream = seekableStreamFactory.getStreamFor(fileLocation);
        if (Format.AES.equals(sourceFormat)) {
            seekableStream = new SeekableAESCipherStream(seekableStream, Objects.requireNonNull(keyRepository.getRSAKeyById(sourceKeyId)));
        }
        seekableStream.seek(startCoordinate);
        InputStream inputStream = endCoordinate != 0 && endCoordinate > startCoordinate ?
                new BoundedInputStream(seekableStream, endCoordinate - startCoordinate) :
                seekableStream;
        if (Format.GPG.equals(targetFormat)) {
            inputStream = new GPGCipherStream(inputStream, Objects.requireNonNull(keyRepository.getPGPPublicKeyById(targetKeyId)), StringUtils.getFilename(fileLocation));
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
