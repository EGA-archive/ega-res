package eu.elixir.ega.ebi.reencryptionmvc.service;

import eu.elixir.ega.ebi.reencryptionmvc.domain.Format;
import htsjdk.samtools.seekablestream.ISeekableStreamFactory;
import htsjdk.samtools.seekablestream.SeekableStream;
import htsjdk.samtools.seekablestream.cipher.GPGCipherStream;
import htsjdk.samtools.seekablestream.cipher.SeekableAESCipherStream;
import org.apache.commons.io.input.BoundedInputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import javax.annotation.PostConstruct;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Iterator;
import java.util.Objects;

@Service
public class ReencryptionService {

    private ISeekableStreamFactory seekableStreamFactory;

    @PostConstruct
    private void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public InputStream getInputStream(Format sourceFormat,
                                      String sourceKey,
                                      Format targetFormat,
                                      String targetKey,
                                      String fileLocation,
                                      long startCoordinate,
                                      long endCoordinate) throws IOException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidKeyException, InvalidKeySpecException, PGPException {
        SeekableStream seekableStream = seekableStreamFactory.getStreamFor(fileLocation);
        if (Format.AES.equals(sourceFormat)) {
            seekableStream = new SeekableAESCipherStream(seekableStream, Objects.requireNonNull(getAESPrivateKey(sourceKey)));
        }
        seekableStream.seek(startCoordinate);
        InputStream inputStream = endCoordinate != 0 && endCoordinate > startCoordinate ?
                new BoundedInputStream(seekableStream, endCoordinate - startCoordinate) :
                seekableStream;
        if (Format.GPG.equals(targetFormat)) {
            inputStream = new GPGCipherStream(inputStream, Objects.requireNonNull(getPGPPublicKey(targetKey)), StringUtils.getFilename(fileLocation));
        }
        return inputStream;
    }

    private byte[] getAESPrivateKey(String sourceKey) throws IOException {
        try (PemReader pemReader = new PemReader(new InputStreamReader(new FileInputStream(sourceKey)))) {
            return pemReader.readPemObject().getContent();
        }
    }

    private PGPPublicKey getPGPPublicKey(String targetKey) throws IOException, PGPException {
        InputStream in = new FileInputStream(new File(targetKey));
        in = PGPUtil.getDecoderStream(in);
        PGPPublicKeyRingCollection pgpPublicKeyRings = new PGPPublicKeyRingCollection(in, new BcKeyFingerprintCalculator());
        PGPPublicKey pgpPublicKey = null;
        Iterator keyRings = pgpPublicKeyRings.getKeyRings();
        while (pgpPublicKey == null && keyRings.hasNext()) {
            PGPPublicKeyRing kRing = (PGPPublicKeyRing) keyRings.next();
            Iterator publicKeys = kRing.getPublicKeys();
            while (publicKeys.hasNext()) {
                PGPPublicKey key = (PGPPublicKey) publicKeys.next();
                if (key.isEncryptionKey()) {
                    pgpPublicKey = key;
                    break;
                }
            }
        }
        if (pgpPublicKey == null) {
            throw new IllegalArgumentException("Can't find encryption key in key ring.");
        }
        return pgpPublicKey;
    }

    @Autowired
    public void setSeekableStreamFactory(ISeekableStreamFactory seekableStreamFactory) {
        this.seekableStreamFactory = seekableStreamFactory;
    }

}
