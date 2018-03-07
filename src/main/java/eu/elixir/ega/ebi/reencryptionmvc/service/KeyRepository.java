package eu.elixir.ega.ebi.reencryptionmvc.service;

import org.apache.commons.lang.NotImplementedException;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.stereotype.Repository;

import java.io.*;
import java.util.Iterator;

@Repository
public class KeyRepository {

    public byte[] getRSAKeyById(String id) {
        throw new NotImplementedException();
    }

    public PGPPublicKey getPGPPublicKeyById(String id) {
        throw new NotImplementedException();
    }

    public byte[] getRSAKey(String sourceKey) throws IOException {
        try (PemReader pemReader = new PemReader(new InputStreamReader(new FileInputStream(sourceKey)))) {
            return pemReader.readPemObject().getContent();
        }
    }

    public PGPPublicKey getPGPPublicKey(String targetKey) throws IOException, PGPException {
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

}
