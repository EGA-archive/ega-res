package eu.elixir.ega.ebi.reencryptionmvc.service;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.stereotype.Repository;

import java.io.*;
import java.util.Iterator;

@Repository
public class KeyRepository {

    public byte[] getRSAKeyById(String id) throws IOException {
        // TODO: temporary implementation - treat "id" as file path
        try (PemReader pemReader = new PemReader(new InputStreamReader(new FileInputStream(id)))) {
            return pemReader.readPemObject().getContent();
        }
    }

    public PGPPublicKey getPGPPublicKeyById(String id) throws IOException, PGPException {
        // TODO: temporary implementation - treat "id" as file path
        InputStream in = new FileInputStream(new File(id));
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
