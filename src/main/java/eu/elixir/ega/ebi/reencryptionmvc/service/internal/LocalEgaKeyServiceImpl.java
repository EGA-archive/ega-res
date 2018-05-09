package eu.elixir.ega.ebi.reencryptionmvc.service.internal;

import com.google.gson.Gson;
import eu.elixir.ega.ebi.reencryptionmvc.service.KeyService;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Iterator;

@Service
@Profile("LocalEGA")
@EnableDiscoveryClient
public class LocalEgaKeyServiceImpl implements KeyService {

    private String keyServiceURL;
    private String cegaURL;
    private RestTemplate restTemplate;

    @Override
    public byte[] getRSAKeyById(String id) throws IOException, DecoderException {
        // TODO: bring that back after LocalEGA key server becomes able to register itself against Eureka
        // ResponseEntity<Resource> responseEntity =
        //        restTemplate.getForEntity(keyServiceURL + "/temp/rsa/" + id, Resource.class);

        String rawKey =  IOUtils.toString(new URL(keyServiceURL + "/temp/rsa/" + id).openStream(), Charset.defaultCharset());
        System.out.println("DEBUG getRSAKey: rawKey=" + rawKey);
        String privateKey = String.valueOf(rawKey);
        byte[] privateKeyBytes = Hex.decodeHex(privateKey.toCharArray());
        try (PemReader pemReader = new PemReader(new InputStreamReader(new ByteArrayInputStream(privateKeyBytes)))) {
            return pemReader.readPemObject().getContent();
        }
    }

    // ID = username, e.g. "john" or "jane" (LocalEGA test users available out of the box in bootstrap-installation)
    @Override
    public PGPPublicKey getPGPPublicKeyById(String id) throws IOException, PGPException {
        // TODO: bring that back after LocalEGA key server becomes able to register itself against Eureka
        // ResponseEntity<Resource> responseEntity =
        //        restTemplate.getForEntity(keyServiceURL + "/pgp/" + id, Resource.class);

        InputStream in = PGPUtil.getDecoderStream(new URL(cegaURL + "/pgp/" + id).openStream());
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

    @Value("${localega.keyserver.url:http://localhost:8443}")
    public void setKeyServiceURL(String keyServiceURL) {
        this.keyServiceURL = keyServiceURL;
    }

    @Value("${localega.cega.url:http://localhost:9100}")
    public void setCegaURL(String cegaURL) {
        this.cegaURL = cegaURL;
    }

    @Autowired
    public void setRestTemplate(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }


    // TODO -- Implement The Abstract Functions

    @Override
    public String getFileKey(String fileId) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public String[] getKeyPath(String key) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public String[] getFormats() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

}
