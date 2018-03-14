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
import org.springframework.web.client.RestTemplate;

import java.io.*;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Iterator;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

@Service
@Profile("LocalEGA")
@EnableDiscoveryClient
public class LocalEgaKeyServiceImpl implements KeyService {

    private String keyServiceURL;
    private RestTemplate restTemplate;

    @Override
    public byte[] getRSAKeyById(String id) throws IOException, DecoderException {
        // TODO: bring that back after LocalEGA key server becomes able to register itself against Eureka
        // ResponseEntity<Resource> responseEntity =
        //        restTemplate.getForEntity(keyServiceURL + "/retrieve/rsa/rsa.key." + id, Resource.class);

        HashMap response = new Gson().fromJson(IOUtils.toString(new URL(keyServiceURL + "/retrieve/rsa/rsa.key." + id).openStream(), Charset.defaultCharset()), HashMap.class);
        String privateKey = String.valueOf(response.get("public")); // type here: will be replaced to "private"
        byte[] privateKeyBytes = Hex.decodeHex(privateKey.toCharArray());
        try (PemReader pemReader = new PemReader(new InputStreamReader(new ByteArrayInputStream(privateKeyBytes)))) {
            return pemReader.readPemObject().getContent();
        }
    }

    @Override
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

    @Value("${localega.keyserver.url:http://localhost:8443}")
    public void setKeyServiceURL(String keyServiceURL) {
        this.keyServiceURL = keyServiceURL;
    }

    @Autowired
    public void setRestTemplate(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    
    // TODO -- Implement The Abstract Functiopns
    
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
