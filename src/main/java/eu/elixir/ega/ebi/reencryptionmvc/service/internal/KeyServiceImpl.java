/*
 * Copyright 2017 ELIXIR EGA
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

import eu.elixir.ega.ebi.reencryptionmvc.service.KeyService;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

/**
 * @author asenf
 */
@Service
@Profile("!LocalEGA")
@EnableDiscoveryClient
public class KeyServiceImpl implements KeyService {

    private final String SERVICE_URL = "http://KEYSERVICE";

    @Autowired
    RestTemplate restTemplate;

    @Override
//    @HystrixCommand
    //@Retryable(maxAttempts = 4, backoff = @Backoff(delay = 5000))
    @Cacheable(cacheNames = "key")
    public String getFileKey(String fileId) {

        ResponseEntity<String> forEntity = restTemplate.getForEntity(SERVICE_URL + "/keys/filekeys/{file_id}", String.class, fileId);
        String body = forEntity.getBody();

        return body;
    }

    @Override
//    @HystrixCommand
    //@Retryable(maxAttempts = 4, backoff = @Backoff(delay = 5000))
    public String[] getFormats() {

        ResponseEntity<String[]> forEntity = restTemplate.getForEntity(SERVICE_URL + "/keys/formats", String[].class);
        String[] body = forEntity.getBody();

        return body;
    }

    @Override
//    @HystrixCommand
    //@Retryable(maxAttempts = 4, backoff = @Backoff(delay = 5000))
    public String[] getKeyPath(String key) {

        ResponseEntity<String[]> forEntity = restTemplate.getForEntity(SERVICE_URL + "/keys/paths/{key}", String[].class, key);
        String[] body = forEntity.getBody();

        return body;
    }

    // Local EGA Functionality - Not Required for Central EGA / EBI
    
    @Override
    public byte[] getRSAKeyById(String keyId) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public PGPPublicKey getPGPPublicKeyById(String keyId) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

}
