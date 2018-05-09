/*
 * Copyright 2016 ELIXIR EBI
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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.when;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

/**
 * Test class for {@link KeyServiceImpl}.
 * 
 * @author amohan
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest(KeyServiceImpl.class)
public class KeyServiceImplTest {

    private final String SERVICE_URL = "http://KEYSERVICE";

    @InjectMocks
    private KeyServiceImpl keyServiceImpl;

    @Mock
    RestTemplate restTemplate;

    @Before
    public void initMocks() {
        MockitoAnnotations.initMocks(this);
    }

    /**
     * Test class for {@link KeyServiceImpl#getFileKey(String)}. Verify the output
     * key.
     */
    @Test
    public void testGetFileKey() {
        final ResponseEntity<String> mockResponseEntity = mock(ResponseEntity.class);
        final String keyMock = "body Output";
        when(restTemplate.getForEntity(SERVICE_URL + "/keys/filekeys/{file_id}", String.class, "fileId"))
                .thenReturn(mockResponseEntity);
        when(mockResponseEntity.getBody()).thenReturn(keyMock);

        final String key = keyServiceImpl.getFileKey("fileId");

        assertThat(key, equalTo(keyMock));
    }

    /**
     * Test class for {@link KeyServiceImpl#getFormats()}. Verify the output
     * formats.
     */
    @Test
    public void testGetFormats() {
        final ResponseEntity<String[]> mockResponseEntity = mock(ResponseEntity.class);
        final String[] formatsMock = { "symmetricgpg", "aes256" };
        when(restTemplate.getForEntity(SERVICE_URL + "/keys/formats", String[].class)).thenReturn(mockResponseEntity);
        when(mockResponseEntity.getBody()).thenReturn(formatsMock);

        final String[] format = keyServiceImpl.getFormats();

        assertThat(format, equalTo(formatsMock));
    }

    /**
     * Test class for {@link KeyServiceImpl#getKeyPath(String)}. Verify the output
     * path.
     */
    @Test
    public void testGetKeyPath() {
        final ResponseEntity<String[]> mockResponseEntity = mock(ResponseEntity.class);
        final String[] keyPathsMock = { "path1", "path2" };
        when(restTemplate.getForEntity(SERVICE_URL + "/keys/paths/{key}", String[].class, "key"))
                .thenReturn(mockResponseEntity);
        when(mockResponseEntity.getBody()).thenReturn(keyPathsMock);

        final String[] paths = keyServiceImpl.getKeyPath("key");

        assertThat(paths, equalTo(keyPathsMock));
    }

    /**
     * Test class for {@link KeyServiceImpl#getRSAKeyById(String)}. Expected
     * exception as operation Not supported yet.
     */
    @Test(expected = UnsupportedOperationException.class)
    public void testGetRSAKeyById() {
        keyServiceImpl.getRSAKeyById("keyId");
    }

    /**
     * Test class for {@link KeyServiceImpl#getPGPPublicKeyById(String)}. Expected
     * exception as operation Not supported yet.
     */
    @Test(expected = UnsupportedOperationException.class)
    public void testGetPGPPublicKeyById() {
        keyServiceImpl.getPGPPublicKeyById("keyId");
    }
}
