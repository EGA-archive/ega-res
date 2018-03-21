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

import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;

import java.nio.file.Path;
import java.nio.file.Paths;

import javax.servlet.http.HttpServletResponse;

import org.apache.http.impl.client.HttpClientBuilder;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import eu.elixir.ega.ebi.reencryptionmvc.dto.MyAwsConfig;
import eu.elixir.ega.ebi.reencryptionmvc.service.KeyService;
import eu.elixir.ega.ebi.reencryptionmvc.util.validation.EgaByteStreams;
import htsjdk.samtools.seekablestream.SeekablePathStream;
import htsjdk.samtools.seekablestream.cipher.ebi.RemoteSeekableCipherStream;

/**
 * Test class for {@link RandomAccessResServiceImpl}.
 * 
 * @author amohan
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({ RandomAccessResServiceImpl.class, HttpClientBuilder.class, Paths.class, EgaByteStreams.class })
public class RandomAccessResServiceImplTest {

    @InjectMocks
    private RandomAccessResServiceImpl randomAccessResServiceImpl;

    @Mock
    private KeyService keyService;

    @Mock
    private MyAwsConfig myAwsConfig;

    @Before
    public void initMocks() {
        MockitoAnnotations.initMocks(this);
    }

    /**
     * Test class for
     * {@link RandomAccessResServiceImpl#transfer(String, String, String, String, String, String, long, long, long, String, String, HttpServletRequest, HttpServletResponse)}.
     * Verify code is executing without errors.
     */
    @Test
    public void testTransfer() {

        try {
            setupMock();
            randomAccessResServiceImpl.transfer("aes256", "sourceKey", "plain", "destinationKey", "destinationIV",
                    "/EGAZ0000125/analysis/ALL.chr22.phase3_shapeit2_mvncall_integrated_v5a.20130502.genotypes.vcf.gz.cip",
                    0, 0, 37, "httpAuth", "id", new MockHttpServletRequest(), new MockHttpServletResponse());

        } catch (Exception e) {
            fail("Should not have thrown an exception");
        }

    }

    /**
     * Method to Setup mock.
     * 
     * @throws Exception
     */
    private void setupMock() throws Exception {
        final String[] keyPaths = { "keyPath" };

        final Paths pathsMock = mock(Paths.class);
        final Path pathMock = mock(Path.class);
        final SeekablePathStream seekablePathStream = mock(SeekablePathStream.class);
        final RemoteSeekableCipherStream remoteSeekableCipherStream = mock(RemoteSeekableCipherStream.class);

        mockStatic(HttpClientBuilder.class);
        mockStatic(Paths.class);
        mockStatic(EgaByteStreams.class);
        whenNew(Paths.class).withAnyArguments().thenReturn(pathsMock);
        whenNew(SeekablePathStream.class).withAnyArguments().thenReturn(seekablePathStream);
        whenNew(RemoteSeekableCipherStream.class).withAnyArguments().thenReturn(remoteSeekableCipherStream);
        when(Paths.get(any())).thenReturn(pathMock);
        when(keyService.getKeyPath(any(String.class))).thenReturn(keyPaths);
        when(keyService.getKeyPath(any(String.class))).thenReturn(keyPaths);

    }

}
