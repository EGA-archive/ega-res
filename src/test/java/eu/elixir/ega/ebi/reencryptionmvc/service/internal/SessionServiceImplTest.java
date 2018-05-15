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
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.when;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.test.context.junit4.SpringRunner;

import eu.elixir.ega.ebi.reencryptionmvc.domain.entity.Transfer;
import eu.elixir.ega.ebi.reencryptionmvc.domain.repository.TransferRepository;

/**
 * Test class for {@link SessionServiceImpl}.
 * 
 * @author anand
 */
@RunWith(SpringRunner.class)
public class SessionServiceImplTest {

    @Autowired
    private SessionServiceImpl SessionServiceImpl;
    
    @MockBean
    private TransferRepository transferRepository;
    
    @Before
    public void setup() {
        when(transferRepository.findOne(anyString())).thenReturn(getTransfer());
    }
    
    /**
     * Test class for {@link SessionServiceImpl#getSessionStats()}. Verify uuid
     * retrieved from db mock call.
     */
    @Test
    public void testGetSessionStats() {
        assertThat(SessionServiceImpl.getSessionStats("session_uuid").getUuid(), equalTo(getTransfer().getUuid()));
    }
    
    private Transfer getTransfer() {
        final Transfer transfer = new Transfer();
        transfer.setUuid("uuid");
        return transfer;
    }
    
    @TestConfiguration
    static class SessionServiceImplTestContextConfiguration {
        @Bean
        public SessionServiceImpl sessionService() {
            return new SessionServiceImpl();
        }
    }
}
