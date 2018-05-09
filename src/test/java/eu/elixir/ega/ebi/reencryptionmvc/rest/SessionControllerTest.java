/*
 * Copyright 2016 ELIXIR EGA
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
package eu.elixir.ega.ebi.reencryptionmvc.rest;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpStatus.NOT_FOUND;
import static org.springframework.http.HttpStatus.OK;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import eu.elixir.ega.ebi.reencryptionmvc.domain.entity.Transfer;
import eu.elixir.ega.ebi.reencryptionmvc.service.SessionService;

/**
 * Test class for {@link SessionController}.
 * 
 * @author amohan
 */
@RunWith(SpringRunner.class)
@WebMvcTest(SessionController.class)
@TestPropertySource(locations = "classpath:application-test.properties")
public class SessionControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private SessionService sessionService;

    /**
     * Test {@link SessionController#get(String)}. Verify the api call returns
     * status is OK.
     * 
     * @throws Exception
     */
    @Test
    public void testGet() throws Exception {
        when(sessionService.getSessionStats(any(String.class))).thenReturn(new Transfer());

        final MockHttpServletResponse response = mockMvc.perform(get("/session/sessionid")).andReturn().getResponse();
        assertThat(response.getStatus(), equalTo(OK.value()));
    }

    /**
     * Test {@link SessionController#get(String)}. Verify the api call returns
     * status as NOT FOUND.
     * 
     * @throws Exception
     */
    @Test
    public void testGet_TransferNull() throws Exception {
        when(sessionService.getSessionStats(any(String.class))).thenReturn(null);

        final MockHttpServletResponse response = mockMvc.perform(get("/session/sessionid")).andReturn().getResponse();
        assertThat(response.getStatus(), equalTo(NOT_FOUND.value()));
    }

}
