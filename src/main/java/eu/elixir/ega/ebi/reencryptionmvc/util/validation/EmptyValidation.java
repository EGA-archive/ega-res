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
package eu.elixir.ega.ebi.reencryptionmvc.util.validation;

import java.io.IOException;
import java.io.InputStream;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author asenf
 */
public class EmptyValidation implements Runnable {

    private final InputStream in;
    
    public EmptyValidation(InputStream in) {
        this.in = in;
    }
    
    @Override
    public void run() {
        
        byte[] buffer = new byte[65535];
        int readCount = 0;
        long total = 0;
        
        try {
            while ( (readCount = in.read(buffer)) > -1) { // As long as stream isn't cosed?
                if (readCount > 0) {
                    total += readCount;

                    // Peform Validation on Data

                    // This is intended to run in a separate thread; even if this
                    // process fails the primary re-encryption stream will continue

                } else {
                    Thread.sleep(10);
                }
            }
        } catch (IOException | InterruptedException ex) {
            Logger.getLogger(EmptyValidation.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }
    
}
