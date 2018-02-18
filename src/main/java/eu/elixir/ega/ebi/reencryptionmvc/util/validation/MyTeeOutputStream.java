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
import java.io.OutputStream;

/**
 * @author asenf
 */
public final class MyTeeOutputStream extends OutputStream {

    private final OutputStream out;
    CircularByteBuffer cbb;

    public MyTeeOutputStream(OutputStream out, CircularByteBuffer cbb) {
        if (out == null)
            throw new NullPointerException();
        else if (cbb == null)
            throw new NullPointerException();

        this.out = out;
        this.cbb = cbb;
    }

    @Override
    public void write(int b) throws IOException {
        out.write(b);
        cbb.getOutputStream().write(b);
    }

    @Override
    public void write(byte[] b) throws IOException {
        out.write(b);
        cbb.getOutputStream().write(b);
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        out.write(b, off, len);
        cbb.getOutputStream().write(b, off, len);
    }

    @Override
    public void flush() throws IOException {
        out.flush();
        cbb.getOutputStream().flush();
    }

    @Override
    public void close() throws IOException {
        out.close();
        cbb.getOutputStream().close();
    }

}