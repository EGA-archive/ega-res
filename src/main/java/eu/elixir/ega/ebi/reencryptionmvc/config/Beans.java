package eu.elixir.ega.ebi.reencryptionmvc.config;

import htsjdk.samtools.seekablestream.ISeekableStreamFactory;
import htsjdk.samtools.seekablestream.SeekableStreamFactory;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableDiscoveryClient
public class Beans {

    @Bean
    public ISeekableStreamFactory seekableStreamFactory() {
        return SeekableStreamFactory.getInstance();
    }

}
