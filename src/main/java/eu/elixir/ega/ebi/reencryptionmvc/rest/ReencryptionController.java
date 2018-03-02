package eu.elixir.ega.ebi.reencryptionmvc.rest;

import eu.elixir.ega.ebi.reencryptionmvc.domain.Format;
import eu.elixir.ega.ebi.reencryptionmvc.service.ReencryptionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.core.io.InputStreamResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import java.io.InputStream;

// Test files can be found at "src/test/resources/htsjdk/samtools/seekablestream/cipher/" under ega-htsdjk project
// http://localhost:8080/download?fileLocation=/lorem.aes.enc&startByte=10&endByte=20&sourceFormat=AES&sourceKey=/ega.sec&targetFormat=GPG&targetKey=/public.key
@EnableDiscoveryClient
@RequestMapping("/download")
@RestController
public class ReencryptionController {

    private static final String CONTENT_DISPOSITION_PREFIX = "attachment; filename=";

    private ReencryptionService reencryptionService;

    @GetMapping
    @ResponseBody
    public ResponseEntity<Resource> download(@RequestParam(value = "sourceFormat", required = false, defaultValue = "plain") String sourceFormat,
                                             @RequestParam(value = "sourceKey", required = false) String sourceKey,
                                             @RequestParam(value = "targetFormat", required = false, defaultValue = "plain") String targetFormat,
                                             @RequestParam(value = "targetKey", required = false) String targetKey,
                                             @RequestParam(value = "fileLocation") String fileLocation,
                                             @RequestParam(value = "startByte", required = false, defaultValue = "0") long startByte,
                                             @RequestParam(value = "endByte", required = false, defaultValue = "0") long endByte) throws Exception {
        InputStream inputStream = reencryptionService.getInputStream(Format.valueOf(sourceFormat.toUpperCase()),
                sourceKey,
                Format.valueOf(targetFormat.toUpperCase()),
                targetKey,
                fileLocation,
                startByte,
                endByte);
        InputStreamResource file = new InputStreamResource(inputStream);
        return ResponseEntity
                .ok()
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_OCTET_STREAM_VALUE)
                .header(HttpHeaders.CONTENT_DISPOSITION, CONTENT_DISPOSITION_PREFIX + StringUtils.getFilename(fileLocation))
                .body(file);
    }

    @Autowired
    public void setReencryptionService(ReencryptionService reencryptionService) {
        this.reencryptionService = reencryptionService;
    }

}
