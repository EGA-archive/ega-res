# EGA.Data.API.v3.RES

This is a Re-Encryption Server. It is available via EUREKA using the service name `"RES"`.

Dependency: 
* CONFIG (`https://github.com/EGA-archive/ega-config-server`). The `'bootstrap-blank.properties'` file must be modified to point to a running configuration service, which will be able to serve the `application.properties` file for this service `RES`
* EUREKA (`https://github.com/EGA-archive/ega-eureka-service`). RES service will contact the KEY service via EUREKA and registers itself with it.
* KEY (`https://github.com/EGA-archive/ega-api-key`). This provides RES with the keys it requires to perform encryption/decryption.
* FILEDATABASE (`https://github.com/EGA-archive/ega-filedatabase-service`). This provides a resolution from File IDs to File Paths, and information necessary to access the archived file.
* H2 Database Instance. Any database can be used - this is a convenient lightweight database. It can be downloaded (`http://central.maven.org/maven2/com/h2database/h2/1.4.193/h2-1.4.193.jar`) and is started using (`"java -cp $PATH_TO_JAR org.h2.tools.Server -tcpAllowOthers"`). This database holds temporary information, such as MD5 values of completed cryptographic streams. Using a database allows RES to be replicated and load balanced without requiring sticky sessions.

Provides: 
* RES: requests encryption and decryption keys from this service

### Documentation

RES incorporates all cryptographic services required by EGA and can read input streams (and produce output streams) encrypted using:
* GPG Public Key	{“semi-random-access”}
* GPG Symmetric Key 	{“semi-random-access”}
* AES 128-Bit
* AES 256-Bit
* Plain (Unencrypted)

Plain and AES-encrypted input streams can be accessed at a byte-level. Currently two input stream sources are supported: file path and http, to support files stored in file systems as well as object stores (Cleversafe).
GPG-encrypted input streams can still be “sliced” - the mechanism allowing this form of access has to read/decrypt a file from start until the specified start coordinate, and then the specified number of bytes are read and returned. Bytes can be ‘skipped’ there is no true ‘seek’ functionality. This is slow, but may still be beneficial in saving data transfer volume.

RES uses FILEDATABASE to translate an EGAF file ID into an access URL so that archive files can be accessed directly by ID rather than requiring an absolute file locator; for convenience.

[GET] `/stats/load`
[GET] `/file` `[sourceFormat, sourceKey, destinationFormat, destinationKey, filePath, startCoordinate, endCoordinate, fileSize, httpAuth, id]`
[GET] `/file/archive/{id}`	`[destinationFormat, destinationKey, startCoordinate, endCoordinate]`
[GET] `/file/archive/{id}/size`	
[GET] `/session/{session_id}`

[GET] `/file/test2/{size}`

Each request returns a special header field `“X-Session”` which contains a UUID and identifies this file transfer. Clients can request server statistics (e.g. MD5s, sizes) from the server after the transfer is completed using the /session endpoint with the session UUID. Further in the future this should allow websocket connections for higher-performance interactions with archived files. This functionality is currently not used.

### Todos

 - Write Tests

### EXPERIMENTAL Deploy

The service can be deployed directly to a Docker container, using these instructions:

`wget https://raw.github.com/elixir-europe/ega-data-api-v3-res_mvc/master/docker/runfromsource.sh`  
`wget https://raw.github.com/elixir-europe/ega-data-api-v3-res_mvc/master/docker/build.sh`  
`chmod +x runfromsource.sh`  
`chmod +x build.sh`  
`./runfromsource.sh`  

These commands perform a series of actions:  
	1. Pull a build environment from Docker Hub  
	2. Run the 'build.sh' script inside of a transient build environment container.  
	3. The source code is pulled from GitHub and built  
	4. A Deploy Docker Image is built and the compiled service is added to the image  
	5. The deploy image is started; the service is automatically started inside the container  

The Docker image can also be obtained directly from Docker Hub:  

`sudo docker run -d -p 9090:9090 alexandersenf/ega_access`  or by running the `./runfromimage.sh` file.
