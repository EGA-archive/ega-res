# EGA Data API v3 -- Overview

The EGA Data API is a portable set of microservices providing a REST API to access to EGA data. There are currently several clients available for this API, including a command line download client and a FUSE layer for direct random access to archived files.

The API is written in Java 1.8 using the Spring Framework and Spring Boot 1.4. As a prerequisite two Spring Servers are expected to be running at all times:
* (Netflix) Eureka Server
* (Netflix) Config Server

All sercives register themselves with the Eureka instance, using the Spring application name `{app.name}` specified in `'bootstrap.configuration'`:`"spring.application.name={app.name}"`. Contact between microservices then utilises `{app.name}` instead of the absolute URL. Eureka automatically resolves the application name to a URL; if multiple instances with the same application name are present, Eureka automatically performs Ribbon load balancing between the instances. This greatly simplifies deployment and allows for easy and dynamic scaling to meet demand.

The Configuration server serves all `'application.configuration'` files to the respective microservices. The location (URL) of the config server must be specified in the `'bootstrap.configuration'`:`"spring.cloud.config.uri="` file of each service. This entry requires an absolute URL to the configration server. This is necessary because the configuration file must be loaded before the application startup. A config file named `'{app.name}.configuration'` must be in the config directory referenced by the configuration server before a service with `"spring.application.name={app.name}"` can be started.

Without these two services the remaining microservices will not function properly.

There are two microservices interfacing with a database:
* FILEDATABASE
* PERMISSIONSDATABASE [used only at Central EGA]

The PERMISSIONSDATABASE service reads (read-only) permissions-related information (user-dataset associations; etc.) while the FILEDATABASE service serves archive-related information (file-dataset associations; file paths; etc.) and keeps some logs (read/write).

Two microservices provide publicly accessible Edge services:
* CENTRAL [used only at Central EGA]
* DATAEDGE

DATAEDGE provides access to the data. It provides access to archived files directly; it streams downloas. This is the primary back end for the FUSE layer. All DATAEDGE endpoints require a valid EGA (ELIXIR) OAuth2 Bearer Token. Security for CENTRAL is different because it is meant as a service-facing API. CENTRAL serves user-dataset associations, and general dataset-file information.

One microservice serves as front door to all requests. It is a reverse proxy/filter and performs functions such as rate limitations, permissions-injection for ELIXIR access tokens. It also forwards all requests to an available back end service, based on availability provided by EUREKA, thus tying all services behind a single URL and load-balancing multiple back end services.

At EGA Central these services are deployed behind an SSL terminating load balancer; therefore https is not initially implemented with these services.

The CPU heavy cryptographic work is performed by the RES service, supported by a Key provider service and an H2 database (to enable this service to be properly load balanced). The key provider service produces the archive decryption key for a specified file, and is only used from within RES. The H2 database stores MD5 values of data transfers, to enable verification of completed downloads.
* KEY
* H2 DB
* RES

### Summary
* EUREKA
    * Requires: CONFIG
    * Required By: DATAEDGE, CENTRAL PERMISSIONSDATABASE, FILEDATABASE, RES, KEY, ZUUL
* CONFIG
    * Requires:
    * Required By: DATAEDGE, CENTRAL PERMISSIONSDATABASE, FILEDATABASE, RES, KEY
* H2
    * Requires:
    * Required By: RES, DATAEDGE
* KEY
    * Requires: EUREKA, CONFIG
    * Required By: RES
* PERMISSIONSDATABASE
    * Requires: EUREKA, CONFIG
    * Required By: CENTRAL
* FILEDATABASE
    * Requires: EUREKA, CONFIG
    * Required By: DATAEDGE
* DATAEDGE
    * Requires: EUREKA, CONFIG, FILEDATABASE
    * Required By: ZUUL
* CENTRAL
    * Requires: EUREKA, CONFIG, PERMISSIONSDATABASE
    * Required By: ZUUL
* RES
    * Requires: EUREKA, CONFIG, KEY, H2
    * Required By: FILEDATABASE
* ZUUL
    * Requires: EUREKA, CONFIG
    * Required By: 
