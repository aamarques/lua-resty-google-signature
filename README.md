# lua-resty-google-signature

This library is based on the work of [Ludovic Vielle (lukkor)](https://github.com/jobteaser)
at https://github.com/jobteaser/lua-resty-aws.
It is basically forked from his repository and I have "translated" from AWS to GOOGLE format. 
This can help people find this signature process faster.

The signature, algoritms, etc is the same used for Signature V4 (SigV4), and GCS cam use it without modification, but here the aim is helping people to use the GCS syntax.

## Overview

This library implements request signing using the [Google Signature
Version 4][goog4] specification. This signature scheme is used in GCS acesse or in GCS migrations.

## GCS documentation

[goog4]: https://cloud.google.com/storage/docs/access-control/signed-urls

## Usage

This library uses GCS environment variables as credentials to
generate [GCS Signature Version 4][goog4].

```bash
export GCS_ACCESS_KEY=GOOGEXAMPLE
export GCS_SECRET_KEY=EXAMPLE_KEY
```

To be accessible in your nginx configuration, these variables should be
declared in `nginx.conf` file.

Example:

```nginx
worker_processes 1;
error_log stderr notice;
daemon off;

env GCS_ACCESS_KEY;
env GCS_SECRET_KEY;


events {
    worker_connections  1024;
}


http {
    include /usr/local/openresty/nginx/conf/mime.types;
    variables_hash_max_size 1024;
    real_ip_header X-Real-IP;
    charset utf-8;

    access_log  /dev/stdout;
    sendfile        on;
    keepalive_timeout  65;


    lua_package_path "$prefix/resty_modules/lualib/?.lua;;";
    lua_package_cpath "$prefix/resty_modules/lualib/?.so;;";

    resolver 8.8.8.8;

    server {
       listen 8080;
       set $gcs_host YOUR-BUCKET_NAME.storage.googleapis.com;

       location / {
            default_type  application/octet-stream;
            access_by_lua_block {
                require("resty.aws-signature").gcs_set_headers(ngx.var.gcs_host, ngx.var.uri)
            }
            proxy_pass https://$gcs_host;
        }
     }

}
```

If you install this module into a local dir, you should put this in `nginx.conf` file.
[Openresty Local Installation](https://opm.openresty.org/docs#local-installation)

```nginx
    lua_package_path "$prefix/resty_modules/lualib/?.lua;;";
    lua_package_cpath "$prefix/resty_modules/lualib/?.so;;";
```

`resolver 8.8.8.8` is here to prevent DNS resolve problems into the Docker.

Note: 
ItS not necessary  to set either <LOCATION>` or `<SERVICE>. 
`<LOCATION>` will be set automatically to  `auto` value  as this parameter exists to maintain compatibility with Amazon S3.
`<SERVICE>`  will be set automatically to  `storage` because we will be access GCP resources.

For example, a typical credential scope looks like:

`20211025/auto/storage/goog4_request`



## Contributing

Check [CONTRIBUTING.md](CONTRIBUTING.md) for more information.

## License

Copyright 2021 Antonio Marques (aamarques)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
