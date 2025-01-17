# Kong Splunk Log Customized
## Over
This is a forked and customized version of the excellent Kong Splunk Log (C) Optum. I recommend that you use the original.
This version support logging of request body, setting splunk index and setting source type for Splunk. 
## Supported Kong Releases
Kong >= 3.x

## Installation
```
$ git clone https://github.com/ilovetypescript/kong-splunk-log-customized.git /path/to/kong/plugins/kong-splunk-log-customized
$ cd /path/to/kong/plugins/kong-splunk-log-customized
$ luarocks make *.rockspec

For more information see https://docs.konghq.com/gateway/latest/plugin-development/distribution/
```

## Configuration
The plugin requires an environment variable `SPLUNK_HOST` . This is how we define the host="" splunk field in the example log picture embedded above in our README.

Example Plugin Configuration:

![Splunk Config](https://github.com/ilovetypescript/kong-splunk-log-customized/blob/master/SplunkConfig.png)

And in  addition to these parameters you can set ....
splunk_index = { type = "string", default = "" }
splunk_sourcetype = { type = "string", default = "AccessLog" }
includebody = { type = "integer", default = 0 }
includeresponse = { type = "integer", default = 0 }, },
includejwt = { type = "integer", default = 0 }, },
includeheaders = { type = "integer", default = 0 }, },
includeBearerTokenHeader = { type = "integer", default = 0 } },
          
If not already set, it can be done so as follows:
```
$ export SPLUNK_HOST="gateway.company.com"
```

**One last step** is to make the environment variable accessible by an nginx worker. To do this, simply add this line to your _nginx.conf_
```
env SPLUNK_HOST;
```

## Maintainers
[ilovetypescript](https://github.com/Ilovetypescript)

