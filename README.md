# Kong Splunk Log Customized
## Overview
This is a forked and customized version of the excellent Kong Splunk Log (C) Optum. I recommend that you use the original.
## Supported Kong Releases
Kong >= 2.4

## Installation
```
$ git clone https://github.com/ilovetypescript/kong-splunk-log-customized.git /path/to/kong/plugins/kong-splunk-log-customized
$ cd /path/to/kong/plugins/kong-splunk-log-customized
$ luarocks make *.rockspec

And then look at 
```

## Configuration
The plugin requires an environment variable `SPLUNK_HOST` . This is how we define the host="" splunk field in the example log picture embedded above in our README.

Example Plugin Configuration:

![Splunk Config](https://github.com/ilovetypescript/kong-splunk-log-customized/blob/master/SplunkConfig.png)

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

