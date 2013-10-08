zap-java-api
============

I require a client API to the OWASP ZAP proxy that implements two specified interfaces:

- [LoggingProxy.java](https://github.com/continuumsecurity/zap-java-api/blob/master/src/main/java/net/continuumsecurity/proxy/LoggingProxy.java)
- [ScanningProxy.java](https://github.com/continuumsecurity/zap-java-api/blob/master/src/main/java/net/continuumsecurity/proxy/ScanningProxy.java)

The requirements for each interfaces are noted in the method comments.
There is an existing Java client API to ZAP that implements some, but not all, of the required functions, it's included in the project files in the lib folder.
More information on using this API can be found at: https://code.google.com/p/zaproxy/wiki/FAQhowtousezapapi

The skeleton project includes the HarLib library for dealing with the Har format:  http://www.frogthinker.org/projects/harlib

# Deliverables

- Implement the net.continuumsecurity.proxy.ZAProxyScanner class according to the comments in the LoggingProxy and ScanningProxy interfaces.
- Note that the LoggingProxy interface makes use of the Har format to store HTTP data.  *ALL* of the contained classes must be populated with data, for example, the HarCookie must have all its fields (path, isHttpOnly, isSecure, etc) populated for every Cookie in the HarRequest and HarResponse.

# Bounty
100 of the finest Euros for a working implementation.  If you're interested in working on this, please get in contact first: stephen at continuumsecurity dot net.

The contributed code will remain open source under the same license as ZAP

