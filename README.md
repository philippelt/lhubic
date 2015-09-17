This library allow access from python 3 to OVH/Hubic file cloud service using the python swiftclient API binding.

The library request full authentication :

 - client_id and client_secret created from your HUBIC Account web interface (in the developper's section)  
AND
 - username and password of your Hubic Account  
OR
 - refresh_token if you already got it from a previous user/password authentication

This informations can be supplied when creating the Hubic class instance, at init time, or better supplied as environment parameters : HUBIC_CLIENT_ID, HUBIC_CLIENT_SECRET, HUBIC_USERNAME, HUBIC_PASSWORD, HUBIC_REFRESH_TOKEN

For details about full use of the swiftclient API, see http://docs.openstack.org/developer/python-swiftclient/

Usage example :
```
$ export HUBIC_CLIENT_ID="<your client id>"
$ export HUBIC_CLIENT_SECRET="<your client secret>"
$ export HUBIC_USERNAME="<your hubic account login>"
$ export HUBIC_PASSWORD="<your hubic account password>"

$ python3
>>>import lhubic
>>> hubic = lhubic.Hubic()   # You could provide here client_id, client_secret, username, password, refresh_token
>>> hubic.os_auth()          # To get an openstack swift token
>>> header, content = hubic.get_object("default", "ubuntu_logo.png")
>>> header["content-type"]
'image/png'
>>> header["content-length"]
'5135'
>>> # content contains the byte array of the "ubuntu_logo.png" content
>>> hubic.refresh_token
'lkjlkLKLFHLFKLSJLDJLHFKJGKSJHDLKSLDJLFHKJSKJHFKJSKHFKSJFHKJF'
```

Note that once you have successfully authenticate with your username and password, you can save the ```hubic.refresh_token``` for a future connection : it will no longer be necessary to supply username and password, just the refresh_token in place.

example :
```
$ export HUBIC_CLIENT_ID="<your client id>"
$ export HUBIC_CLIENT_SECRET="<your client secret>"
$ export HUBIC_REFRESH_TOKEN="lkjlkLKLFHLFKLSJLDJLHFKJGKSJHDLKSLDJLFHKJSKJHFKJSKHFKSJFHKJF"

$ python3
>>>import lhubic
>>> hubic = lhubic.Hubic()   # You could provide here client_id, client_secret, username, password, refresh_token
>>> hubic.os_auth()          # To get an openstack swift token
```

With this method, should the application source be compromised, you have the ability, from you Hubic account to suppress the application credentials that would make any credential embedded in source code unusable and keeping your username/password secret.

Example with credentials embedded in app (therefore not exactly the best possible practice) :
```python
hubic = lhubic.Hubic( client_id="<your client id>", client_Secret="<your client secret>",
                      refresh_token="lkjlkLKLFHLFKLSJLDJLHFKJGKSJHDLKSLDJLFHKJSKJHFKJSKHFKSJFHKJF")
hubic.os_auth()
```
