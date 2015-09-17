## Overview

This library allow access from python 3 to OVH/Hubic file cloud service using the python swiftclient API binding.

This developement is based on the initial work of puzzle1536 that can be found at https://github.com/puzzle1536/hubic-wrapper-to-swift

>You will need the ```python-swiftclient``` and ```requests``` additional library

The library request full authentication :

 - client_id and client_secret created from your HUBIC Account web interface (in the developper's section)  
AND
 - username and password of your Hubic Account  
OR
 - refresh_token if you already got it from a previous user/password authentication

These informations can be supplied when creating the Hubic class instance, at init time, or better supplied as environment parameters : HUBIC_CLIENT_ID, HUBIC_CLIENT_SECRET, HUBIC_USERNAME, HUBIC_PASSWORD, HUBIC_REFRESH_TOKEN

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

## Examples of swift API bindings

>Note, if your want to be able to access your objects/files using the web interface, your have to place them in the default container created by hubic named "default".

#### Get account information

Provides some general account information (number of objects stored, bytes used, quota, ...) as well as the list of defined containers.

```python
>>> header, containers = hubic.get_account()

header is a dictionary of meta-data about the account
content is a list of containers dictionary

>>> total_space = int(header["x-account-meta-quota"])
>>> used_space = int(header["x-account-bytes-used"])
>>> usage = used_space / total_space

>>> [c["name"] for c in containers]
['default']
```

#### Get a container content list

Container is a flat structure. It is possible to add full path in object names to simulate a usual file system tree structure.
Getting the list of container content return by default all objects names stored (limited to 10000). You can use ```delimiter``` parameter to limit to first level of virtual directories.

```python
>>> header, objectList = hubic.get_container("default", delimiter="/")

Again, header is a dictionary of container properties
obkectList is a list of dictionaries describing each object at the top container level
all object with a / in the object name will not be returned and the virtual
directory will be returned as subdir

>>> [(f["name"],f["last_modified"]) for f in objectList if "name" in f]
[('ubuntu_logo.png', '2015-09-17T09:47:23.209850'), ('uploadTest', '2015-09-17T08:31:06.547660')]

>>> [f["subdir"] for f in objectList if "subdir" in f]
['python/']
```

#### Put/Get a file

The object name may contain the "/" character like a full pathname of a tree filesystem.

```python
>>> # Store a file
>>> with open("test.png", "rb") as f:
...   hubic.put_object("default", "photos/my_copy_of_test.png", f.read())
'kdfskgdfkJHKFKjfkkjhkj'

The returned value is the id of the object. You could use it to refer to this object in an external system.

>>> # Retrieve a file
>>> stats, content = hubic.get_object("default", "photos/my_copy_of_test.png")

stats is a directory of usual metadata (date modified, size, content-type, content-length)
content is the file content. You can save it ina file with :
>>> with open("test_copy.png", "wb") as f: f.write(content)

If you have a large file to download and don't want to keep it in memory, use the chunk download

>>> stats, reader = hubic.get_object("default", "a_big_object", resp_chunk_size=1048560) # For chunks of 1MB
>>> with open("big_object.dat", "wb") as f:
...   for chunk in reader: f.write(chunk)
```

#### Directe store a serializable python object

Any serializable object (using pickle, json or any other method) can easily be stored.

```python
>>> myList = [1,2,3,4]

>>> # Store
>>> hubic.put_object("default", "python/data/myList", pickle.dumps(myList))

>>> # Retrieve
>>> header, content = hubic.get_object("default", "python/data/myList")
>>> myList = pickls.loads(content)
>>> myList
[1,2,3,4]
```

