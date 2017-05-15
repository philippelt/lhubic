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
>>> # content contains the byte array of the "ubuntu_logo.png"
>>> # You can write it to a file with :
>>> with open("ubuntu_logo.png", "wb") as f: f.write(content)
>>>
>>> # Save the content of refresh_token to get access without user/password
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
>>> hubic = lhubic.Hubic()
>>> hubic.os_auth()
```

With this method, should the application source be compromised, you have the ability, from you Hubic account, to suppress the application credentials that will make any credential embedded in source code unusable and keep your username/password secret.

Example with credentials embedded in app (therefore not exactly the best possible practice) :
```python
hubic = lhubic.Hubic( client_id="<your client id>",
...                   client_Secret="<your client secret>",
...                   refresh_token="<the saved refresh token>")
hubic.os_auth()
```

## Access to OVH Hubic API

You can request GET/POST/DELETE to the hubic API with hubic_get / hubic_post / hubic_delete methods of your hubic instance.  
Using the json() method on the result directly return a dictionary from the json response.  

Check the OVH Hubic API at : https://api.hubic.com/console/

Exemple
```python
>>> result = hubic.hubic_get("/account/credentials").json()
>>> targetUrl = result["endpoint"]
```

## Examples of swift API bindings

>Note, if you want to be able to access your objects using the official OVH web Hubic interface, your have to place them in the default container created by hubic named "default".

You can use as many containers as you want but they will be accessible only through the API.

#### Get account information

Provides some general account information (number of objects stored, bytes used, quota, ...) as well as the list of containers.

```python
>>> header, containers = hubic.get_account()
>>> # header is a dictionary of meta-data about the account
>>> # content is a list of containers dictionary

>>> total_space = int(header["x-account-meta-quota"])
>>> used_space = int(header["x-account-bytes-used"])
>>> usage = used_space / total_space

>>> [c["name"] for c in containers]
['default']  # In this case, there is only 1 container in the account, it is the Hubic default
```

#### Get a container content list, create additionals containers

Container is a flat structure. Objects are identified using a name.  
It is possible to add delimiters in object names to simulate a usual file system tree structure (eg object name "A/B/C" to simulate an object named C in the subdirectory B of A).  
Getting the list of container content return by default all objects names stored (limited to 10000). You can use ```delimiter``` parameter to limit to first level of "virtual directories".  
If you want only object list of one of the virtual subdir, use ```prefix``` to specifiy the "virtual path". Practically, it returns object names starting with the prefix content which could be use in other cases than file system tree emulation.

```python
>>> header, objectList = hubic.get_container("default", delimiter="/")
>>> # header is a dictionary of container properties
>>> # objectList is a list of dictionaries describing each object at the top container level
>>> # all object with a / in the object name will not be returned and the virtual
>>> # directory (first part before /) will be returned as subdir item

>>> # Get the list of "leaf" objects, they alone have a "name" key
>>> [(f["name"],f["last_modified"]) for f in filter(lambda i: "name" in i, objectList)]
[('ubuntu_logo.png', '2015-09-17T09:47:23.209850'), ('uploadTest', '2015-09-17T08:31:06.547660')]
>>>
>>> # Get the list of "virtual subdir", they have a "subdir" key
>>> [f["subdir"] for f in filter(lambda i: "subdir" in i, objectList)]
['python/']
>>> # NOTE : The delimiter is always part (at end) of the subdir name

>>> # Get the list of the python virtual subdir
>>> header, objectList = hubic.get_container("default", delimiter="/", prefix="python/")

>>> # Create a new container
>>> hubic.put_container("myNewContainer")
>>> # Eventually remove it
>>> hubic.delete_container("myNewContainer")
```

#### Put/Get a file

The object name may contain the "/" character like a full pathname of a tree filesystem (see above).

```python
>>> # Store the content of a local file
>>> with open("test.png", "rb") as f:
...   hubic.put_object("default", "photos/my_copy_of_test.png", f.read())
'<md5 sum of the stored content>'

The returned value is the MD5 sum of the object content.
You could use it to ensure storage sanity checkup for sensitive content.

>>> # Retrieve a file
>>> stats, content = hubic.get_object("default", "photos/my_copy_of_test.png")

stats is a directory of usual metadata (date modified, size, content-type, content-length)
content is the file content. You can save it in a file with :
>>> with open("test_copy.png", "wb") as f: f.write(content)

If you just want file information replace
get_object with head_object that return only stats
(usefull to check object size before download for example)
>>> stats = hubic.head_object("default", "photos/my_copy_of_test.png")

If you have a large file to download and don't want to keep it in memory,
use the chunk download

>>> stats, reader = hubic.get_object("default", "a_big_object",
...                                  resp_chunk_size=1048560) # For chunks of 1MB
>>> # the reader is a generator that will let you iterate over chunks
>>> with open("big_object.dat", "wb") as f:
...   for chunk in reader: f.write(chunk)

Despite swift supporting chunk upload, it seems to systematcaly fail if attempted on hubic.
I suggest manualy managing chunks (by splitting object files if they are too big).

If you want to get ride of an object :
>>> hubic.delete_object("default", "a_big_object")
```

#### Directe store a serializable python object

Any serializable object (using pickle, json or any other method) can easily be stored.

```python
>>> myList = [1, 2, {"A":1,"B":2}, 4, "Test"]

>>> # Store
>>> hubic.put_object("default", "python/data/myList", pickle.dumps(myList))

>>> # Retrieve
>>> header, content = hubic.get_object("default", "python/data/myList")
>>> myList = pickle.loads(content)
>>> myList
[1, 2, {"A":1,"B":2}, 4, "Test"]

>>> # You can do this with serializable classes (very nice)
>>>
>>> class People:
...   def __init__(self, firstname, name):
...      self.firstname = firstname
...      self.name = name
>>>
>>> Test = People("myFirstName", "myName")
>>> # Store the class with a name generated from "name" property of the instance
>>> hubic.put_object("default", "python/data/testPeople/%s" % testPeople.name,
...                  pickle.dumps(testPeople))
>>>
>>> # You now want to retrieve the People instance with name "myName"
>>> header, content = hubic.get_object("default", "python/data/testPeople/myName")
>>> result = pickle.loads(content)
>>> type(result)
<class '__main__.People'>
>>> result.__dict__
{'firstname': 'myFirstName', 'name': 'myName'}
```
