## HOW DO I ADD THE ABILITY TO ADD A NEW SECRET TYPE?

I imagine this will be the most pressing question on everybody's mind, so let me document it here.

Basically, you follow what I did in [this commit](https://github.com/id-unibe-ch/ansible-module-secretserver/commit/016ed50d97734b78f1c652823770d626c181f009).

That means:
1. Create a secret of the specific type through the Web UI of the secret server
2. Get your Secret via the REST API with `curl --location '$BASE_URL/api/v2/secrets/$SECRET_ID' --header 'Content-Type: application/json' --header 'Authorization: Bearer $TOKEN'`
3. Expand the `type_mapping` dict of the `get_secret_body` method with the info you just got from the API. Implement every field except for file upload types. When it comes time to name the type, use the same name as outlined in the `type_mapping` dict of `lookup_single_secret`.
4. Expand the method signatures to include the fields you just added
5. Update the documentation (both on top of `library/secretserver.py` and in `README.md`)
6. Add a nice example in `README.md`
7. Test your code
8. Done

## HOW DO I DEBUG DURING THE DEV PROCESS?

Ansible makes it _really_ hard to get good insight into a module.

There are two ways i found to debug:

### One

You can use `print` within your code and then before the `module.exit_json` call you just `exit(1)`.
This will cause Ansible to think your module encountered an error and dump all the stout to your console.
Much of the formatting will be lost, so you'll have to dig a bit to fid the line you were looking for.

### Two

You can set the debug environment variable
````bash
export ANSIBLE_DEBUG=True
````
This will then print all kind of debug info to your screen.
In this mode, you can simply use `print` within your python code to have it show up during the run.
I heavily encourage turning debug mode back off in production, because passwords will be printed to your screen, even if they are specified as no-log.