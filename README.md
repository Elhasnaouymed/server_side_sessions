# Server Side Sessions

Lets You deal with session is `dict` format, and it handles **Creation**, **Encryption**, **Reading**, **Updating** and **Deletion** of Sessions in the Server Side.  
Saves each session as one file.

You can choose your master key, and the directory where to save session files, you can also choose to save session unencrypted.

**License = GPLv2**

## Example

Let's create an instance of `ServerSideSession` and use it to create one empty session:

```python
from server_side_sessions import ServerSideSession

SECRET_KEY = '1e3411c6b699deff70392001783f5804266a13db2fa9d83569deb0f1d838db79'
DIR = 'user-sessions'
manager = ServerSideSession()
manager.initialize(SECRET_KEY, DIR)

# This creates an empty session with the specified name, just by opening it using `with` statement.
with manager['session name'] as session:
    pass
```

Now, this is hiw we loop and read + update all existing sessions one by one:

```python
for session_name in manager.list_sessions():  # list all sessions by names
    with manager[session_name] as session:  # open sessions to read and write as dictionary
        print(session_name, session)
        session['update'] = 'new value'  # update any value
        session['nonce'] = 15556.22  # all JSON valid types are supported
        session['nested'] = {
            'list': [1, 2, 3, 4],  # nesting
        }
    # after you close the context manager, session saving takes affect immediately
```

## Use Un-Encrypted

To make `ServerSideSession` saves sessions to disk in a JSON format, specify argument `unencrypted=True` at initialization:

```python
manager = ServerSideSession(unencrypt=1)
```

## Check and Delete Sessions

Use `exists()` to check if a session exists or not

```python
manager.exists('session name')

# > True
```

Use `del` statement to remove a session permanently

```python
del manager['session name']
```

---

> **Session names are Case Sensitive, and they support all names that can be used to name a file.**

> **Obviously, If you lose your encryption key, you are fucked.**

---

## Unique Keys

If you want to use a unique key for every single session, you should create a `ServerSideSession` instance on every operation.  
You can use something like this:

```python
DIR = 'user-sessions'


@contextmanager
def get_session(name: str, key: str, directory: str):
    manager = ServerSideSession()
    manager.initialize(key, directory)
    with manager[name] as session:
        yield session
```

Now call the method as you would call the `ServerSideSession` and provide your unique key:

```python
with get_session('session-1', 'session-1-key', DIR) as session:
    session['name'] = 'session-1'
    print(session)

with get_session('session-2', 'session-2-key', DIR) as session:
    session['name'] = 'session-2'
    print(session)

with get_session('session-3', 'session-3-key', DIR) as session:
    session['name'] = 'session-3'
    print(session)

with get_session('session-4', 'session-4-key', DIR) as session:
    session['name'] = 'session-4'
    print(session)
```

> **Any attempt to open a session with different key will raise `ServerSideSessionCorruptError`.**
