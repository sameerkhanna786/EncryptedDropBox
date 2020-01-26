# SecureFileStorage
Implementation of an authenticated secure file storage system with the ability to add and revoke permissions.

Storing files on a server and sharing them with friends and collaborators is very useful. Commercial services like Dropbox or Google Drive are popular examples of a file store service (with convenient filesystem interfaces). But what if you couldn’t trust the server you wanted to store your files on? What if you wanted to securely share and collaborate on files, even if the owner of the server is malicious? Especially since both Dropbox and Google Drive don’t actually encrypt the user data.

The goal of this project is to implement an encrypted dropbox-like system, a cryptographically authenticated and secure file store.

## Secure File Store
We designed our system to be able to store files. This file store can be used to store your own files securely, or to share your files with other people you trust.

It has the following properties:

### Confidentiality
Any data placed in the file store should be available only to you and people you share the file with. In particular, the server should not be able to learn any bits of information of any file you store, nor of the name of any file you store.

### Integrity
You should be able to detect if any of your files have been modified while stored on the server and reject them if they have been. More formally, you should only accept changes to a file if the change was performed by either you or someone with whom you have shared access to the file.
