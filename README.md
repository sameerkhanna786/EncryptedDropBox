# SecureFileStorage
Implementation of an authenticated secure file storage system with the ability to add and revoke permissions.

Storing files on a server and sharing them with friends and collaborators is very useful. Commercial services like Dropbox or Google Drive are popular examples of a file store service (with convenient filesystem interfaces). But what if you couldn’t trust the server you wanted to store your files on? What if you wanted to securely share and collaborate on files, even if the owner of the server is malicious? Especially since both Dropbox and Google Drive don’t actually encrypt the user data.

The goal of this project is to implement an encrypted dropbox-like system, a cryptographically authenticated and secure file store.

## Secure File Store
We designed our system to be able to store files. This file store can be used to store your own files securely, or to share your files with other people you trust.

### Properties
It has the following properties:

#### Confidentiality
Any data placed in the file store should be available only to you and people you share the file with. In particular, the server should not be able to learn any bits of information of any file you store, nor of the name of any file you store.

#### Integrity
You should be able to detect if any of your files have been modified while stored on the server and reject them if they have been. More formally, you should only accept changes to a file if the change was performed by either you or someone with whom you have shared access to the file.

### Servers
We assume we have access to two server types:

A storage server, which is untrusted, where files are stored. It has three methods:
• DatastoreSet(key string, value []byte), which stores value at key
• DatastoreGet(key string), which returns the value stored at key
• DatastoreDelete(key string), which deletes that item from the data store.

A public key server, which is trusted, that allows you to receive other users’ public keys. You have a secure channel to the public key server. It has two methods:
• KeystoreSet(key string, value []byte), which sets the public key for your username key to be value
• KeystoreGet(key string), which returns the public key for key

We represent accesses to the servers via the above API methods.

## Simple upload/download
Implement a file store with a secure upload/download interface.

### Properties
We ensure the following properties hold. See RFC 2119 for the definitions of MUST, MUST NOT, SHOULD, and MAY as used below.

#### Property 1
MUST take the user’s password, which is assumed to have good entropy, and use this to help pop- ulate the User data structure (including generating at least one random RSA key), securely store a copy of the data structure in the data store, register a public key in the keystore, and return the newly populated user data structure. The user’s name MUST be confidential to the data store.

#### Property 2
If the username and password are correct this MUST load the appropriate information from the data store to populate the User data structure or, if the data is corrupted, return an er- ror. If either the username or password are not correct it MUST return an error.

#### Property 3
When not under attack by the storage server or another user, loading a file MUST return the last value stored at filename by the user or nil if no such file exists. It MUST NOT raise IntegrityError or any other error.

#### Property 4
Loading a file MUST NOT ever return an incorrect value. A value (excluding nil ) is “incorrect” if it is not one of the values currently or previously stored at filename by the current user.

It also MUST raise an error or return nil if under any attack by the server or other users that successfully corrupts the file. It MUST return an error if the file has been tampered with but some record of it still exists in the data store. It MUST return nil if it appears that no value for filename exists for the user.

#### Property 5
Storing a file MUST place the value data at filename so that future loading of files for filename return data. Any person other than the owner of filename MUST NOT be able to learn even partial information about data or filename with probability better than random guesses, other than the length of the data written.

#### Property 6
Appending a file MUST append the value data at filename so that future LoadFiles for filename return data appended to the previous contents. Appending a file MAY return an error if some parts of the file are corrupted.

Any person other than the owner of filename MUST NOT be able to learn even partial information about data or filename, apart from the length of data and the number of appends conducted to the file, with probability better than random guesses.

We assume file names are alphanumeric (they match the regex [A-Za-z0-9]+). We also assume file names will not be empty. We make no assumptions regarding file contents.

#### Property 7
After a shares file n1 with b under name n2, user b MUST now have access to file n1 under the name n2. Every user with whom this file has been shared (including the owner) MUST see any updates made to this file immediately. To user b, it MUST be as if this file was created by them: they MUST be able to read, modify, or re-share this file.

Loading a file operations MUST return the last value written by anyone with access to the file (the owner, or anyone with whom the file was shared). Only those with access to the file should be able to read or modify it.

#### Property 8
If the original creator of the underlying file revoke permission, then afterwards all other users MUST NOT be able to observe new updates to filename, and anyone with whom other users shared this file MUST also be revoked. Except for knowing the previous contents of filename, to other users, it MUST be as if they never had received the file. It is undefined behavior if someone other than the original creator invokes RevokeFile, but it is acceptable for this to revoke access for everyone other than the user invoking RevokeFile.

This single property has several hidden implications which may not be clear right away. Suppose that in the past, Alice granted Bob access to file F, and now Alice revokes Bob’s access. Then we want all the following to be true subsequently:
1. Bob should not be able to update F,
2. Bob should not be able to read the updated contents of F (for any updates that happen after Bob’s access was revoked), and
3. If Bob shared the file with Carol, Carol should also not be able to read or update F.
4. Bob should not be able to regain access to F by calling Receive File() with Alice’s previous msg.
Revocation must not require any communication between clients.
You only need to implement functionality to revoke access from all other users.
If Alice shares a file with Bob, and then revokes Bob’s access, it may still be possible (depending on the design of your system) for Bob to mount a denial of service (DoS) attack on Alice’s file (for example, by overwriting it with all 0s, or deleting ids), but Alice should never accept any changes Bob makes as valid. She should always either raise an IntegrityError, or return None (if Bob deleted her files).

## Design Document
Please view the pdf in this repository for the project's design document.

## Acknowledgements
1. Dr. Nicholas Weaver (http://www1.icsi.berkeley.edu/~nweaver/)
2. Mohammed Shaikh ()
