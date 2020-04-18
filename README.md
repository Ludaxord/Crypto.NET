# Crypto.NET

Library to create authorization based on libsodium library.

## Instalation

* [Nuget.org](https://www.nuget.org/packages/Crypto.NET)

To install package use nuget package manager 
````                     
dotnet add package Crypto.NET
````
## Usage

``Crypto`` is based on ``ICrypto`` interface. To start using library just call new instance of ``Crypto`` class.

```c#
ICrypto crypto = new Crypto();
```


Main datatype in Crypto.NET is ``Hash``. Hash has properties like ``HashToken`` and ``Token``. ``HashToken`` is main property of ``Hash`` object. To create Hash object and hash some message or password call function ``GenerateEncodedAuthHash`` like below:
```c#
string exampleMessage = "example_message";                  
int difficulty = 20;
Hash hash = crypto.GenerateEncodedAuthHash(exampleMessage, difficulty);
```                   


To check if CrossHash (another name of ``HashToken`` property) use function ``GenerateDecodedAuthHash`` like below:

```c#
string exampleMessage = "example_message";
Hash encodedHash = crypto.GenerateDecodedAuthHash(hash.HashToken, exampleMessage, hash.Salt, hash.Key);
bool verified = encodedHash.Verified;
```                           
