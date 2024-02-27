# CyberSecurityProject
This package provides a collection of cryptographic algorithms implemented in C#. From classic ciphers like the Caesar cipher and monoalphabetic substitution to more advanced techniques like the Diffie-Hellman key exchange, RSA (Rivest–Shamir–Adleman), and more.

# Getting Started
## Package Hierarchy
```bash
|-- .gitattributes
|-- .gitignore
|-- SecurityPackage.sln
|-- README.md
|-- securitylibrary
    |-- ICryptographic_Technique.cs
    |-- SecurityLibrary.csproj
    |-- ICryptographicTechnique.cs
    |-- CryptographicTechnique.cs
    |-- DiffieHellman
        |-- DiffieHellman.cs
        |-- MainAlgorithms
            |-- HillCipher.cs
            |-- AutokeyVigenere.cs
            |-- PlayFair.cs
            |-- RailFence.cs
            |-- Monoalphabetic.cs
            |-- Columnar.cs
            |-- Ceaser.cs
            |-- RepeatingKeyVigenere.cs
            |-- Exceptions
                |-- InvalidAnlysisException.cs
                |-- Properties
                    |-- AssemblyInfo.cs
                    |-- RSA
                        |-- RSA.cs
                        |-- ElGamal
                            |-- ELGAMAL.cs
                            |-- securitypackagetest
                                |-- PlayfairTest.cs
                                |-- ColumnarTest.cs
                                |-- MonoalphabeticTest.cs
                                |-- ElGamalTest.cs
                                |-- RSATest.cs
                                |-- RailFenceTest.cs
                                |-- CeaserTest.cs
                                |-- SecurityPackageTest.csproj
                                |-- VignereTest.cs
                                |-- HillCipherTest.cs
                                |-- DeffieHelmanTest.cs
                                |-- Properties
                                    |-- AssemblyInfo.cs
```
## Installing
1. Clone the repo using this command: <br/> ``` git clone https://github.com/KholoudAhmedx/CyberSecurityProject.git ```
