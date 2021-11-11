# JCBitcoinWallet
A Bitcoin Wallet, implemented in Java Card

## How to install
1. This project uses [ant-javacard](https://github.com/martinpaljak/ant-javacard). Download and install it first.
1. Make sure you have the JCKit for your Java Card version downloaded
1. Edit the path for the JCKit and your desired output path in the build.xml file
1. Run the "Wallet" ant target in the build.xml file. This will produce a CAP file in the specified location
1. Install this CAP file onto your smart card (for example using [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro))

## Versions
There are two, incompatible versions of this applet:
1. Version A (this version)
    * can be found on the *signaturecard*-Branch 
    * is only compatible with the *signaturecard*-Branch of the terminal application
    * smart card is only used to sign transactions prepared by the terminal
    
2. Version B
    * can be found on the *master*-Branch
    * is only compatible with the *master*-Branch of the terminal application
    * smart card creates the transaction on its own with data sent from the terminal

## How to use
* this Applet is designed to be used with the our [Bitcoin Terminal Application](https://github.com/johannzapf/bitcointerminal)
* follow the instructions there to run the program