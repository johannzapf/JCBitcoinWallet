package de.johannzapf.jc.bitcoinwallet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

public class Wallet extends Applet {

    private static final byte[] version = {'1', '.', '3', '.', 'S'};
    private static final byte CLA = (byte) 0x80;

    private static final byte INS_VERSION = (byte) 0x00;
    private static final byte INS_CONN_MODE = (byte) 0x01;
    private static final byte INS_STATUS = (byte) 0x02;
    private static final byte INS_INIT = (byte) 0x03;
    private static final byte INS_GET_ADDR = (byte) 0x05;
    private static final byte INS_SIGN = (byte) 0x06;
    private static final byte INS_GET_PUBKEY = (byte) 0x07;

    private static final byte INS_PIN_REMAINING_TRIES = (byte) 0x19;
    private static final byte INS_VERIFY_PIN = (byte) 0x20;
    private static final byte INS_MODIFY_PIN = (byte) 0x24;

    private static final byte P1_MAINNET = (byte) 0x01;
    private static final byte P1_TESTNET = (byte) 0x02;

    private static final short SW_PINVERIFY_FAILED = (short)0x6900;


    private static final byte PIN_TRIES = (byte) 5;
    private static final byte PIN_SIZE = (byte) 4;

    private byte[] scratch;

    private byte initialized = (byte) 0x00;
    private byte[] address;
    private ECPrivateKey privKey;
    private ECPublicKey pubKey;

    private byte[] signature;

    private Signature sign;

    private byte[] bcPub;
    private byte[] sha;
    private byte[] ripemd160;
    private byte[] net;

    private OwnerPIN pin;
    private boolean pinInitialized = false;

    /**
     * The install()-Method. Called by the JCVM on Applet install.
     * @param bArray
     * @param bOffset
     * @param bLength
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new Wallet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    /**
     * The default constructor allocates all memory of fixed length that is needed later and the PIN.
     */
    public Wallet(){
        this.scratch = JCSystem.makeTransientByteArray((short)256, JCSystem.CLEAR_ON_DESELECT);

        this.signature = new byte[72];

        this.bcPub = new byte[65];
        this.sha = new byte[32];
        this.ripemd160 = new byte[20];
        this.net = new byte[21];
        this.address = new byte[25];

        this.pin = new OwnerPIN(PIN_TRIES, PIN_SIZE);

        this.sign = Signature.getInstance(MessageDigest.ALG_NULL, Signature.SIG_CIPHER_ECDSA, Cipher.PAD_NULL, true);
    }

    /**
     * This method is called when an APDU is sent to the card. It reads the INS value and calls the respective method.
     * @param apdu
     */
    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }

        byte[] buffer = apdu.getBuffer();

        if (buffer[ISO7816.OFFSET_CLA] != Wallet.CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch(buffer[ISO7816.OFFSET_INS]){
            case INS_VERSION:
                getVersion(apdu);
                break;
            case INS_CONN_MODE:
                getConnectionMode(apdu);
                break;
            case INS_STATUS:
                getStatus(apdu);
                break;
            case INS_INIT:
                initialize(apdu);
                break;
            case INS_GET_PUBKEY:
                getPubKey(apdu);
                break;
            case INS_GET_ADDR:
                getAddr(apdu);
                break;
            case INS_SIGN:
                signTransaction(apdu);
                break;
            case INS_PIN_REMAINING_TRIES:
                getRemainingPINTries(apdu);
                break;
            case INS_VERIFY_PIN:
                verifyPIN(apdu);
                break;
            case INS_MODIFY_PIN:
                modifyPIN(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    /**
     * Reads the PIN sent with APDU and checks it against the OwnerPIN object.
     * Returns 0x9000 on success and 0x6900 in case the PIN is wrong.
     * @param apdu
     */
    private void verifyPIN(APDU apdu){
        byte[] buffer = apdu.getBuffer();
        short bytes = apdu.setIncomingAndReceive();

        if (!pin.check(buffer, ISO7816.OFFSET_CDATA, (byte) bytes)) {
            ISOException.throwIt(SW_PINVERIFY_FAILED);
        }
    }

    /**
     * Reads the PIN sent with the APDU and sets it as the new PIN, given that this is the first time this method is called
     * Returns 0x9000 on success and 0x6900 if the PIN has already been set.
     * @param apdu
     */
    private void modifyPIN(APDU apdu){
        byte[] buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();

        if(!pinInitialized){
            pin.update(buffer, ISO7816.OFFSET_CDATA, PIN_SIZE);
            pinInitialized = true;
        } else {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    /**
     * The main method to sign a transaction.
     * Reads the hash inside the APDU, signs it and returns the signature.
     * Throws 0x6982 if the PIN is not validated AND the card is not connected via NFC
     * @param apdu
     */
    private void signTransaction(APDU apdu){
        if(!isConnectedViaNFC() && !pin.isValidated()){
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        byte[] buffer = apdu.getBuffer();
        short bytes = apdu.setIncomingAndReceive();

        //Signature
        sign.init(privKey, Signature.MODE_SIGN);
        short length = sign.sign(buffer, ISO7816.OFFSET_CDATA, bytes, signature, (short) 0);

        //Check and potentially fix S value
        length += CryptoUtils.fixS(signature, (short) 0);

        Util.arrayCopyNonAtomic(signature, (short) 0, buffer, (short) 0, length);
        apdu.setOutgoingAndSend((short) 0, length);
    }

    /**
     * Generates a new ECC Keypair and generates a Bitcoin address with it.
     * Sets the initialized flag to 1 once completed.
     * @param apdu
     */
    private void initialize(APDU apdu){
        byte[] buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();

        //Generate Private and Public Key
        KeyPair keyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
        privKey = (ECPrivateKey) keyPair.getPrivate();
        pubKey = (ECPublicKey) keyPair.getPublic();


        //Represent Public Key as Point on Elliptic Curve
        Secp256k1.setCommonCurveParameters(privKey);
        Secp256k1.setCommonCurveParameters(pubKey);
        keyPair.genKeyPair();
        pubKey.getW(bcPub, (short) 0);

        //SHA-256
        MessageDigest sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, true);
        sha256.doFinal(bcPub, (short) 0, (short) bcPub.length, sha, (short) 0);

        //RIPEMD-160
        Ripemd160.hash32(sha, (short) 0, ripemd160, (short) 0, scratch, (short) 0);

        //Add Network Byte (0x00 for Mainnet, 0x6F for Testnet)
        if (buffer[ISO7816.OFFSET_P1] == P1_MAINNET) {
            net[0] = 0x00;
        } else if(buffer[ISO7816.OFFSET_P1] == P1_TESTNET) {
            net[0] = 0x6F;
        } else {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }
        for (short i = 0 ; i < ripemd160.length ; i++){
            net[(short) (i+1)] = ripemd160[i];
        }

        //Double SHA-256
        sha256.doFinal(net, (short) 0, (short) net.length, sha, (short) 0);
        sha256.doFinal(sha, (short) 0, (short) sha.length, sha, (short) 0);

        //Append Checksum to RIPEMD-Hash
        for (short i = 0; i < net.length; i++){
            address[i] = net[i];
        }
        for (short i = 0; i < 4; i++){
            address[(short)(21 + i)] = sha[i];
        }

        this.initialized = 0x01;
    }

    /**
     * Returns the public key of this wallet
     * @param apdu
     */
    private void getPubKey(APDU apdu){
        byte[] buffer = apdu.getBuffer();
        short length = pubKey.getW(buffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, length);
    }

    /**
     * Returns the address of the wallet.
     * @param apdu
     */
    private void getAddr(APDU apdu){
        byte[] buffer = apdu.getBuffer();
        short length = (short) address.length;
        Util.arrayCopyNonAtomic(address, (short) 0, buffer, (short) 0, length);
        apdu.setOutgoingAndSend((short) 0, length);
    }

    /**
     * Returns the version of this wallet
     * @param apdu
     */
    private void getVersion(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short length = (short) version.length;
        Util.arrayCopyNonAtomic(version, (short) 0, buffer, (short) 0, length);
        apdu.setOutgoingAndSend((short) 0, length);
    }

    /**
     * Returns 1 if the card is connected via NFC and 0 otherwise
     * @param apdu
     */
    private void getConnectionMode(APDU apdu){
        byte[] buffer = apdu.getBuffer();
        buffer[0] = (byte) (isConnectedViaNFC() ? 1 : 0);
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

    /**
     * Returns the value of the initialized flag
     * @param apdu
     */
    private void getStatus(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        buffer[0] = this.initialized;
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

    /**
     * Returns the remaining PIN tries
     * @param apdu
     */
    private void getRemainingPINTries(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        buffer[0] = pin.getTriesRemaining();
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

    private boolean isConnectedViaNFC(){
        return (APDU.getProtocol() & APDU.PROTOCOL_MEDIA_MASK)
                == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A;
    }

}
