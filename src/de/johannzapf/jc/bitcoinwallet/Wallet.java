package de.johannzapf.jc.bitcoinwallet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.apdu.ExtendedLength;
import javacardx.crypto.Cipher;

public class Wallet extends Applet implements ExtendedLength {

    private static final byte[] version = {'2', '.', '0', '.', '0'};
    private static final byte CLA = (byte) 0x80;
    private static final byte INS_VERSION = (byte) 0x00;
    private static final byte INS_CONN_MODE = (byte) 0x01;
    private static final byte INS_STATUS = (byte) 0x02;

    private static final byte INS_INIT = (byte) 0x03;
    private static final byte INS_VERIFY_PIN = (byte) 0x04;

    private static final byte INS_GET_ADDR = (byte) 0x05;
    private static final byte INS_PAY = (byte) 0x06;

    private static final byte P1_MAINNET = (byte) 0x01;
    private static final byte P1_TESTNET = (byte) 0x02;


    private static final byte PIN_TRIES = (byte) 3;
    private static final byte PIN_SIZE = (byte) 4;

    private byte[] scratch;

    private byte initialized = (byte) 0x00;
    private byte[] address;
    private ECPrivateKey privKey;
    private ECPublicKey pubKey;

    private byte[] bcPub;
    private byte[] sha;
    private byte[] pubKeyHash;
    private byte[] net;

    private OwnerPIN pin;

    private Transaction tx;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new Wallet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    public Wallet(){
        this.scratch = JCSystem.makeTransientByteArray((short)256, JCSystem.CLEAR_ON_DESELECT);

        this.bcPub = new byte[65];
        this.sha = new byte[32];
        this.pubKeyHash = new byte[20];
        this.net = new byte[21];
        this.address = new byte[25];

        this.pin = new OwnerPIN(PIN_TRIES, PIN_SIZE);

        this.tx = new Transaction();
    }

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
            case INS_GET_ADDR:
                getAddr(apdu);
                break;
            case INS_PAY:
                manageTransaction(apdu);
                break;
            case INS_VERIFY_PIN:
                verifyPin(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void verifyPin(APDU apdu){

    }

    private void manageTransaction(APDU apdu){
        byte[] buffer = apdu.getBuffer();
        short bytes = apdu.setIncomingAndReceive();


        if((short)(bytes-37) % 58 != 0){
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        tx.parse(buffer, ISO7816.OFFSET_CDATA);
        byte[] finalTx = tx.getFinalTransaction(pubKeyHash, bcPub, privKey);
        short length = WalletUtil.getTransactionLength(finalTx);

        apdu.setOutgoing();
        apdu.setOutgoingLength(length);
        apdu.sendBytesLong(finalTx, (short) 0 , length);
    }

    private void initialize(APDU apdu){
        byte[] buffer = apdu.getBuffer();
        short bytes = apdu.setIncomingAndReceive();

        //Set PIN
        if(bytes != PIN_SIZE){
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        pin.update(buffer, ISO7816.OFFSET_CDATA, PIN_SIZE);

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
        Ripemd160.hash32(sha, (short) 0, pubKeyHash, (short) 0, scratch, (short) 0);

        //Add Network Byte (0x00 for Mainnet, 0x6F for Testnet)
        if (buffer[ISO7816.OFFSET_P1] == P1_MAINNET) {
            net[0] = 0x00;
        } else if(buffer[ISO7816.OFFSET_P1] == P1_TESTNET) {
            net[0] = 0x6F;
        } else {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }
        for (short i = 0; i < pubKeyHash.length ; i++){
            net[(short) (i+1)] = pubKeyHash[i];
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

    private void getAddr(APDU apdu){
        byte[] buffer = apdu.getBuffer();
        short length = (short) address.length;
        Util.arrayCopyNonAtomic(address, (short) 0, buffer, (short) 0, length);
        apdu.setOutgoingAndSend((short) 0, length);
    }

    private void getVersion(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short length = (short) version.length;
        Util.arrayCopyNonAtomic(version, (short) 0, buffer, (short) 0, length);
        apdu.setOutgoingAndSend((short) 0, length);
    }

    private void getConnectionMode(APDU apdu){
        byte[] buffer = apdu.getBuffer();
        buffer[0] = (byte) (((APDU.getProtocol() & APDU.PROTOCOL_MEDIA_MASK)
                == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A) ? 1 : 0);
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

    private void getStatus(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        buffer[0] = this.initialized;
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

}
