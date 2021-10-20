package de.johannzapf.jc.bitcoinwallet;


import javacard.framework.Util;
import javacard.security.MessageDigest;

public class Transaction {

    private byte[] toSign;
    private byte[] sha;

    private byte[] arg0; // Pubkeyhash of target address
    private byte[] arg1; // amount to spent (in satoshis)
    private byte[] arg2; // change (in satoshis)
    private byte arg3A; // previous output index
    private byte[] arg3B; // previous tx hash
    private byte[] arg3C; // outputpubkey

    public Transaction(){
        toSign = new byte[148];
        sha = new byte[32];
        arg0 = new byte[20];
        arg1 = new byte[8];
        arg2 = new byte[8];
        arg3B = new byte[32];
        arg3C = new byte[25];
    }

    public void parse(byte[] data, short offset){
        //Parse Transaction;
        Util.arrayCopyNonAtomic(data, offset, this.arg0, (short) 0, (short) 20);
        Util.arrayCopyNonAtomic(data, (short) (offset+20), this.arg1, (short) 0, (short) 8);
        Util.arrayCopyNonAtomic(data, (short) (offset+28), this.arg2, (short) 0, (short) 8);
        this.arg3A = data[(short) (offset+37)];
        Util.arrayCopyNonAtomic(data, (short) (offset+38), this.arg3B, (short) 0, (short) 32);
        Util.arrayCopyNonAtomic(data, (short) (offset+70), this.arg3C, (short) 0, (short) 25);
    }

    public byte[] getFinalTransaction(byte[] signature, short sigLength, byte[] pubKey){
        //The part of the transaction length that varies
        short offset = (short) (sigLength + 45 + pubKey.length);

        byte[] transaction = new byte[(short)(offset+77)];


        Util.arrayCopyNonAtomic(toSign, (short) 0, transaction, (short) 0, (short) 38); //version, number of inputs, previous TX, output index

        short scriptLength = (short) (3 + sigLength + pubKey.length);
        transaction[41] = (byte) scriptLength; // InScriptLength

        //ScriptSig
        transaction[42] = (byte) (sigLength + 1);
        for(short i = 0; i < sigLength; i++){
            transaction[(short) (i+43)] = signature[i];
        }
        transaction[(short)(sigLength+43)] = 0x01;
        transaction[(short)(sigLength+44)] = (byte) pubKey.length;

        for(short i = 0; i < pubKey.length; i++){
            transaction[(short)(sigLength+45+i)] = pubKey[i];
        }

        Util.arrayCopyNonAtomic(toSign, (short) 67, transaction, offset, (short) 77);

        return transaction;
    }


    public byte[] getDoubleHashedTx(byte[] senderPubKeyHash){
        toSign[0] = 0x01; //version
        toSign[4] = 0x01; //number of inputs
        Util.arrayCopyNonAtomic(WalletUtil.reverse(arg3B), (short) 0, toSign, (short) 5, (short) 32); // Previous TX hash
        toSign[37] = arg3A; // Previous Output index
        toSign[41] = (byte) arg3C.length; // InScriptLength
        Util.arrayCopyNonAtomic(arg3C, (short) 0, toSign, (short) 42, (short) 25); // ScriptSig

        toSign[67] = (byte) 0xff; // Sequence
        toSign[68] = (byte) 0xff;
        toSign[69] = (byte) 0xff;
        toSign[70] = (byte) 0xff;

        toSign[71] = 0x02; // Number of outputs

        toSign[72] = this.arg1[7]; // Output 0 value
        toSign[73] = this.arg1[6];
        toSign[74] = this.arg1[5];
        toSign[75] = this.arg1[4];
        toSign[76] = this.arg1[3];
        toSign[77] = this.arg1[2];
        toSign[78] = this.arg1[1];
        toSign[79] = this.arg1[0];

        toSign[80] = (byte) (this.arg0.length + 5); //Output Script 0 length
        Util.arrayCopyNonAtomic(constructScriptPubKey(arg0, (short) (arg0.length + 5))
                , (short) 0, toSign, (short) 81, (short) 25); //Output Script 1

        toSign[106] = this.arg2[7]; // Output 1 value
        toSign[107] = this.arg2[6];
        toSign[108] = this.arg2[5];
        toSign[109] = this.arg2[4];
        toSign[110] = this.arg2[3];
        toSign[111] = this.arg2[2];
        toSign[112] = this.arg2[1];
        toSign[113] = this.arg2[0];

        toSign[114] = (byte) (senderPubKeyHash.length + 5); //Output Script 1 length
        Util.arrayCopyNonAtomic(constructScriptPubKey(senderPubKeyHash, (short) (senderPubKeyHash.length + 5)),
                (short) 0, toSign, (short) 115, (short) 25); //Output Script 1

        toSign[144] = 0x01; //Sig Hash Code;

        MessageDigest sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, true);
        sha256.doFinal(toSign, (short) 0, (short) toSign.length, sha, (short) 0);
        sha256.doFinal(sha, (short) 0, (short) sha.length, sha, (short) 0);

        return sha;
    }

    public static byte[] constructScriptPubKey(byte[] pubKeyHash, short scriptLength){
        byte[] scriptPubKey = new byte[scriptLength];
        scriptPubKey[0] = (byte) 0x76;
        scriptPubKey[1] = (byte) 0xa9;
        scriptPubKey[2] = (byte) 0x14;
        for(byte b = 0; b < pubKeyHash.length; b++){
            scriptPubKey[(short)(3+b)] = pubKeyHash[b];
        }
        scriptPubKey[(short)(scriptLength-2)] = (byte) 0x88;
        scriptPubKey[(short)(scriptLength-1)] = (byte) 0xac;

        return scriptPubKey;
    }


}
