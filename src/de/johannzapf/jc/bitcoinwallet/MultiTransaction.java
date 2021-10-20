package de.johannzapf.jc.bitcoinwallet;

import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.MessageDigest;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

import static de.johannzapf.jc.bitcoinwallet.Transaction.constructScriptPubKey;

public class MultiTransaction {
    private byte[] sha;
    private byte[] signature;

    private byte[] arg0; // Pubkeyhash of target address
    private byte[] arg1; // amount to spent (in satoshis)
    private byte[] arg2; // change (in satoshis)

    private TransactionInput[] arg3;

    private short utxoAmount;


    public MultiTransaction(){
        sha = new byte[32];
        signature = new byte[72];
        arg0 = new byte[20];
        arg1 = new byte[8];
        arg2 = new byte[8];
    }

    public void parse(byte[] data, short offset){
        //Parse Transaction;
        Util.arrayCopyNonAtomic(data, offset, this.arg0, (short) 0, (short) 20);
        Util.arrayCopyNonAtomic(data, (short) (offset+20), this.arg1, (short) 0, (short) 8);
        Util.arrayCopyNonAtomic(data, (short) (offset+28), this.arg2, (short) 0, (short) 8);

        this.utxoAmount = data[(short) (offset+36)];
        this.arg3 = new TransactionInput[utxoAmount];
        for(short i = 0; i < utxoAmount; i++){
            arg3[i] = new TransactionInput();
            arg3[i].parse(data, (short) (offset+37+i*58));
        }
    }

    public byte[] getFinalTransaction(byte[] pubKeyHash, byte[] pubKey, ECPrivateKey privKey){
        Signature sign = Signature.getInstance(MessageDigest.ALG_NULL, Signature.SIG_CIPHER_ECDSA, Cipher.PAD_NULL, true);
        sign.init(privKey, Signature.MODE_SIGN);

        byte[] transaction = new byte[(short)(this.utxoAmount * 180 + 80)];

        transaction[0] = 0x01; //version
        transaction[4] = (byte) this.utxoAmount; //number of inputs

        short offset = 5;


        // Inputs
        for(short i = 0; i < this.utxoAmount; i++){
            TransactionInput ti = this.arg3[i];
            Util.arrayCopyNonAtomic(WalletUtil.reverse(ti.getArg3B()), (short) 0, transaction, offset, (short) 32); // Previous TX hash
            transaction[(short)(offset + 32)] = ti.getArg3A(); // Previous Output index


            byte[] toSign = getDoubleHashedTx(pubKeyHash, i);

            short sigLength;
            do {
                sigLength = sign.sign(toSign, (short) 0, (short) 32, signature, (short) 0);
            } while (!CryptoUtils.checkS(signature));

            transaction[(short)(offset + 36)] = (byte) (3 + sigLength + pubKey.length); // InScriptLength


            //ScriptSig
            transaction[(short)(offset + 37)] = (byte) (sigLength + 1);
            Util.arrayCopyNonAtomic(signature, (short) 0, transaction, (short) (offset + 38), sigLength);
            transaction[(short)(sigLength + offset + 38)] = 0x01;
            transaction[(short)(sigLength + offset + 39)] = (byte) pubKey.length;

            for(short j = 0; j < pubKey.length; j++){
                transaction[(short)(j + sigLength + offset + 40)] = pubKey[j];
            }

            transaction[(short)(sigLength + offset + 105)] = (byte) 0xff; // Sequence
            transaction[(short)(sigLength + offset + 106)] = (byte) 0xff;
            transaction[(short)(sigLength + offset + 107)] = (byte) 0xff;
            transaction[(short)(sigLength + offset + 108)] = (byte) 0xff;
            offset += 109 + sigLength;
        }

        transaction[offset] = 0x02; // Number of outputs

        transaction[(short)(offset + 1)] = this.arg1[7]; // Output 0 value
        transaction[(short)(offset + 2)] = this.arg1[6];
        transaction[(short)(offset + 3)] = this.arg1[5];
        transaction[(short)(offset + 4)] = this.arg1[4];
        transaction[(short)(offset + 5)] = this.arg1[3];
        transaction[(short)(offset + 6)] = this.arg1[2];
        transaction[(short)(offset + 7)] = this.arg1[1];
        transaction[(short)(offset + 8)] = this.arg1[0];

        transaction[(short)(offset + 9)] = (byte) (this.arg0.length + 5); //Output Script 0 length
        Util.arrayCopyNonAtomic(constructScriptPubKey(arg0, (short) (arg0.length + 5))
                , (short) 0, transaction, (short) (offset + 10), (short) 25); //Output Script 1

        transaction[(short)(offset + 35)] = this.arg2[7]; // Output 1 value
        transaction[(short)(offset + 36)] = this.arg2[6];
        transaction[(short)(offset + 37)] = this.arg2[5];
        transaction[(short)(offset + 38)] = this.arg2[4];
        transaction[(short)(offset + 39)] = this.arg2[3];
        transaction[(short)(offset + 40)] = this.arg2[2];
        transaction[(short)(offset + 41)] = this.arg2[1];
        transaction[(short)(offset + 42)] = this.arg2[0];

        transaction[(short)(offset + 43)] = (byte) (pubKeyHash.length + 5); //Output Script 1 length
        Util.arrayCopyNonAtomic(constructScriptPubKey(pubKeyHash, (short) (pubKeyHash.length + 5)),
                (short) 0, transaction, (short) (offset + 44), (short) 25); //Output Script 1


        return transaction;
    }


    public byte[] getDoubleHashedTx(byte[] senderPubKeyHash, short round){
        byte[] toSign = new byte[(short)(107 + 41 * this.utxoAmount)];

        toSign[0] = 0x01; //version
        toSign[4] = (byte) this.utxoAmount; //number of inputs

        short offset = 5;

        for(short i = 0; i < utxoAmount; i++){
            TransactionInput ti = this.arg3[i];
            Util.arrayCopyNonAtomic(WalletUtil.reverse(ti.getArg3B()), (short) 0, toSign, offset, (short) 32); // Previous TX hash
            toSign[(short)(offset + 32)] = ti.getArg3A(); // Previous Output index
            if(i == round){
                toSign[(short)(offset + 36)] = (byte) ti.getArg3C().length; // InScriptLength
                Util.arrayCopyNonAtomic(ti.getArg3C(), (short) 0, toSign, (short) (offset + 37), (short) 25); // ScriptSig
                toSign[(short)(offset + 62)] = (byte) 0xff; // Sequence
                toSign[(short)(offset + 63)] = (byte) 0xff;
                toSign[(short)(offset + 64)] = (byte) 0xff;
                toSign[(short)(offset + 65)] = (byte) 0xff;
                offset += 66;
            } else {
                toSign[(short)(offset + 36)] = (byte) 0x00; // InScriptLength
                toSign[(short)(offset + 37)] = (byte) 0xff; // Sequence
                toSign[(short)(offset + 38)] = (byte) 0xff;
                toSign[(short)(offset + 39)] = (byte) 0xff;
                toSign[(short)(offset + 40)] = (byte) 0xff;
                offset += 41;
            }
        }

        toSign[offset] = 0x02; // Number of outputs

        toSign[(short)(offset + 1)] = this.arg1[7]; // Output 0 value
        toSign[(short)(offset + 2)] = this.arg1[6];
        toSign[(short)(offset + 3)] = this.arg1[5];
        toSign[(short)(offset + 4)] = this.arg1[4];
        toSign[(short)(offset + 5)] = this.arg1[3];
        toSign[(short)(offset + 6)] = this.arg1[2];
        toSign[(short)(offset + 7)] = this.arg1[1];
        toSign[(short)(offset + 8)] = this.arg1[0];

        toSign[(short)(offset + 9)] = (byte) (this.arg0.length + 5); //Output Script 0 length
        Util.arrayCopyNonAtomic(constructScriptPubKey(arg0, (short) (arg0.length + 5))
                , (short) 0, toSign, (short) (offset + 10), (short) 25); //Output Script 1

        toSign[(short)(offset + 35)] = this.arg2[7]; // Output 1 value
        toSign[(short)(offset + 36)] = this.arg2[6];
        toSign[(short)(offset + 37)] = this.arg2[5];
        toSign[(short)(offset + 38)] = this.arg2[4];
        toSign[(short)(offset + 39)] = this.arg2[3];
        toSign[(short)(offset + 40)] = this.arg2[2];
        toSign[(short)(offset + 41)] = this.arg2[1];
        toSign[(short)(offset + 42)] = this.arg2[0];

        toSign[(short)(offset + 43)] = (byte) (senderPubKeyHash.length + 5); //Output Script 1 length
        Util.arrayCopyNonAtomic(constructScriptPubKey(senderPubKeyHash, (short) (senderPubKeyHash.length + 5)),
                (short) 0, toSign, (short) (offset + 44), (short) 25); //Output Script 1

        toSign[(short)(offset + 73)] = 0x01; //Sig Hash Code;

        MessageDigest sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, true);
        sha256.doFinal(toSign, (short) 0, (short) toSign.length, sha, (short) 0);
        sha256.doFinal(sha, (short) 0, (short) sha.length, sha, (short) 0);




        return sha;
    }
}
