package de.johannzapf.jc.bitcoinwallet;

import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.MessageDigest;
import javacard.security.Signature;
import javacardx.crypto.Cipher;


public class Transaction {

    private byte[] sha;
    private byte[] signature;

    private byte[] targetAddressPKH; // Pubkeyhash of target address
    private byte[] amount; // amount to spent (in satoshis)
    private byte[] change; // amount that goes back to address (in satoshis)

    private TransactionInput[] transactionInputs;

    private short utxoAmount;


    public Transaction(){
        sha = new byte[32];
        signature = new byte[72];
        targetAddressPKH = new byte[20];
        amount = new byte[8];
        change = new byte[8];
    }

    public void parse(byte[] data, short offset){
        //Parse Transaction;
        Util.arrayCopyNonAtomic(data, offset, this.targetAddressPKH, (short) 0, (short) 20);
        Util.arrayCopyNonAtomic(data, (short) (offset+20), this.amount, (short) 0, (short) 8);
        Util.arrayCopyNonAtomic(data, (short) (offset+28), this.change, (short) 0, (short) 8);

        this.utxoAmount = data[(short) (offset+36)];
        this.transactionInputs = new TransactionInput[utxoAmount];
        for(short i = 0; i < utxoAmount; i++){
            transactionInputs[i] = new TransactionInput();
            transactionInputs[i].parse(data, (short) (offset+37+i*58));
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
            TransactionInput ti = this.transactionInputs[i];
            Util.arrayCopyNonAtomic(WalletUtil.reverse(ti.getPrevTxHash()), (short) 0, transaction, offset, (short) 32); // Previous TX hash
            transaction[(short)(offset + 32)] = ti.getPrevOutputIndex(); // Previous Output index


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

        transaction[(short)(offset + 1)] = this.amount[7]; // Output 0 value
        transaction[(short)(offset + 2)] = this.amount[6];
        transaction[(short)(offset + 3)] = this.amount[5];
        transaction[(short)(offset + 4)] = this.amount[4];
        transaction[(short)(offset + 5)] = this.amount[3];
        transaction[(short)(offset + 6)] = this.amount[2];
        transaction[(short)(offset + 7)] = this.amount[1];
        transaction[(short)(offset + 8)] = this.amount[0];

        transaction[(short)(offset + 9)] = (byte) (this.targetAddressPKH.length + 5); //Output Script 0 length
        Util.arrayCopyNonAtomic(constructScriptPubKey(targetAddressPKH, (short) (targetAddressPKH.length + 5))
                , (short) 0, transaction, (short) (offset + 10), (short) 25); //Output Script 1

        transaction[(short)(offset + 35)] = this.change[7]; // Output 1 value
        transaction[(short)(offset + 36)] = this.change[6];
        transaction[(short)(offset + 37)] = this.change[5];
        transaction[(short)(offset + 38)] = this.change[4];
        transaction[(short)(offset + 39)] = this.change[3];
        transaction[(short)(offset + 40)] = this.change[2];
        transaction[(short)(offset + 41)] = this.change[1];
        transaction[(short)(offset + 42)] = this.change[0];

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
            TransactionInput ti = this.transactionInputs[i];
            Util.arrayCopyNonAtomic(WalletUtil.reverse(ti.getPrevTxHash()), (short) 0, toSign, offset, (short) 32); // Previous TX hash
            toSign[(short)(offset + 32)] = ti.getPrevOutputIndex(); // Previous Output index
            if(i == round){
                toSign[(short)(offset + 36)] = (byte) ti.getOutputPubkey().length; // InScriptLength
                Util.arrayCopyNonAtomic(ti.getOutputPubkey(), (short) 0, toSign, (short) (offset + 37), (short) 25); // ScriptSig
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

        toSign[(short)(offset + 1)] = this.amount[7]; // Output 0 value
        toSign[(short)(offset + 2)] = this.amount[6];
        toSign[(short)(offset + 3)] = this.amount[5];
        toSign[(short)(offset + 4)] = this.amount[4];
        toSign[(short)(offset + 5)] = this.amount[3];
        toSign[(short)(offset + 6)] = this.amount[2];
        toSign[(short)(offset + 7)] = this.amount[1];
        toSign[(short)(offset + 8)] = this.amount[0];

        toSign[(short)(offset + 9)] = (byte) (this.targetAddressPKH.length + 5); //Output Script 0 length
        Util.arrayCopyNonAtomic(constructScriptPubKey(targetAddressPKH, (short) (targetAddressPKH.length + 5))
                , (short) 0, toSign, (short) (offset + 10), (short) 25); //Output Script 1

        toSign[(short)(offset + 35)] = this.change[7]; // Output 1 value
        toSign[(short)(offset + 36)] = this.change[6];
        toSign[(short)(offset + 37)] = this.change[5];
        toSign[(short)(offset + 38)] = this.change[4];
        toSign[(short)(offset + 39)] = this.change[3];
        toSign[(short)(offset + 40)] = this.change[2];
        toSign[(short)(offset + 41)] = this.change[1];
        toSign[(short)(offset + 42)] = this.change[0];

        toSign[(short)(offset + 43)] = (byte) (senderPubKeyHash.length + 5); //Output Script 1 length
        Util.arrayCopyNonAtomic(constructScriptPubKey(senderPubKeyHash, (short) (senderPubKeyHash.length + 5)),
                (short) 0, toSign, (short) (offset + 44), (short) 25); //Output Script 1

        toSign[(short)(offset + 73)] = 0x01; //Sig Hash Code;

        MessageDigest sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, true);
        sha256.doFinal(toSign, (short) 0, (short) toSign.length, sha, (short) 0);
        sha256.doFinal(sha, (short) 0, (short) sha.length, sha, (short) 0);

        return sha;
    }


    private static byte[] constructScriptPubKey(byte[] pubKeyHash, short scriptLength){
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
