package de.johannzapf.jc.bitcoinwallet;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
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

    private MessageDigest sha256;
    private Signature sign;


    public Transaction(){
        sha = new byte[32];
        signature = new byte[72];
        targetAddressPKH = new byte[20];
        amount = new byte[8];
        change = new byte[8];
        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, true);
        sign = Signature.getInstance(MessageDigest.ALG_NULL, Signature.SIG_CIPHER_ECDSA, Cipher.PAD_NULL, true);
    }

    /**
     * Parses all relevant TX information from the data generated by the host
     * @param data
     * @param offset
     */
    public void parse(byte[] data, short offset){
        Util.arrayCopyNonAtomic(data, offset, this.targetAddressPKH, (short) 0, (short) 20);
        Util.arrayCopyNonAtomic(data, (short) (offset+20), this.amount, (short) 0, (short) 8);
        Util.arrayCopyNonAtomic(data, (short) (offset+28), this.change, (short) 0, (short) 8);

        this.utxoAmount = data[(short) (offset+36)];
        if(utxoAmount > 7){
            //We do not support transactions with more than seven inputs
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        this.transactionInputs = new TransactionInput[utxoAmount];
        for(short i = 0; i < utxoAmount; i++){
            transactionInputs[i] = new TransactionInput();
            transactionInputs[i].parse(data, (short) (offset+37+i*58));
        }
    }

    /**
     * Constructs a transaction
     * @param pubKeyHash
     * @param pubKey
     * @param privKey
     * @return
     */
    public byte[] getFinalTransaction(byte[] pubKeyHash, byte[] pubKey, ECPrivateKey privKey){
        sign.init(privKey, Signature.MODE_SIGN);

        //A standard transaction with one input is at most 180 + 80 = 260 bytes long
        //With every input transaction that is added, it grows by 180 bytes
        //However, it can be shorter than that, which is why the length is checked at the end with WalletUtil.getTransactionLength()
        byte[] transaction = new byte[(short)(this.utxoAmount * 180 + 80)];

        transaction[0] = 0x01; //Version
        transaction[4] = (byte) this.utxoAmount; //Number of Inputs

        short offset = 5;

        //Iterate over all input transactions (UTXOs)
        for(short i = 0; i < this.utxoAmount; i++){
            TransactionInput ti = this.transactionInputs[i];

            WalletUtil.reverseArrayCopy(ti.getPrevTxHash(), (short) 0, transaction, offset, (short) 32); //UTXO Hash
            transaction[(short)(offset + 32)] = ti.getPrevOutputIndex(); //UTXO Output index

            byte[] toSign = getDoubleHashedTx(pubKeyHash, i); //Retrieve SHA-256 Hash that needs to be signed

            //The actual Signature
            short sigLength = sign.sign(toSign, (short) 0, (short) 32, signature, (short) 0);
            sigLength += CryptoUtils.fixS(signature, (short) 0);

            transaction[(short)(offset + 36)] = (byte) (3 + sigLength + pubKey.length); //InScriptLength

            //ScriptSig
            transaction[(short)(offset + 37)] = (byte) (sigLength + 1);
            Util.arrayCopyNonAtomic(signature, (short) 0, transaction, (short) (offset + 38), sigLength);
            transaction[(short)(sigLength + offset + 38)] = 0x01;
            transaction[(short)(sigLength + offset + 39)] = (byte) pubKey.length;
            for(short j = 0; j < pubKey.length; j++){
                transaction[(short)(j + sigLength + offset + 40)] = pubKey[j];
            }

            fillSequence(transaction, (short)(sigLength + offset + 105)); //Sequence

            offset += 109 + sigLength;
        }

        fillOutputs(transaction, offset, pubKeyHash); //Outputs

        return transaction;
    }


    /**
     * Constructs the SHA-256 Hash that needs to be signed by ECDSA
     * @param senderPubKeyHash
     * @param txIndex index of the input transaction of which the ScriptSig is included
     * @return
     */
    private byte[] getDoubleHashedTx(byte[] senderPubKeyHash, short txIndex){
        //A standard toHash object with one input is 107 + 41 = 148 bytes long
        //With every input transaction that is added, it grows by 41 bytes
        byte[] toSign = new byte[(short)(107 + 41 * this.utxoAmount)];

        toSign[0] = 0x01; //Version

        toSign[4] = (byte) this.utxoAmount; //Number of inputs

        short offset = 5;

        //Iterate over all input transactions (UTXOs)
        for(short i = 0; i < utxoAmount; i++){
            TransactionInput ti = this.transactionInputs[i];

            WalletUtil.reverseArrayCopy(ti.getPrevTxHash(), (short) 0, toSign, offset, (short) 32); //UTXO Hash

            toSign[(short)(offset + 32)] = ti.getPrevOutputIndex(); //UTXO Output index

            if(i == txIndex){
                //If the UTXO index matches the param, ScriptSig is included.
                //This means that the resulting hash and signature will verify this UTXO

                toSign[(short)(offset + 36)] = (byte) ti.getOutputPubkey().length; //InScriptLength

                Util.arrayCopyNonAtomic(ti.getOutputPubkey(), (short) 0, toSign, (short) (offset + 37), (short) 25); //ScriptSig

                fillSequence(toSign, (short) (offset + 62)); //Sequence

                offset += 66;
            } else {
                //If the UTXO index doesn't match the param, we leave out the ScriptSig

                toSign[(short)(offset + 36)] = (byte) 0x00; //InScriptLength

                fillSequence(toSign, (short) (offset + 37)); //Sequence

                offset += 41;
            }
        }

        fillOutputs(toSign, offset, senderPubKeyHash); //Outputs

        toSign[(short)(offset + 73)] = 0x01; //Sig Hash Code

        //Double SHA-256 entire structure
        sha256.doFinal(toSign, (short) 0, (short) toSign.length, sha, (short) 0);
        sha256.doFinal(sha, (short) 0, (short) sha.length, sha, (short) 0);

        return sha;
    }

    /**
     * Takes a transaction and, starting from the offset, adds:
     *  - Number of outputs (always 2 in this case)
     *  - Output 1 Value
     *  - Output 1 Script Length
     *  - Output 1 Script
     *  - Output 2 Value
     *  - Output 2 Script Length
     *  - Output 2 Script
     * @param transaction
     * @param offset
     * @param pubKeyHash
     */
    private void fillOutputs(byte[] transaction, short offset, byte [] pubKeyHash){
        transaction[offset] = 0x02; //Number of outputs

        //Value of Output 1 (reversed)
        transaction[(short)(offset + 1)] = this.amount[7];
        transaction[(short)(offset + 2)] = this.amount[6];
        transaction[(short)(offset + 3)] = this.amount[5];
        transaction[(short)(offset + 4)] = this.amount[4];
        transaction[(short)(offset + 5)] = this.amount[3];
        transaction[(short)(offset + 6)] = this.amount[2];
        transaction[(short)(offset + 7)] = this.amount[1];
        transaction[(short)(offset + 8)] = this.amount[0];

        transaction[(short)(offset + 9)] = (byte) (this.targetAddressPKH.length + 5); //Output 1 Script Length

        //Output 1 Script
        Util.arrayCopyNonAtomic(constructScriptPubKey(targetAddressPKH), (short) 0, transaction,
                (short) (offset + 10), (short) 25);

        //Value of Output 2 (reversed)
        transaction[(short)(offset + 35)] = this.change[7];
        transaction[(short)(offset + 36)] = this.change[6];
        transaction[(short)(offset + 37)] = this.change[5];
        transaction[(short)(offset + 38)] = this.change[4];
        transaction[(short)(offset + 39)] = this.change[3];
        transaction[(short)(offset + 40)] = this.change[2];
        transaction[(short)(offset + 41)] = this.change[1];
        transaction[(short)(offset + 42)] = this.change[0];

        transaction[(short)(offset + 43)] = (byte) (pubKeyHash.length + 5); //Output 2 Script Length

        //Output 2 Script
        Util.arrayCopyNonAtomic(constructScriptPubKey(pubKeyHash),
                (short) 0, transaction, (short) (offset + 44), (short) 25);
    }

    /**
     * Fills the sequence part (FFFFFFFF) for a given transaction starting from the offset
     * @param transaction
     * @param offset
     */
    private void fillSequence(byte[] transaction, short offset){
        transaction[offset] = (byte) 0xff;
        transaction[(short)(offset + 1)] = (byte) 0xff;
        transaction[(short)(offset + 2)] = (byte) 0xff;
        transaction[(short)(offset + 3)] = (byte) 0xff;
    }


    /**
     * Builds a scriptPubKey from a given pubKeyHash
     * ab..xy --> 76a914ab..xy88ac
     * @param pubKeyHash
     * @return
     */
    private static byte[] constructScriptPubKey(byte[] pubKeyHash){
        short scriptLength = 25;
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

    public byte[] getAmount(){
        return this.amount;
    }
}
