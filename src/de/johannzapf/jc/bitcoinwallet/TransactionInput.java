package de.johannzapf.jc.bitcoinwallet;

import javacard.framework.JCSystem;
import javacard.framework.Util;

public class TransactionInput {

    private byte prevOutputIndex; // previous output index
    private byte[] prevTxHash; // previous tx hash
    private byte[] outputPubkey; // outputpubkey

    /**
     * The default constructor allocates the needed memory
     */
    public TransactionInput(){
        prevTxHash = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
        outputPubkey = JCSystem.makeTransientByteArray((short) 25, JCSystem.CLEAR_ON_DESELECT);
    }

    /**
     * Parses the given data into a TransactionInput object.
     * @param data
     * @param offset
     */
    public void parse(byte[] data, short offset){
        this.prevOutputIndex = data[offset];
        Util.arrayCopyNonAtomic(data, (short) (offset+1), this.prevTxHash, (short) 0, (short) 32);
        Util.arrayCopyNonAtomic(data, (short) (offset+33), this.outputPubkey, (short) 0, (short) 25);
    }

    public byte getPrevOutputIndex() {
        return prevOutputIndex;
    }

    public byte[] getPrevTxHash() {
        return prevTxHash;
    }

    public byte[] getOutputPubkey() {
        return outputPubkey;
    }
}
