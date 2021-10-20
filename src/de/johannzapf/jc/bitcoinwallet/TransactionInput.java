package de.johannzapf.jc.bitcoinwallet;

import javacard.framework.Util;

public class TransactionInput {

    private byte arg3A; // previous output index
    private byte[] arg3B; // previous tx hash
    private byte[] arg3C; // outputpubkey

    public TransactionInput(){
        arg3B = new byte[32];
        arg3C = new byte[25];
    }

    public void parse(byte[] data, short offset){
        this.arg3A = data[offset];
        Util.arrayCopyNonAtomic(data, (short) (offset+1), this.arg3B, (short) 0, (short) 32);
        Util.arrayCopyNonAtomic(data, (short) (offset+33), this.arg3C, (short) 0, (short) 25);
    }

    public byte getArg3A() {
        return arg3A;
    }

    public byte[] getArg3B() {
        return arg3B;
    }

    public byte[] getArg3C() {
        return arg3C;
    }
}
