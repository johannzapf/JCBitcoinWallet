package de.johannzapf.jc.bitcoinwallet;

public class WalletUtil {

    public static byte[] reverse(byte[] a){
        byte[] reversed = new byte[a.length];
        for(short i = 0; i < a.length; i++){
            reversed[i] = a[(short)(a.length-1-i)];
        }
        return reversed;
    }

    public static short getTransactionLength(byte[] transaction){
        short length = (short) transaction.length;

        short index = (short) (length-4);
        while(transaction[index] == 0x00){
            index--;
            length--;
        }
        return (short) (length+1);
    }
}
