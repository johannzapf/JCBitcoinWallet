package de.johannzapf.jc.bitcoinwallet;

import javacard.framework.JCSystem;

public class WalletUtil {

    public static byte[] contactlessLimit = {0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x0d, 0x40}; // 0.002 BTC

    /**
     * Reverses a given byte array
     * @param a
     * @return
     */
    public static byte[] reverse(byte[] a){
        byte[] reversed = JCSystem.makeTransientByteArray((short) a.length, JCSystem.CLEAR_ON_DESELECT);
        for(short i = 0; i < a.length; i++){
            reversed[i] = a[(short)(a.length-1-i)];
        }
        return reversed;
    }

    /**
     * Gets the length of a transaction.
     * @param transaction
     * @return
     */
    public static short getTransactionLength(byte[] transaction){
        //In our case, every TX ends on (00, 00, 00, 00) (Locktime), but the last byte before that is always 'ac',
        //so we can just check if there are more 0s

        short length = (short) transaction.length;

        short index = (short) (length-4);
        while(transaction[index] == 0x00){
            index--;
            length--;
        }
        return (short) (length+1);
    }

    public static boolean isHigherThanContactlessLimit(byte[] amount){
        if(amount.length != 8){
            return true;
        }
        for(short i = 0; i < 8; i++){
            if(amount[i] > contactlessLimit[i]){
                return true;
            } else if(amount[i] < contactlessLimit[i]){
                return false;
            }
        }
        return false;
    }
}
