package de.johannzapf.jc.bitcoinwallet;


public class WalletUtil {

    public static byte[] contactlessLimit = {0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x0d, 0x40}; // 0.002 BTC

    /**
     * Copies the in array from the inOffset to the out array from the outOffset for length bytes in reverse order.
     * @param in
     * @param inOffset
     * @param out
     * @param outOffset
     * @param length
     */
    public static void reverseArrayCopy(byte[] in, short inOffset, byte[] out, short outOffset, short length){
        for(short s = 0; s < length; s++){
            out[(short) (outOffset+s)] = in[(short) (inOffset+length-s-1)];
        }
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
