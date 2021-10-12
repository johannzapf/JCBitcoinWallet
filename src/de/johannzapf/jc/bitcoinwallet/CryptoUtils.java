package de.johannzapf.jc.bitcoinwallet;

public class CryptoUtils {

    private static final byte[] MAX_S = { (byte) 0x7F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0x5D, (byte) 0x57, (byte) 0x6E, (byte) 0x73, (byte) 0x57, (byte) 0xA4,
            (byte) 0x50, (byte) 0x1D, (byte) 0xDF, (byte) 0xE9, (byte) 0x2F, (byte) 0x46, (byte) 0x68, (byte) 0x1B,
            (byte) 0x20, (byte) 0xA0 };


    /**
     * Checks whether the s value of the given signature is smaller than N/2
     * @param signature
     * @return true if signature is OK, false otherwise
     */
    public static boolean checkS(byte[] signature){
        //Extract S value from DER encoded signature
        byte rlength = signature[3];
        byte slength = signature[5 + rlength];
        byte[] s = new byte[slength];
        short j = 0;
        for(short i = (short) (6 + rlength); i < (short)(6 + rlength + slength); i++){
            s[j++] = signature[i];
        }

        //Remove possible 0-padding from S value
        while (s[0] == 0x00) {
            byte[] newS = new byte[slength-1];
            for(short i = 0; i < (short)(slength-1); i++){
                newS[i] = s[(short)(i+1)];
            }
            s = newS;
        }

        //If S value has less bytes than MAX_S we are finished
        if(s.length < MAX_S.length){
            return true;
        }

        //Bitwise comparison of S value with MAX_S
        for(short i = 0; i < (short)(s.length); i++){
            if ((s[i] & 0xff) > (MAX_S[i] & 0xff)){
                return false;
            } else if ((s[i] & 0xff) < (MAX_S[i] & 0xff)){
                return true;
            }
        }

        //If S equals MAX_S we return true
        return true;
    }


}
