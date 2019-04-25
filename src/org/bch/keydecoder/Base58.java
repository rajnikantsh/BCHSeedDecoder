package org.bch.keydecoder;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

public class Base58 {

    private static BigInteger bi_58 = new BigInteger("58");
    private static BigInteger bi_256 = new BigInteger("256");

    public static String base_decode_58(String v) {

        // This method using to decode a string for base58.
        byte[] vBytes = v.getBytes();
        BigInteger long_value = BigInteger.ZERO;

        for (int counter = 0; counter < vBytes.length; counter++) {
            int ccc = Util.unsignedToBytes(vBytes[vBytes.length - counter -1]);
            int charpos = Util.BASE_58_CHARS.indexOf(ccc);
            BigInteger bi_charpos = BigInteger.valueOf(charpos);
            long_value = long_value.add(bi_58.pow(counter).multiply(bi_charpos));

        }

        StringBuilder result = new StringBuilder();
        // Main decoding loop

        while (long_value.compareTo(bi_256) > -1) {
            BigInteger[] divMod = long_value.divideAndRemainder(bi_256);
            long_value = divMod[0];
            String modhex = divMod[1].toString(16);
            // ensure hexbyte contains leading 0 if necessary.
            if (modhex.length() == 1) {
                result.append("0");
            }
            result.append(modhex);
        }

        if (long_value.toString().length() == 1) {
            result.append("0");
        }
        result.append(long_value.toString());

        // Extra zero padding if necessary.
        Byte oneByte = 1;
        for(int nPad = 0; oneByte.compareTo(vBytes[nPad]) == 0; nPad++){
            result.append("00");
        }

        byte[] finalBytes = Util.hexStringToByteArray(result.toString());

        // REVERSE IN PLACE
        for (int i = 0; i < finalBytes.length / 2; i++) {
            byte temp = finalBytes[i];
            finalBytes[i] = finalBytes[finalBytes.length - i - 1];
            finalBytes[finalBytes.length - i - 1] = temp;
        }

        String data = Util.bytesToHex(finalBytes);
        return data.substring(0, (data.length() - 8));

    }

    public static String base_encode_58(String v) throws NoSuchAlgorithmException {

        // This method is used to encode a string for base58.
        String suffixHash = Util.Hash(v);
        byte[] vBytes = new BigInteger(v, 16).toByteArray();

        BigInteger long_value = BigInteger.ZERO;
        byte[] zz = new BigInteger(v + suffixHash.substring(0, 8), 16).toByteArray();

        // First prepare main variable "long_value"
        for (int counter = 0; counter < zz.length; counter++) {

            int ccc = Util.unsignedToBytes(zz[zz.length - counter - 1]);
            BigInteger cc = BigInteger.valueOf(ccc);
            long_value = long_value.add(bi_256.pow(counter).multiply(cc));
        }

        StringBuilder retval = new StringBuilder();

        // Main encoding loop
        while (long_value.compareTo(bi_58) > -1) {
            BigInteger[] divMod = long_value.divideAndRemainder(bi_58);
            long_value = divMod[0];
            retval.append(Util.BASE_58_CHARS.substring(divMod[1].intValue(), divMod[1].intValue() + 1));
        }

        retval.append(Util.BASE_58_CHARS.substring(long_value.intValue(), long_value.intValue() + 1));
        for(int nPad = 0; vBytes[nPad] == 0 ; nPad++){
            retval.append("0");
        }

        return retval.reverse().toString();
    }
}
