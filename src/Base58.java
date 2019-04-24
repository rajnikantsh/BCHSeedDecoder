import java.math.BigInteger;

public class Base58 {

    public static final char[] ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray();

    public static String base_decode_58(String v) {

        // This method using to decode a string for base58.

        BigInteger bi_58 = new BigInteger("58");
        BigInteger bi_256 = new BigInteger("256");

        String b58chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

        byte[] vBytes = v.getBytes();

        BigInteger val1 = BigInteger.ZERO;
        BigInteger val2 = BigInteger.ZERO;
        BigInteger long_value = BigInteger.ZERO;

        BigInteger cc = BigInteger.ZERO;

        int c = 0;
        int charpos = 0;
        int i = 0;
        BigInteger bi_charpos = BigInteger.ZERO;
        int kounter = vBytes.length - 1;
        int kkk = Util.unsignedToBytes(vBytes[kounter]);

        for (int counter = vBytes.length - 1; counter >= 0; counter--) {
            c = vBytes[counter];
            int ccc = Util.unsignedToBytes(vBytes[counter]);
            cc = BigInteger.valueOf(ccc);
            charpos = b58chars.indexOf(ccc);
            bi_charpos = BigInteger.valueOf(charpos);
            val1 = bi_58.pow(i);
            i++;
            val2 = val1.multiply(bi_charpos);
            long_value = long_value.add(val2);

        }

        BigInteger[] divMod = null;
        BigInteger div = null;
        BigInteger mod = null;
        String result = "";
        String modhex = "";

        // Main decoding loop

        while (long_value.compareTo(bi_256) > -1) {
            divMod = long_value.divideAndRemainder(bi_256);
            div = divMod[0];
            mod = divMod[1];

            modhex = Integer.toHexString(mod.intValue());

            // ensure hexbyte contains leading 0 if necessary.
            if (modhex.length() == 1) {
                modhex = "0" + modhex;
            }

            result = result + modhex;

            long_value = div;
        }
        String long_value_string = long_value.toString();
        if (long_value_string.length() == 1) {
            long_value_string = "0" + long_value_string;
        }
        result = result + long_value_string;

        // Extra zero padding if necessary.
        Byte oneByte = new Byte("1");
        boolean has_leading_zeroes = true;
        int nPad = 0;
        Byte myByte;
        while (has_leading_zeroes) {
            myByte = vBytes[nPad];
            if (myByte.compareTo(oneByte) == 0) {
                nPad++;
            } else {
                has_leading_zeroes = false;
            }

        } // end while

        for (int n = 0; n < nPad; n++) {
            result = result + "00";
        }

        byte[] finalBytes = Util.hexStringToByteArray(result);

        // REVERSE IN PLACE
        for (i = 0; i < finalBytes.length / 2; i++) {
            byte temp = finalBytes[i];
            finalBytes[i] = finalBytes[finalBytes.length - i - 1];
            finalBytes[finalBytes.length - i - 1] = temp;
        }
        // END REVERSE CODE

        result = Util.bytesToHex(finalBytes);
        result = result.substring(0, (result.length() - 8));
        return result;

    }

    public static String base_encode_58(String v) {

        // This method is used to encode a string for base58.

        BigInteger bi_58 = new BigInteger("58");
        BigInteger bi_256 = new BigInteger("256");
        String suffixHash = Util.Hash(v);
        byte[] vBytes = new BigInteger(v, 16).toByteArray();

        v = v + suffixHash.substring(0, 8);
        int i = 0;
        BigInteger val1 = BigInteger.ZERO;
        BigInteger val2 = BigInteger.ZERO;
        BigInteger long_value = BigInteger.ZERO;
        BigInteger cc = BigInteger.ZERO;
        byte[] zz = new BigInteger(v, 16).toByteArray();

        // First prepare main variable "long_value"
        for (int counter = zz.length - 1; counter >= 0; counter--) {

            int ccc = Util.unsignedToBytes(zz[counter]);
            cc = BigInteger.valueOf(ccc);
            val1 = bi_256.pow(i);
            val2 = val1.multiply(cc);
            long_value = long_value.add(val2);
            i++;
        }

        BigInteger[] divMod = null;
        BigInteger div = null;
        BigInteger mod = null;
        String mychar = "";
        String result = "";

        // Main encoding loop
        while (long_value.compareTo(bi_58) > -1) {
            divMod = long_value.divideAndRemainder(bi_58);
            div = divMod[0];
            mod = divMod[1];
            mychar = Util.BASE_58_CHARS.substring(mod.intValue(), mod.intValue() + 1);
            result = result + mychar;
            long_value = div;
        }

        // handle final character
        mychar = Util.BASE_58_CHARS.substring(long_value.intValue(), long_value.intValue() + 1);
        result = result + mychar;

        // Extra zero padding if necessary.
        byte zeroByte = Byte.parseByte("0");
        boolean has_leading_zeroes = true;
        int nPad = 0;
        byte myByte;
        while (has_leading_zeroes) {
            myByte = vBytes[nPad];
            if (myByte == zeroByte) {
                nPad++;
            } else {
                has_leading_zeroes = false;
            }

        } // end while

        for (int n = 0; n < nPad; n++) {
            result = result + "0";
        }

        StringBuffer retval = new StringBuffer();
        retval.append(result);
        retval = retval.reverse();
        return retval.toString();
    }
}
