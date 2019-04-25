import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

public class Base58 {

    private static BigInteger bi_58 = new BigInteger("58");
    private static BigInteger bi_256 = new BigInteger("256");

    public static String base_decode_58(String v) {

        // This method using to decode a string for base58.

        byte[] vBytes = v.getBytes();

        BigInteger val1, val2;
        BigInteger long_value = BigInteger.ZERO;

        for (int counter = 0; counter < vBytes.length; counter++) {
            int ccc = Util.unsignedToBytes(vBytes[vBytes.length - counter -1]);
            int charpos = Util.BASE_58_CHARS.indexOf(ccc);
            BigInteger bi_charpos = BigInteger.valueOf(charpos);
            val1 = bi_58.pow(counter);
            val2 = val1.multiply(bi_charpos);
            long_value = long_value.add(val2);

        }

        BigInteger[] divMod;
        BigInteger div, mod;
        StringBuilder result = new StringBuilder();
        String modhex;

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

            result.append(modhex);
            long_value = div;
        }
        String long_value_string = long_value.toString();
        if (long_value_string.length() == 1) {
            long_value_string = "0" + long_value_string;
        }
        result.append(long_value_string);

        // Extra zero padding if necessary.
        Byte oneByte = new Byte("1");
        boolean has_leading_zeroes = true;
        int nPad = 0;
        while (has_leading_zeroes) {
            if (oneByte.compareTo(vBytes[nPad]) == 0) {
                nPad++;
                result.append("00");
            } else {
                has_leading_zeroes = false;
            }
        } // end while


        byte[] finalBytes = Util.hexStringToByteArray(result.toString());

        // REVERSE IN PLACE
        for (int i = 0; i < finalBytes.length / 2; i++) {
            byte temp = finalBytes[i];
            finalBytes[i] = finalBytes[finalBytes.length - i - 1];
            finalBytes[finalBytes.length - i - 1] = temp;
        }
        // END REVERSE CODE

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
            BigInteger val1 = bi_256.pow(counter);
            BigInteger val2 = val1.multiply(cc);
            long_value = long_value.add(val2);
        }

        BigInteger[] divMod;
        BigInteger div, mod;
        //String result = "";
        StringBuilder retval = new StringBuilder();

        // Main encoding loop
        while (long_value.compareTo(bi_58) > -1) {
            divMod = long_value.divideAndRemainder(bi_58);
            div = divMod[0];
            mod = divMod[1];
            retval.append(Util.BASE_58_CHARS.substring(mod.intValue(), mod.intValue() + 1));
            long_value = div;
        }

        // handle final character
        retval.append(Util.BASE_58_CHARS.substring(long_value.intValue(), long_value.intValue() + 1));

        // Extra zero padding if necessary.
        byte zeroByte = 0;
        boolean has_leading_zeroes = true;
        int nPad = 0;
        while (has_leading_zeroes) {
            if (vBytes[nPad] == zeroByte) {
                nPad++;
                retval.append("0");
            } else {
                has_leading_zeroes = false;
            }

        } // end while
        return retval.reverse().toString();
    }
}
