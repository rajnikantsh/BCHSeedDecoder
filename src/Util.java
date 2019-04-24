import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Util {

    public static final String HEX_STRING = "0123456789abcdef";
    public static final String BASE_58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static final String ZERO = "0000000000000000000000000000000000000000000000000000000000000000";

    public static String Hash(String x) {

        byte[] xBytes = new BigInteger(x , 16).toByteArray();
        return new BigInteger(1,doubleHash(xBytes)).toString(16);
    }

    public static String format(BigInteger coord, int size) {
        String hex = coord.toString(16);
        int length = hex.length();
        int appendLength = size - length;
        return ZERO.substring(0,appendLength)+hex;
    }


    public static byte[] doubleHash(byte[] b) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            b = digest.digest(b);
            return digest.digest(b);
        }catch (NoSuchAlgorithmException exception){
            exception.printStackTrace();
        }
        return new byte[0];
    }

    public static String padLeftHexString(String s, int expectedLength) {

        String retval = s;
        StringBuffer zeroString = new StringBuffer();
        int myLength = s.length();
        if (expectedLength > myLength) {
            int numberOfZeroes = expectedLength - myLength;
            for (int i = 0; i < numberOfZeroes; i++) {
                zeroString.append("0");
            }
            retval = zeroString.toString() + retval;
        }
        return retval;
    }

    public static int unsignedToBytes(byte a) {
        int b = a & 0xFF;
        return b;
    }

    public static String[] deserialize_xkey(String key, boolean prv) {
        String xkey = Base58.base_decode_58(key);
        String depth = xkey.substring(8, 10);
        String fingerprint = xkey.substring(10, 18);
        String child_number = xkey.substring(18, 26);
        String c = xkey.substring(26, 90);

        if (!prv) {
            if ((!xkey.substring(0, 8).equals("0488B21E")) && (!xkey.substring(0, 8).equals("0488b21e"))) {
                System.out.println("BAD KEY HEADER FAILURE.");
            }
        }

        if (prv) {
            if ((!xkey.substring(0, 8).equals("0488ADE4")) && (!xkey.substring(0, 8).equals("0488ade4"))) {
                System.out.println("BAD KEY HEADER FAILURE.");
            }
        }

        int n = prv ? 33 : 32;
        String K_or_k = xkey.substring(26 + (n * 2));
        return new String[] {"standard",depth,fingerprint,child_number,c,K_or_k};

    }

    public static String ripeHash(String x) {

        // This method will peform a RIPEMD160 Hash of the SHA256 Hash.
        String out = null;
        MessageDigest digest = null;
        MessageDigest digest2 = null;
        byte[] xBytes = null;

        try {
            digest = MessageDigest.getInstance("SHA-256");
            digest2 = MessageDigest.getInstance("RIPEMD160");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("NO SUCH ALGORITHM EXCEPTION");
            System.exit(0);
        }

        xBytes = Util.hexStringToByteArray(x);
        // --- Hash sha256
        xBytes = digest.digest(xBytes);
        // ripemd160
        xBytes = digest2.digest(xBytes);
        out = Util.bytesToHex(xBytes);
        return out;
    }

    public static String bytesToHex(byte[] bytes) {
        final char[] hexArray = "0123456789abcdef".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public static byte[] hmac_sha_512_bytes_from_hex(byte[] message, String hexkey) {
        try {
            byte[] byteKey = Util.hexStringToByteArray(hexkey);
            return hmac_sha_512_bytes(message, byteKey);
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } finally {
            // We're done!
        }

        return new byte[0];
    }

    public static byte[] hmac_sha_512_bytes(byte[] message, byte[] key) throws InvalidKeyException,NoSuchAlgorithmException{

        final String HMAC_SHA512 = "HmacSHA512";

        Mac sha512_HMAC = Mac.getInstance(HMAC_SHA512);
        SecretKeySpec keySpec = new SecretKeySpec(key, HMAC_SHA512);
        sha512_HMAC.init(keySpec);
        byte [] mac_data = sha512_HMAC.doFinal(message);
        return mac_data;

    }
}
