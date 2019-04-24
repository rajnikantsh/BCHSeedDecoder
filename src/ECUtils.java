import java.io.*;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import java.security.KeyFactory;
import java.security.Security;
import java.security.MessageDigest;


public class ECUtils {

    private static final String EC_GEN_PARAM_SPEC = "secp256k1";
    private static final String KEY_PAIR_GEN_ALGORITHM = "ECDSA";

    public static String get_pubkey_from_secret(byte[] secret) {

        // This function is to get the public key from private key, mostly for XPUB.

        // Bouncy Castle used to provide Crypto Libraries
        Security.addProvider(new BouncyCastleProvider());

        // Format Secret Exponent (the Private Key) into an Integer
        BigInteger secretExponent = new BigInteger(Util.bytesToHex(secret), 16);

        // Calculate the Public Key
        ECParameterSpec ecParameterSpec = ECNamedCurveTable.getParameterSpec(EC_GEN_PARAM_SPEC);
        ECPoint ecPoint = ecParameterSpec.getG().multiply(secretExponent);

        KeySpec publicKeySpec = new ECPublicKeySpec(ecPoint, ecParameterSpec);

        PublicKey publicKey = null;
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance(KEY_PAIR_GEN_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("NO SUCH ALGORITHM EXCEPTION");
            System.exit(0);
        }
        try {
            publicKey = keyFactory.generatePublic(publicKeySpec);

            // privateKey = keyFactory.generatePublic(publicKeySpec);
        } catch (InvalidKeySpecException e) {
            System.out.println("INVALID KEY SPEC EXCEPTION");
            System.exit(0);
        }

        // Native java library does not provide good format, so use Bouncy Castle class:
        ECPublicKey ecPublicKey = (ECPublicKey) publicKey;

        // Extract and return Hex Value:
        String pubKeyHexFormat = getHexPubKeyfromECkeys(ecPublicKey, true);
        // System.out.println("DEBUG pubkey is " + pubKeyHexFormat);
        return pubKeyHexFormat;
    }

    public static String[] _CKD_pub(String cK, String c, String s)  {

        Security.addProvider(new BouncyCastleProvider());
        ECParameterSpec ecParameterSpec = ECNamedCurveTable.getParameterSpec(EC_GEN_PARAM_SPEC);

        String data = cK + s;
        byte[] dataBytes = Util.hexStringToByteArray(data);
        byte[] I = Util.hmac_sha_512_bytes_from_hex(dataBytes, c);
        String I_hex = Util.bytesToHex(I);
        String I_hex32 = I_hex.substring(0, 64); // first 32 bytes (64 chars)
        BigInteger bi_I32 = new BigInteger(I_hex32, 16);
        byte[] cK_bytes = new BigInteger(cK, 16).toByteArray();

        ECPoint ecPoint = ecParameterSpec.getG().multiply(bi_I32).add(ecParameterSpec.getCurve().decodePoint(cK_bytes));
        KeySpec publicKeySpec = new ECPublicKeySpec(ecPoint, ecParameterSpec);
        PublicKey publicKey = null;
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance(KEY_PAIR_GEN_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("NO SUCH ALGORITHM EXCEPTION");
            System.exit(0);
        }
        try {
            publicKey = keyFactory.generatePublic(publicKeySpec);
        } catch (InvalidKeySpecException e) {
            System.out.println("INVALID KEY SPEC EXCEPTION");
            System.exit(0);
        }
        org.bouncycastle.jce.interfaces.ECPublicKey ecPublicKey = (org.bouncycastle.jce.interfaces.ECPublicKey) publicKey;
        String pubKeyHexFormat = ECUtils.getHexPubKeyfromECkeys(ecPublicKey, true);

        String retval[] = new String[2];
        retval[0] = pubKeyHexFormat;
        retval[1] = I_hex.substring(64);
        return retval;

    }

    public static String getHexPubKeyfromECkeys(ECPublicKey ecPublicKey, boolean compressed) {

        // This method will get a string version of Pubkey from ECC object

        ECPoint ec = ecPublicKey.getQ();
        BigInteger affineXCoord = ec.getAffineXCoord().toBigInteger();
        BigInteger affineYCoord = ec.getAffineYCoord().toBigInteger();
        if (!compressed) {
            return String.format("%064x", affineXCoord) + String.format("%064x", affineYCoord);
        } else {
            // If odd, use 03 otherwise 02 - standard key compression rule
            if (affineYCoord.and(BigInteger.ONE).compareTo(BigInteger.ONE) == 0) {
                return "03" + String.format("%064x", affineXCoord);
            } else {
                return "02" + String.format("%064x", affineXCoord);
            }
        }
    }
}