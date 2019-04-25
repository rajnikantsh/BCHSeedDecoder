package org.bch.keydecoder;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.jce.interfaces.ECPublicKey;


public class ECUtils {

    private static final String EC_GEN_PARAM_SPEC = "secp256k1";
    private static final String KEY_PAIR_GEN_ALGORITHM = "ECDSA";

    public static String get_pubkey_from_secret(byte[] secret) throws NoSuchAlgorithmException, InvalidKeySpecException{
        // This function is to get the public key from private key, mostly for XPUB.
        BigInteger secretExponent = new BigInteger(1, secret);
        return getHexString(secretExponent , null);
    }

    public static KeysHolder _CKD_pub(String cK, String c, String s)  throws InvalidKeySpecException,InvalidKeyException, NoSuchAlgorithmException {

        String data = cK + s;
        byte[] dataBytes = Util.hexStringToByteArray(data);
        byte[] keyBytes = Util.hexStringToByteArray(c);
        byte[] I = Util.hmac_sha_512_bytes(dataBytes, keyBytes);
        String I_hex = Util.bytesToHex(I);
        String I_hex32 = I_hex.substring(0, 64); // first 32 bytes (64 chars)
        BigInteger bi_I32 = new BigInteger(I_hex32, 16);
        byte[] cK_bytes = new BigInteger(cK, 16).toByteArray();

        String pubKeyHexFormat = getHexString(bi_I32, cK_bytes);

        return new KeysHolder(pubKeyHexFormat , I_hex.substring(64));
    }

    public static String getHexString(BigInteger secretExponent, byte[] publicPoint) throws NoSuchAlgorithmException, InvalidKeySpecException{

        // Calculate the Public Key
        ECParameterSpec ecParameterSpec = ECNamedCurveTable.getParameterSpec(EC_GEN_PARAM_SPEC);
        ECPoint ecPoint = ecParameterSpec.getG().multiply(secretExponent);

        if (publicPoint != null){
            ecPoint = ecPoint.add(ecParameterSpec.getCurve().decodePoint(publicPoint));
        }

        KeySpec publicKeySpec = new ECPublicKeySpec(ecPoint, ecParameterSpec);

        KeyFactory keyFactory = KeyFactory.getInstance(KEY_PAIR_GEN_ALGORITHM);

        // Native java library does not provide good format, so use Bouncy Castle class:
        ECPublicKey ecPublicKey = (ECPublicKey) keyFactory.generatePublic(publicKeySpec);;

        // Extract and return Hex Value:
        String pubKeyHexFormat = getHexPubKeyfromECkeys(ecPublicKey, true);
        return pubKeyHexFormat;
    }

    public static String getHexPubKeyfromECkeys(ECPublicKey ecPublicKey, boolean compressed) {

        // This method will get a string version of Pubkey from ECC object

        ECPoint ec = ecPublicKey.getQ();
        BigInteger affineXCoord = ec.getAffineXCoord().toBigInteger();
        BigInteger affineYCoord = ec.getAffineYCoord().toBigInteger();
        if (compressed) {
            // If odd, use 03 otherwise 02 - standard key compression rule
            if (affineYCoord.and(BigInteger.ONE).compareTo(BigInteger.ONE) == 0) {
                return "03" + String.format("%064x", affineXCoord);
            } else {
                return "02" + String.format("%064x", affineXCoord);
            }
        } else {
            return String.format("%064x", affineXCoord) + String.format("%064x", affineYCoord);
        }
    }
}
