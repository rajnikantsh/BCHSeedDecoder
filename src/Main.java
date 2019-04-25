
import java.io.*;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Main {


    private static List<String> words = new ArrayList<>();

    public static void main(String[] args) throws Exception{
        String clue="1EtzTPhtQTvXbkBivtbeBgovft3zETBWUo";
        fileReader();
        String[] myseed = {"constant", "forest", "adore", "false", "green", "weave", "stop", "guy", "fur", "freeze", "giggle", "clock"};

        for(int x =0; x < 12; x++) {
            for(int y =0 ;y < 1626 ; y++) {
                try {
                    String variedword = words.get(y);
                    myseed[x] = variedword;
                    String seed = String.join(" ", myseed);
                    System.out.println("We're on seed word " + (x + 1) + " iteration " + y);

                    byte[] bip32root = Util.get_seed_from_mnemonic(seed);
                    byte[] root512 = Util.hmac_sha_512_bytes(bip32root, "Bitcoin seed".getBytes());
                    byte[] kBytes = Arrays.copyOfRange(root512, 0, 32);
                    byte[] cBytes = Arrays.copyOfRange(root512, 32, 64);
                    String publicKey = ECUtils.get_pubkey_from_secret(kBytes);
                    String serializedXpub = serializeXpub(cBytes, publicKey);
                    String finalXpub = Base58.base_encode_58(serializedXpub);
                    String deserialized_xpub[] = Util.deserialize_xkey(finalXpub, false);
                    String my_c = deserialized_xpub[4];
                    String my_cK = deserialized_xpub[5];
                    String[] newKeys = ECUtils._CKD_pub(my_cK, my_c, "00000000");
                    String my_cK2 = newKeys[0];
                    String my_c2 = newKeys[1];
                    for (int i = 0; i < 5; i++) {
                        newKeys = ECUtils._CKD_pub(my_cK2, my_c2, "0000000" + i);
                        String my_cK3 = newKeys[0];
                        String pubKeyHash = Util.ripeHash(my_cK3);
                        String address = legacyAddrfromPubKeyHash(pubKeyHash);
                        if (address.equals(clue)) {
                            System.out.println("seed found --> "+seed);
                            System.exit(0);
                        }

                    }
                }catch (Exception e){
                    e.printStackTrace();
                }
            }
        }
    }

    private static void fileReader()
    {
        String wordListFileName = "wordlist/english.txt";
        String line = null;
        try {

            InputStream in = Main.class.getResourceAsStream("/wordlist/english.txt");
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(in, "UTF-8"));
            while((line = bufferedReader.readLine()) != null) {
                words.add(line);
            }
            bufferedReader.close();
        }
        catch(FileNotFoundException ex) {
            System.out.println("Unable to open file '" + wordListFileName + "'");
        }
        catch(IOException ex) {
            System.out.println("Error reading file '" + wordListFileName + "'");
        }
    }

    public static String legacyAddrfromPubKeyHash(String pubKeyHash) throws NoSuchAlgorithmException {

        BigInteger bi_58 = new BigInteger("58");

        StringBuffer addr = new StringBuffer("00");
        addr.append(pubKeyHash);
        String checksum = Util.Hash(addr.toString());
        String checksumhead = (checksum.substring(0, 8));
        addr.append(checksumhead);
        BigInteger int_payload = new BigInteger(addr.toString(), 16);
        String mychar = "";
        StringBuffer result = new StringBuffer();

        while (int_payload.compareTo(bi_58) > -1) {
            BigInteger[] divMod = int_payload.divideAndRemainder(bi_58);
            BigInteger div = divMod[0];
            BigInteger mod = divMod[1];
            mychar = Util.BASE_58_CHARS.substring(mod.intValue(), mod.intValue() + 1);
            result.append(mychar);
            int_payload = div;
        }

        result.append(Util.BASE_58_CHARS.substring(int_payload.intValue(), int_payload.intValue() + 1)).append("1");
        return result.reverse().toString();

    }

    private static String serializeXpub(byte[] c, String Ck){
        return "0488B21E000000000000000000" + Util.bytesToHex(c) + Ck;
    }
}
