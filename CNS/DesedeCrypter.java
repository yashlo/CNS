import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
public class DesedeCrypter {

    private static final String CRYPT_ALGORITHM = "DESede";
    private static final String PADDING = "DESede/CBC/NoPadding";
    private static final String CHAR_ENCODING = "UTF-8";

    private static final byte[] MY_KEY = "5oquil2oo2vb63e8ionujny6".getBytes();//24-byte
    private static final byte[] MY_IV = "3oco1v52".getBytes();//8-byte

    public static void main(String[] args) {
        String srcText = "Hellowor";
        final DesedeCrypter crypter = new DesedeCrypter();
        String encryptedText = crypter.encrypt(srcText);
        System.out.println("sourceText=" + srcText + " -> encryptedText=" + encryptedText + "\n");

        System.out.println("encrypted-text=" + encryptedText + " -> decrypted-text(source text)="
                + crypter.decrypt(encryptedText));
    }
    public String encrypt(String text) {

        if (text == null) {
            return null;
        }

        String retVal = null;

        try {

            final SecretKeySpec secretKeySpec = new SecretKeySpec(MY_KEY, CRYPT_ALGORITHM);

            final IvParameterSpec iv = new IvParameterSpec(MY_IV);

            final Cipher cipher = Cipher.getInstance(PADDING);

            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, iv);

            final byte[] encrypted = cipher.doFinal(text.getBytes(CHAR_ENCODING));

            retVal = new String(encodeHex(encrypted));

        } catch (Exception e) {
            e.printStackTrace();
        }

        return retVal;
    }
    public String decrypt(String text) {

        if (text == null) {
            return null;
        }

        String retVal = null;

        try {

            final SecretKeySpec secretKeySpec = new SecretKeySpec(MY_KEY, CRYPT_ALGORITHM);
            final IvParameterSpec iv = new IvParameterSpec(MY_IV);

            final Cipher cipher = Cipher.getInstance(PADDING);

            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, iv);

            final byte[] decrypted = cipher.doFinal(decodeHex(text.toCharArray()));

            retVal = new String(decrypted, CHAR_ENCODING);

        } catch (Exception e) {

            e.printStackTrace();
        }

        return retVal;
    }
    private byte[] decodeHex(char[] data) throws Exception {

        int len = data.length;

        if ((len & 0x01) != 0) {
            throw new Exception("Odd number of characters.");
        }

        byte[] out = new byte[len >> 1];
        for (int i = 0, j = 0; j < len; i++) {

            int f = toDigit(data[j], j) << 4;
            j++;
            f = f | toDigit(data[j], j);
            j++;
            out[i] = (byte) (f & 0xFF);
        }

        return out;
    }
    private int toDigit(char ch, int index) throws Exception {
        int digit = Character.digit(ch, 16);
        if (digit == -1) {
            throw new Exception("Illegal hexadecimal character " + ch + " at index " + index);
        }
        return digit;
    }
    private char[] encodeHex(byte[] data) {

        final char[] DIGITS = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

        int l = data.length;
        char[] out = new char[l << 1];
        for (int i = 0, j = 0; i < l; i++) {
            out[j++] = DIGITS[(0xF0 & data[i]) >>> 4];
            out[j++] = DIGITS[0x0F & data[i]];
        }
        return out;
    }
}
