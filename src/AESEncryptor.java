import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESEncryptor {
    private final byte[] key;
    private final byte[] iv;
    private byte[] tmp;

    public AESEncryptor(byte[] key, byte[] iv) {
        this.key = key;
        this.iv = iv;
    }

    public byte[] encrypt(byte[] plain) {
        byte[] data;
        if (tmp != null) {
            data = new byte[tmp.length + plain.length];
            System.arraycopy(tmp, 0, data, 0, tmp.length);
            System.arraycopy(plain, 0, data, tmp.length, plain.length);
        } else {
            data = plain.clone();
        }

        int blockSize = iv.length;
        int len = data.length;
        int nBlocks = (int) Math.ceil(len / (double) blockSize);

        byte[] out = new byte[len];

        for (int bIdx = 0; bIdx < nBlocks; bIdx++) {
            int startIdx = bIdx * blockSize;
            int endIndex = Math.min(startIdx + blockSize, len) - 1;
            int currentBlockLen = endIndex - startIdx + 1;

            byte[] currentBlock = new byte[currentBlockLen];
            System.arraycopy(data, startIdx, currentBlock, 0, currentBlockLen);

            byte[] encrypted = encryptBlock(key, iv, currentBlock);
            System.arraycopy(encrypted, 0, out, startIdx, currentBlockLen);

            if (currentBlockLen < blockSize) {
                tmp = currentBlock.clone();
            } else {
                System.arraycopy(encrypted, 0, iv, 0, blockSize);
                tmp = null;
            }
        }

        byte[] result = new byte[plain.length];
        System.arraycopy(out, out.length - plain.length, result, 0, plain.length);
        return result;
    }

    private byte[] encryptBlock(byte[] key, byte[] iv, byte[] plain) {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            Cipher encryptCipher = Cipher.getInstance("AES/CFB/NoPadding");
            encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

            return encryptCipher.doFinal(plain);
        } catch (Exception e) {
            e.printStackTrace();
            return new byte[0];
        }
    }
}