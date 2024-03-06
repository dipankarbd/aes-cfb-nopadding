import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESDecryptor {
    private final byte[] key;
    private final byte[] iv;
    private byte[] tmp;

    public AESDecryptor(byte[] key, byte[] iv) {
        this.key = key;
        this.iv = iv;
    }

    public byte[] decrypt(byte[] cipher) {
        byte[] data;
        if (tmp != null) {
            data = new byte[tmp.length + cipher.length];
            System.arraycopy(tmp, 0, data, 0, tmp.length);
            System.arraycopy(cipher, 0, data, tmp.length, cipher.length);
        } else {
            data = cipher.clone();
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

            byte[] plain = decryptBlock(key, iv, currentBlock);
            System.arraycopy(plain, 0, out, startIdx, currentBlockLen);

            if (currentBlockLen < blockSize) {
                tmp = currentBlock.clone();
            } else {
                System.arraycopy(currentBlock, 0, iv, 0, blockSize);
                tmp = null;
            }
        }


        byte[] result = new byte[cipher.length];
        System.arraycopy(out, out.length - cipher.length, result, 0, cipher.length);
        return result;
    }

    private byte[] decryptBlock(byte[] key, byte[] iv, byte[] plain) {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            Cipher encryptCipher = Cipher.getInstance("AES/CFB/NoPadding");
            encryptCipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

            return encryptCipher.doFinal(plain);
        } catch (Exception e) {
            e.printStackTrace();
            return new byte[0];
        }
    }
}
