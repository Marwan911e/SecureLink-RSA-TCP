import java.security.KeyPair;

/**
 * Generates RSA key pairs for sender and receiver and writes them to keys/.
 * Run this first before RSADecrypt and RSAEncrypt.
 */
public class RSAGenKey {

    public static void main(String[] args) throws Exception {
        System.out.println("Generating RSA key pairs (" + RSAKeyUtil.KEY_SIZE + "-bit)...");

        // Generate KUA/KRA for sender A and KUB/KRB for receiver B (each gets public {e,n} and private {d,n})
        KeyPair senderPair = RSAKeyUtil.generateKeyPair();
        RSAKeyUtil.saveKeyPair(senderPair, "sender");
        System.out.println("  Sender keys  -> keys/sender_private.key, keys/sender_public.key");

        KeyPair receiverPair = RSAKeyUtil.generateKeyPair();
        RSAKeyUtil.saveKeyPair(receiverPair, "receiver");
        System.out.println("  Receiver keys -> keys/receiver_private.key, keys/receiver_public.key");

        System.out.println("Done. Next: start RSADecrypt, then RSAEncrypt.");
    }
}
