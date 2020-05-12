import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.bouncycastle.asn1.pkcs.RSAPublicKey;

public class PgpMain {

	public static void main(String[] args) {
		try {
			KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
			keyGenerator.init(128);
			SecretKey secretKey = keyGenerator.generateKey();

			String input = "Subrato Mondalxcxs## ]";
			byte[] keyBytes = input.getBytes(StandardCharsets.UTF_8);
			printByte(keyBytes, "Byte Conversion of String...", StandardCharsets.UTF_8, StandardCharsets.UTF_16);

			byte[] encryptedBytes = encrypt("AES/ECB/PKCS5Padding", secretKey, keyBytes);
			printByte(encryptedBytes, "\nPost Encryption of String...", StandardCharsets.UTF_8,
					StandardCharsets.UTF_16);

			PublicKey publicKey = getPublicKey("/media/john/CommonDisk/IT PROJECTS/EncryptionProjects/pgp-master/public.key");
			PrivateKey privateKey = getPrivateKey("/media/john/CommonDisk/IT PROJECTS/EncryptionProjects/pgp-master/private.key");

			byte[] rsaEncBytes = rsaEncrypt(encryptedBytes, publicKey);
			printByte(rsaEncBytes, "\nRSA Encrypted byteArr...", StandardCharsets.UTF_8,
					StandardCharsets.UTF_16);
			
			byte[] rsaDecryptBytes = rsaDecrypt(rsaEncBytes, privateKey);
			printByte(rsaDecryptBytes, "\nRSA Decrypted byteArr...", StandardCharsets.UTF_8,
					StandardCharsets.UTF_16);
			
			byte[] decryptedBytes = decrypt("AES/ECB/PKCS5Padding", secretKey, encryptedBytes);
			printByte(decryptedBytes, "\nPost Decryption of encrypted byteArr...", StandardCharsets.UTF_8,
					StandardCharsets.UTF_16);

			String output = new String(decryptedBytes, StandardCharsets.UTF_8);
			System.out.println(output);

			if (output.equals(input)) {
				System.out.println("MATCHED!!");
			} else {
				System.out.println("NOT MATCHED!!");
			}

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
	
	public static byte[] rsaEncrypt(byte[] data, PublicKey publicKey) {
		Cipher cipher;
		byte[] encryptedData = null;
		try {
			cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			encryptedData = cipher.doFinal(data);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return encryptedData;		
	}
	
	public static byte[] rsaDecrypt(byte[] data, PrivateKey privateKey) {
		Cipher cipher;
		byte[] decryptedData = null;
		try {
			cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			decryptedData = cipher.doFinal(data);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return decryptedData;		
	}

	public static PublicKey getPublicKey(String filename) throws Exception {

		byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

		RSAPublicKey rsaPublicKy = RSAPublicKey.getInstance(keyBytes);
		RSAPublicKeySpec spec = new RSAPublicKeySpec(rsaPublicKy.getModulus(), rsaPublicKy.getPublicExponent());
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);
	}
	
	public static PrivateKey getPrivateKey(String filename) throws Exception {

		byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(spec);
	}

	public class PGPEncryptionMethod {

		private Map<String, String> param;

		public void setParameter(Map param) {
			this.param = param;
		}

		public void execute(InputStream in, OutputStream out) {

			if (param instanceof java.util.Map) {
				System.out.println("ERROR");
			}

			try {

				String publicKeyPath = "/com/sap/pi/pgp/publickey.pkr";
				// Encrypt the message
				new PGPEncryption().encrypt(publicKeyPath, in, out);
			} catch (Exception e) {
				e.printStackTrace();
			}

		}
	}

	private static byte[] decrypt(String algo, SecretKey secretKey, byte[] encryptedData) {

		Cipher decryptCipher;
		byte[] decryptedText = null;
		try {

			decryptCipher = Cipher.getInstance(algo);
			decryptCipher.init(Cipher.DECRYPT_MODE, secretKey);
			decryptedText = decryptCipher.doFinal(encryptedData);

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return decryptedText;
	}

	private static void printByte(byte[] data, String description, Charset... charsetArr) {
		System.out.println(description);
		System.out.println("Array: " + Arrays.toString(data));
		for (Charset charset : charsetArr) {
			System.out.println(charset.displayName() + " String:\n" + new String(data, charset));
		}
	}

	private static byte[] encrypt(String algo, SecretKey secretKey, byte[] data) {

		Cipher encryptCipher;
		byte[] encryptedBytes = null;
		try {

			encryptCipher = Cipher.getInstance(algo);
			encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey);
			encryptedBytes = encryptCipher.doFinal(data);

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return encryptedBytes;
	}

}
