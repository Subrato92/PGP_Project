import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.pkcs.RSAPublicKey;

public class PgpMain {

	public static void main(String[] args) {

		
		KeyPairGenerator kpg;
		try {
			kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(2048);
			KeyPair kp = kpg.generateKeyPair();
			
			PublicKey pub = kp.getPublic();
			PrivateKey pk = kp.getPrivate();
			
			try (FileOutputStream out = new FileOutputStream("/home/john/Desktop/private" + ".key")) {
			    out.write(kp.getPrivate().getEncoded());
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			try (FileOutputStream out = new FileOutputStream("/home/john/Desktop/public" + ".pub")) {
			    out.write(kp.getPublic().getEncoded());
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			String msg = "I am Subrato Mondal";
			byte[] msgByte = msg.getBytes(StandardCharsets.UTF_8);
			
			Cipher cipher1 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher1.init(Cipher.ENCRYPT_MODE, pub);
			byte[] encrypted = cipher1.doFinal(msgByte);
			
			String encStr = new String(encrypted);
			System.out.println("encStr:");
			System.out.println(encStr);
			
			Cipher cipher2 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher2.init(Cipher.DECRYPT_MODE, pk);
			byte[] decrypted = cipher2.doFinal(encrypted);
			
			String decypStr = new String(decrypted, StandardCharsets.UTF_8);
			System.out.println("decrypted:");
			System.out.println(decypStr);
			
			BigInteger mod = new BigInteger("18983776524351575068871700350035055581909065148432112387355455892238594754526914703409256744025386767229482754327813763912831401292169549912598851005525807185506584629876119759022512711061790077967400419210324678141344890978498927270913454449415226081587238158352832969860890059895946349522021556464067296976448534658758011896677938042757941023419869872411849510177992335711900028645652021488943905770629758414133793215816789724894205104599331822606911731885832999077062002376723808923995631373430715137343666492089801301953735297745618315457557458342880272756916663369412457979736686241615112858211478598070107103059");
			BigInteger pubExp = new BigInteger("65537");
			BigInteger pvtExp = new BigInteger("3882090620250542580115332225936033308035846790656990253068309807708342568322775086669985792505427978918924086752542229030315187453158617390613696098021832978320021471986812899742431227453958994536202456906125872964131776384238561778610282993287194408432368979328389573249853496234577001942324685288179652930019083615556446569032733621558527864711103275501362534929178819298262362757799525161557156363265691429840855317542417366364687207489166720699680579333562420357490348019536390984952213932843577235683260715329905723818768770150723572386631860223398696904611565044630154824495153469088842333007178694097142204257");
			PublicKey extractedPub = bigIntegerToPublicKey(mod, pubExp);
			PrivateKey etractedPvt = bigIntegerToPrivateKey(mod, pvtExp);
			
			try (FileOutputStream out = new FileOutputStream("/home/john/Desktop/private1" + ".key")) {
			    out.write(etractedPvt.getEncoded());
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			try (FileOutputStream out = new FileOutputStream("/home/john/Desktop/public1" + ".pub")) {
			    out.write(extractedPub.getEncoded());
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			if(extractedPub.toString().equals(pub.toString())) {
				System.out.println("Equals");
			}else {
				System.out.println("NotEquals");
			}
			
			if(etractedPvt.toString().equals(pk.toString())) {
				System.out.println("Equals");
			}else {
				System.out.println("NotEquals");
			}
			
			Cipher cipher3 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher3.init(Cipher.ENCRYPT_MODE, extractedPub);
			encrypted = cipher3.doFinal(msgByte);
			
			encStr = new String(encrypted);
			System.out.println("encStr:");
			System.out.println(encStr);
			
			Cipher cipher4 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher4.init(Cipher.DECRYPT_MODE, etractedPvt);
			decrypted = cipher4.doFinal(encrypted);
			
			decypStr = new String(decrypted, StandardCharsets.UTF_8);
			System.out.println("decrypted:");
			System.out.println(decypStr);
			
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		

		// ===========================================================================================

	}
	
	public static void method() {
//		  532  pwd
//		  533  gpg --list-secret-keys subrato.mondal18@gmail.om
//		  534  gpg --list-secret-keys subrato.mondal18@gmail.com
//		  535  gpg --export-secret-keys 4B5900B9199245E4C706FBF116C9875AD14D4D03 > private.key
//		  536  gpg --armor --output public.key --export subrato.mondal18@gmail.com
//		  537  cd Desktop/
//		  538  ls -lrt
//		  539  pwd
//		  540  ls -lrt
//		  541  cat public.pub 
//		  542  cat private.key 
//		  543  openssl genrsa -out rsa.private 1024
//		  544  ls -lrt
//		  545  cat rsa.private 
//		  546  openssl rsa -in rsa.private -out rsa.public -pubout -outform PEM
//		  547  ls
//		  548  cat rsa.public 
//		  549  openssl ans1parse -i -in rsa.public
//		  550  openssl asn1parse -i -in rsa.public
//		  551  ls -lrt
//		  552  openssl rsa -pubin -in rsa.public -text -noout
//		  553  openssl rsa -pubin -in rsa.private -text -noout
//		  554  openssl rsa -in rsa.private -text -noout
//		  555  cat private1.key 
//		  556  cat private.key 
//		  557  cat public1.pub 
//		  558  cat public.pub 
//		  559  clear
//		  560  cat public.pub 
//		  561  cat public1.pub 
//		  562  cat private.key 
//		  563  cat private1.key 
//		  564  clear
//		  565  openssl rsa -pubin -in rsa.private -text -noout
//		  566  clear
//		  567  openssl rsa -in rsa.private -text -noout
//		  568  openssl rsa -pubin -in rsa.public -text -noout
//		  569  clear
//		  570  openssl rsa -pubin -in public.key -text -noout
//		  571  openssl rsa -pubin -in public.pub -text -noout
//		  572  openssl pkcs8 -nocrypt -inform der < private.key > pvt.pem
//		  573  cat pvt.pem 
//		  574  openssl rsa -in pvt.pem -text -noout
//		  575  clear
//		  576  ls
//		  577  cat private1.key 
//		  578  cat private.key 
//		  579  cat public1.pub 
//		  580  cat public.pub 
//		  581  history
	}

	public static PublicKey bigIntegerToPublicKey(BigInteger m, BigInteger e)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
		KeyFactory fact = KeyFactory.getInstance("RSA");
		PublicKey pubKey = fact.generatePublic(keySpec);
		return pubKey;
	}

	public static PrivateKey bigIntegerToPrivateKey(BigInteger e, BigInteger m)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(e, m);
		KeyFactory fact = KeyFactory.getInstance("RSA");
		PrivateKey privKey = fact.generatePrivate(keySpec);
		return privKey;
	}

	private static void someFlow() {
		try {

			PublicKey publicKey = getPublicKey(
					"/media/john/CommonDisk/IT PROJECTS/EncryptionProjects/pgp-master/public.key");
			PrivateKey privateKey = getPrivateKey(
					"/media/john/CommonDisk/IT PROJECTS/EncryptionProjects/pgp-master/private.key");

			String input = "Subrato Mondalxcxs## ]";
			filterNewlineChars(input);
			StringBuilder sb = new StringBuilder();
			sb.append(input);
			sb.append(System.lineSeparator());
			filterNewlineChars(sb.toString());

			KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
			keyGenerator.init(128);
			SecretKey secretKey = keyGenerator.generateKey();

			byte[] keyBytes = input.getBytes(StandardCharsets.UTF_8);
			printByte(keyBytes, "Byte Conversion of String...", StandardCharsets.UTF_8, StandardCharsets.UTF_16);

			byte[] encryptedBytes = encrypt("AES/ECB/PKCS5Padding", secretKey, keyBytes);
			printByte(encryptedBytes, "\nPost Encryption of String...", StandardCharsets.UTF_8,
					StandardCharsets.UTF_16);

			byte[] rsaEncBytes = rsaEncrypt(encryptedBytes, publicKey);
			printByte(rsaEncBytes, "\nRSA Encrypted byteArr...", StandardCharsets.UTF_8, StandardCharsets.UTF_16);

			byte[] rsaDecryptBytes = rsaDecrypt(rsaEncBytes, privateKey);
			printByte(rsaDecryptBytes, "\nRSA Decrypted byteArr...", StandardCharsets.UTF_8, StandardCharsets.UTF_16);

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

	private static File encryptionFlow(File encryptedFile, PublicKey publicKey) {
		// Extracting Key and Data
		String[] arr = extractDataElements(encryptedFile);

		// Removing NewLine chars from sessionKey
		if (arr != null && arr.length == 2) {
			arr[0] = filterNewlineChars(arr[0]);
		}

		// Base64Decoding of the data
		Base64.Decoder decoder = Base64.getDecoder();
		byte[] encByteSecretKey = decoder.decode(arr[0]);
		byte[] encByteData = decoder.decode(arr[1]);

		// decrypt secretKey with PGP decoder
		byte[] byteSecretKey = rsaEncrypt(encByteData, publicKey);
		SecretKey secKey = new SecretKeySpec(byteSecretKey, "AES");

		// decrypt data using secretKey
		byte[] byteData = decrypt("AES/ECB/PKCS5Padding", secKey, encByteData);
		String data = new String(byteData, StandardCharsets.UTF_8);

		String newFileName = encryptedFile.getName();
		String[] nameElements = newFileName.split(".");
		newFileName = "";
		for (int i = 0; i < nameElements.length - 1; i++) {
			newFileName = newFileName.concat(nameElements[i]);
			if (i < nameElements.length - 2) {
				newFileName = newFileName.concat(".");
			}
		}
		String path = encryptedFile.getPath().substring(0,
				encryptedFile.getPath().length() - encryptedFile.getName().length());
		path = path.concat(newFileName);

		File nwFile = new File(path);
		FileWriter writer;
		try {
			writer = new FileWriter(nwFile);
			BufferedWriter bufWriter = new BufferedWriter(writer);
			bufWriter.write(data);
			bufWriter.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return nwFile;
	}

	private static File decryptionFlow(File encryptedFile, PrivateKey privateKey) {
		// Extracting Key and Data
		String[] arr = extractDataElements(encryptedFile);

		// Removing NewLine chars from sessionKey
		if (arr != null && arr.length == 2) {
			arr[0] = filterNewlineChars(arr[0]);
		}

		// Base64Decoding of the data
		Base64.Decoder decoder = Base64.getDecoder();
		byte[] encByteSecretKey = decoder.decode(arr[0]);
		byte[] encByteData = decoder.decode(arr[1]);

		// decrypt secretKey with PGP decoder
		byte[] byteSecretKey = rsaDecrypt(encByteSecretKey, privateKey);
		SecretKey secKey = new SecretKeySpec(byteSecretKey, "AES");

		// decrypt data using secretKey
		byte[] byteData = decrypt("AES/ECB/PKCS5Padding", secKey, encByteData);
		String data = new String(byteData, StandardCharsets.UTF_8);

		String newFileName = encryptedFile.getName();
		String[] nameElements = newFileName.split(".");
		newFileName = "";
		for (int i = 0; i < nameElements.length - 1; i++) {
			newFileName = newFileName.concat(nameElements[i]);
			if (i < nameElements.length - 2) {
				newFileName = newFileName.concat(".");
			}
		}
		String path = encryptedFile.getPath().substring(0,
				encryptedFile.getPath().length() - encryptedFile.getName().length());
		path = path.concat(newFileName);

		File nwFile = new File(path);
		FileWriter writer;
		try {
			writer = new FileWriter(nwFile);
			BufferedWriter bufWriter = new BufferedWriter(writer);
			bufWriter.write(data);
			bufWriter.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return nwFile;
	}

	private static String[] extractDataElements(File file) {

		String[] dataArr = null;

		FileReader reader;
		BufferedReader bufReader;
		try {
			reader = new FileReader(file);
			bufReader = new BufferedReader(reader);

			String encryptedKey = bufReader.readLine();

			String dataLine = bufReader.readLine();
			StringBuilder dataBuilder = new StringBuilder();
			while (dataLine != null) {
				dataBuilder.append(dataLine);
				dataLine = bufReader.readLine();

				if (dataLine != null)
					dataBuilder.append(System.lineSeparator());
			}
			String data = dataBuilder.toString();
			if (encryptedKey != null) {
				dataArr = new String[2];
				dataArr[0] = encryptedKey;
				dataArr[1] = data;
			}

		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return dataArr;
	}

	private static String filterNewlineChars(String data) {

		if (data == null) {

		}
		System.out.println("String:" + data);
		char carriageReturn = '\r';
		char newLine = '\n';
		int length = data.length();
		int indx = 0;
		while (indx < length && data.charAt(indx) != carriageReturn && data.charAt(indx) != newLine) {
			indx++;
		}

		String modData = data.substring(0, indx);
		System.out.println("AcLength:" + data.length() + ", ModLength:" + modData.length());

		return modData;
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
