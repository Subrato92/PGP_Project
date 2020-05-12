import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Date;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;

/*import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;*/

//import com.sap.aii.mapping.api.AbstractTrace;

public class PGPEncryption {

	// private AbstractTrace trace;

	public void encrypt(InputStream in, OutputStream out) throws Exception {

		String publicKeyPath = "/com/pi/edt/pgp/resources/keys/pubring_dev.pkr";

		try {
			encrypt(publicKeyPath, inputStreamToString(in), out);
		} catch (Exception e) {
			e.printStackTrace();
			throw new Exception(e.toString());
		}
	}

	public void encrypt(String publicKeyPath, InputStream in, OutputStream out) throws Exception {

		try {
			encrypt(publicKeyPath, inputStreamToString(in), out);
		} catch (Exception e) {
			e.printStackTrace();
			throw new Exception(e.toString());
		}
	}

	public void encrypt(String publicKeyPath, String inString, OutputStream out) throws Exception {

		// this.trace = trace;

		try {
			Security.addProvider(new BouncyCastleProvider());
			InputStream keyStream = getClass().getResourceAsStream(publicKeyPath);

			if (keyStream == null) {
				throw new Exception(" Unable to find Resource at " + publicKeyPath);
			}
			// Get Publik key
			PGPPublicKey key = readPublicKeyFromCol(keyStream);
			out = new DataOutputStream(out);
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(PGPCompressedDataGenerator.ZIP);
			writeStringToLiteralData(comData.open(bOut), inString);
			comData.close();
			// object that encrypts the data
			/*
			 * PGPEncryptedDataGenerator cPk = new
			 * PGPEncryptedDataGenerator(PGPEncryptedDataGenerator.CAST5, new
			 * SecureRandom(), “BC”); cPk.addMethod(key);
			 * 
			 * byte[] bytes = bOut.toByteArray(); out = cPk.open(out, bytes.length);
			 * out.write(bytes); cPk.close(); out.close();
			 */
		} catch (Exception e) {
			e.printStackTrace();
			throw new Exception(e.toString());
		}
	}

	/*
	 * private InMemoryKeyring keyring(String passphrase, ArmoredKeyPair
	 * armoredKeyPair, String... recipientsArmoredPublicKey) throws IOException,
	 * PGPException { InMemoryKeyring keyring =
	 * KeyringConfigs.forGpgExportedKeys(KeyringConfigCallbacks.withPassword(
	 * passphrase));
	 * keyring.addSecretKey(armoredKeyPair.privateKey().getBytes(UTF_8));
	 * keyring.addPublicKey(armoredKeyPair.publicKey().getBytes(UTF_8)); for (String
	 * recipientArmoredPublicKey : recipientsArmoredPublicKey) {
	 * keyring.addPublicKey(recipientArmoredPublicKey.getBytes(UTF_8)); } return
	 * keyring; }
	 */

	private String inputStreamToString(InputStream in) {

		// read in stream into string.
		StringBuffer buf = new StringBuffer();
		try {
			InputStreamReader isr = null;
			// try UTF-8 conversion
			try {
				isr = new InputStreamReader(in, "UTF-8");
			} catch (UnsupportedEncodingException e) {
				// or atleast in natural encoding
				isr = new InputStreamReader(in);
			}
			int c = 0;
			while ((c = isr.read()) != -1) {
				buf.append((char) c);
			}

			in.close();
			isr.close();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return buf.toString();
	}

	private void writeStringToLiteralData(OutputStream out, String inString) throws IOException {

		PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
		OutputStream pOut = lData.open(out, PGPLiteralData.BINARY, "", inString.length(), new Date());

		pOut.write(inString.getBytes());
		lData.close();
	}

	private PGPPublicKey readPublicKeyFromCol(InputStream in) throws Exception {
		PGPPublicKeyRing pkRing = null;
		PGPPublicKey result = null, key = null;

		try {
			/*
			 * PGPPublicKeyRingCollection pkCol = new PGPPublicKeyRingCollection(in);
			 * Iterator it = pkCol.getKeyRings(); while (it.hasNext()) { pkRing =
			 * (PGPPublicKeyRing) it.next(); Iterator pkIt = pkRing.getPublicKeys(); while
			 * (pkIt.hasNext()) { key = (PGPPublicKey) pkIt.next(); if
			 * (key.isEncryptionKey()) { result = key; break; } } }
			 */
		} catch (Exception e) {
			e.printStackTrace();
			throw new Exception(e.toString());
		}

		return result;
	}

	public void decrypt(InputStream in, OutputStream out, String passphrase) throws Exception {

		String privateKeyPath = "/com/pi/edt/pgp/resources/keys/Secring_dev.skr";

		try {
			InputStream inKey = null;
			try {
				inKey = getClass().getResourceAsStream(privateKeyPath);
			} catch (Exception e) {
				e.printStackTrace();
				throw new Exception(e.toString());
			}

			decrypt(in, out, inKey, passphrase.toCharArray());

		} catch (Exception e) {
			e.printStackTrace();
			throw new Exception(e.toString());
		}
	}

	public void decrypt(InputStream encData, OutputStream out, String privateKeyPath, String passphrase)
			throws Exception {

		try {

			InputStream inKey = null;
			try {
				inKey = new Object().getClass().getResourceAsStream(privateKeyPath);
			} catch (Exception e) {
				e.printStackTrace();
				throw new Exception(e.toString());
			}

			decrypt(encData, out, inKey, passphrase.toCharArray());

		} catch (Exception e) {
			e.printStackTrace();
			throw new Exception(e.toString());
		}

	}

	public void decrypt(String encData, OutputStream out, String privateKeyPath, String passphrase) throws Exception {

		try {

			InputStream in = null;
			InputStream inKey = null;

			try {
				in = new ByteArrayInputStream(encData.getBytes());
			} catch (Exception e) {
				in = new ByteArrayInputStream(encData.getBytes());
			}

			try {
				inKey = getClass().getResourceAsStream(privateKeyPath);
			} catch (Exception e) {
				e.printStackTrace();
				throw new Exception(e.toString());
			}

			decrypt(in, out, inKey, passphrase.toCharArray());

		} catch (Exception e) {
			e.printStackTrace();
			throw new Exception(e.toString());
		}
	}

	public void decrypt(InputStream encdata, OutputStream out, InputStream key, char passphrase[]) throws Exception {

		Security.addProvider(new BouncyCastleProvider());
		try {

			/*
			 * encdata = PGPUtil.getDecoderStream(encdata); KeyFingerPrintCalculator
			 * keyFingerPrintCalculator = new KeyFingerPrintCalculator() {
			 * 
			 * @Override public byte[] calculateFingerprint(PublicKeyPacket arg0) throws
			 * PGPException { // TODO Auto-generated method stub return null; } };
			 * PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(encdata,
			 * keyFingerPrintCalculator); PGPEncryptedDataList enc; Object o =
			 * pgpObjectFactory.nextObject();
			 * 
			 * if (o instanceof PGPEncryptedDataList) { enc = (PGPEncryptedDataList) o; }
			 * else { enc = (PGPEncryptedDataList) pgpObjectFactory.nextObject(); }
			 * 
			 * Iterator it = enc.getEncryptedDataObjects(); PGPPrivateKey sKey = null;
			 * PGPPublicKeyEncryptedData pbe = null;
			 * 
			 * while (sKey == null && it.hasNext()) { pbe = (PGPPublicKeyEncryptedData)
			 * it.next(); sKey = findSecretKey(key, pbe.getKeyID(), passphrase); }
			 * 
			 * if (sKey == null) { throw new
			 * IllegalArgumentException("secret key for message not found."); }
			 * 
			 * InputStream clear = pbe.getDataStream(sKey, "BC"); PGPObjectFactory plainFact
			 * = new PGPObjectFactory(clear); Object message = plainFact.nextObject();
			 * 
			 * if (message instanceof PGPCompressedData) {
			 * 
			 * PGPCompressedData cData = (PGPCompressedData) message; PGPObjectFactory
			 * pgpFact = new PGPObjectFactory(cData.getDataStream()); message =
			 * pgpFact.nextObject(); }
			 * 
			 * ByteArrayOutputStream baos = new ByteArrayOutputStream();
			 * 
			 * if (message instanceof PGPLiteralData) {
			 * 
			 * PGPLiteralData ld = (PGPLiteralData) message; InputStream unc =
			 * ld.getInputStream();
			 * 
			 * int ch; while ((ch = unc.read()) >= 0) { baos.write(ch); }
			 * 
			 * } else if (message instanceof PGPOnePassSignatureList) { throw new
			 * PGPException(“encrypted message contains a signed message – not literal
			 * data.”); } else { throw new PGPException(“message is not a simple encrypted
			 * file – type unknown.”); } // write outputstream
			 * out.write(baos.toString().getBytes());
			 */
		} catch (Exception e) {
			e.printStackTrace();
			throw new Exception(e.toString());
		}
	}

	private static PGPPrivateKey findSecretKey(InputStream keyIn, long keyID, char[] pass)
			throws IOException, PGPException, NoSuchProviderException {

		/*
		 * PGPSecretKeyRingCollection pgpSec = new
		 * PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyIn)); PGPSecretKey
		 * pgpSecKey = pgpSec.getSecretKey(keyID);
		 * 
		 * if (pgpSecKey == null) { return null; }
		 * 
		 * return pgpSecKey.extractPrivateKey(pass, "BC");
		 */
		return null;
	}
}
