import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

/***
 * 
 * 1.甲方构建密钥对儿，将公钥公布给乙方，将私钥保留；双方约定数据加密算法；乙方通过甲方公钥构建密钥对儿，将公钥公布给甲方，将私钥保留。
 * 2.甲方使用私钥、乙方公钥、约定数据加密算法构建本地密钥，然后通过本地密钥加密数据，发送给乙方加密后的数据；乙方使用私钥、甲方公钥、
 * 约定数据加密算法构建本地密钥，然后通过本地密钥对数据解密。
 * 3.乙方使用私钥、甲方公钥、约定数据加密算法构建本地密钥，然后通过本地密钥加密数据，发送给甲方加密后的数据；甲方使用私钥、乙方公钥、
 * 约定数据加密算法构建本地密钥，然后通过本地密钥对数据解密。
 * a生成密钥对，b根据a的公钥生成，密钥对。数据传输时用a的私钥和b的公钥加密，b收到数据使用b的私钥和a的公钥解密，
 */
public class DHCoder extends Coder {

	public static final String ALGORITHM = "DH";

	/**
	 * 默认密钥字节数
	 * 
	 * <pre>
	 * DH 
	 * Default Keysize 1024   
	 * Keysize must be a multiple of 64, ranging from 512 to 1024 (inclusive).
	 * </pre>
	 */
	private static final int KEY_SIZE = 1024;

	/**
	 * DH加密下需要一种对称加密算法对数据加密，这里我们使用DES，也可以使用其他对称加密算法。
	 */
	public static final String SECRET_ALGORITHM = "DES";
	private static final String PUBLIC_KEY = "DHPublicKey";
	private static final String PRIVATE_KEY = "DHPrivateKey";

	/*****
	 * 初始化甲方密钥对
	 * 
	 * @return
	 * @throws Exception
	 */
	public static Map<String, Object> initKey() throws Exception {

		KeyPairGenerator keyPairGenerator = KeyPairGenerator
				.getInstance(ALGORITHM);
		keyPairGenerator.initialize(KEY_SIZE);

		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		// 甲方公钥
		DHPublicKey dhPublicKey = (DHPublicKey) keyPair.getPublic();
		// 甲方私钥
		DHPrivateKey dhPrivateKey = (DHPrivateKey) keyPair.getPrivate();

		Map<String, Object> keymap = new HashMap<String, Object>();

		keymap.put(PUBLIC_KEY, dhPublicKey);
		keymap.put(PRIVATE_KEY, dhPrivateKey);

		return keymap;
	}

	/****
	 * 初始化乙方密钥对
	 * 
	 * @param key
	 *            甲方公钥
	 * @return
	 * @throws Exception
	 */
	public static Map<String, Object> initKey(String key) throws Exception {

		// 解析甲方公钥
		byte[] keyBytes = decryptBASE64(key);
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
		PublicKey pubKey = keyFactory.generatePublic(x509KeySpec);

		// 由甲方公钥构建乙方密钥
		DHParameterSpec dhParamSpec = ((DHPublicKey) pubKey).getParams();

		KeyPairGenerator keyPairGenerator = KeyPairGenerator
				.getInstance(keyFactory.getAlgorithm());
		keyPairGenerator.initialize(dhParamSpec);

		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		// 乙方公钥
		DHPublicKey dhPublicKey = (DHPublicKey) keyPair.getPublic();
		// 乙方私钥
		DHPrivateKey dhPrivateKey = (DHPrivateKey) keyPair.getPrivate();

		Map<String, Object> keymap = new HashMap<String, Object>();

		keymap.put(PUBLIC_KEY, dhPublicKey);
		keymap.put(PRIVATE_KEY, dhPrivateKey);

		return keymap;
	}

	/*****
	 * 加密
	 * 
	 * @param data
	 *            待加密数据
	 * @param publicKey
	 *            公钥
	 * @param privateKey
	 *            私钥
	 * @return
	 * @throws Exception
	 */
	public static byte[] encrypt(byte[] data, String publicKey,
			String privateKey) throws Exception {
		// 使用本地密钥加密数据
		SecretKey secretKey = getSecretKey(publicKey, privateKey);
		Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		return cipher.doFinal(data);
	}

	/*****
	 * 解密
	 * 
	 * @param data
	 *            待解密数据
	 * @param publicKey
	 *            公钥
	 * @param privateKey
	 *            私钥
	 * @return
	 * @throws Exception
	 */
	public static byte[] decrypt(byte[] data, String publicKey,
			String privateKey) throws Exception {
		// 使用本地密钥解密数据
		SecretKey secretKey = getSecretKey(publicKey, privateKey);
		Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, secretKey);
		return cipher.doFinal(data);
	}

	/******
	 * 构建本地秘钥库
	 * 
	 * @param publicKey
	 * @param privateKey
	 * @return
	 * @throws Exception
	 */
	private static SecretKey getSecretKey(String publicKey, String privateKey)
			throws Exception {

		// 初始化公钥
		byte[] pubKeyBytes = decryptBASE64(publicKey);
		KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
				pubKeyBytes);
		PublicKey pubkey = keyFactory.generatePublic(x509EncodedKeySpec);

		// 初始化私钥
		byte[] preKeyBytes = decryptBASE64(privateKey);
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
				preKeyBytes);
		PrivateKey prikey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);

		KeyAgreement keyAgreement = KeyAgreement.getInstance(keyFactory
				.getAlgorithm());
		keyAgreement.init(prikey);
		keyAgreement.doPhase(pubkey, true);

		// 构建本地密钥
		SecretKey secretKey = keyAgreement.generateSecret(SECRET_ALGORITHM);
		return secretKey;
	}

	/****
	 * 获取私钥
	 * 
	 * @param keyMap
	 * @return
	 * @throws Exception
	 */
	public static String getPrivateKey(Map<String, Object> keyMap)
			throws Exception {

		Key key = (Key) keyMap.get(PRIVATE_KEY);

		return encryptBASE64(key.getEncoded());

	}
	
	/****
	 * 获取公钥
	 * 
	 * @param keyMap
	 * @return
	 * @throws Exception
	 */
	public static String getPublicKey(Map<String, Object> keyMap)
			throws Exception {
		Key key = (Key) keyMap.get(PUBLIC_KEY);
		return encryptBASE64(key.getEncoded());
	}
	
	
	
	
//	 /** 
//     * 初始化甲方密钥 
//     *  
//     * @return 
//     * @throws Exception 
//     */  
//    public static Map<String, Object> initKey() throws Exception {  
//        KeyPairGenerator keyPairGenerator = KeyPairGenerator  
//                .getInstance(ALGORITHM);  
//        keyPairGenerator.initialize(KEY_SIZE);  
//  
//        KeyPair keyPair = keyPairGenerator.generateKeyPair();  
//  
//        // 甲方公钥  
//        DHPublicKey publicKey = (DHPublicKey) keyPair.getPublic();  
//  
//        // 甲方私钥  
//        DHPrivateKey privateKey = (DHPrivateKey) keyPair.getPrivate();  
//  
//        Map<String, Object> keyMap = new HashMap<String, Object>(2);  
//  
//        keyMap.put(PUBLIC_KEY, publicKey);  
//        keyMap.put(PRIVATE_KEY, privateKey);  
//        return keyMap;  
//    }  
//  
//    /** 
//     * 初始化乙方密钥 
//     *  
//     * @param key 
//     *            甲方公钥 
//     * @return 
//     * @throws Exception 
//     */  
//    public static Map<String, Object> initKey(String key) throws Exception {  
//        // 解析甲方公钥  
//        byte[] keyBytes = decryptBASE64(key);  
//        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);  
//        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);  
//        PublicKey pubKey = keyFactory.generatePublic(x509KeySpec);  
//  
//        // 由甲方公钥构建乙方密钥  
//        DHParameterSpec dhParamSpec = ((DHPublicKey) pubKey).getParams();  
//  
//        KeyPairGenerator keyPairGenerator = KeyPairGenerator  
//                .getInstance(keyFactory.getAlgorithm());  
//        keyPairGenerator.initialize(dhParamSpec);  
//  
//        KeyPair keyPair = keyPairGenerator.generateKeyPair();  
//  
//        // 乙方公钥  
//        DHPublicKey publicKey = (DHPublicKey) keyPair.getPublic();  
//  
//        // 乙方私钥  
//        DHPrivateKey privateKey = (DHPrivateKey) keyPair.getPrivate();  
//  
//        Map<String, Object> keyMap = new HashMap<String, Object>(2);  
//  
//        keyMap.put(PUBLIC_KEY, publicKey);  
//        keyMap.put(PRIVATE_KEY, privateKey);  
//  
//        return keyMap;  
//    }  
//  
//    /** 
//     * 加密<br> 
//     *  
//     * @param data 
//     *            待加密数据 
//     * @param publicKey 
//     *            甲方公钥 
//     * @param privateKey 
//     *            乙方私钥 
//     * @return 
//     * @throws Exception 
//     */  
//    public static byte[] encrypt(byte[] data, String publicKey,  
//            String privateKey) throws Exception {  
//  
//        // 生成本地密钥  
//        SecretKey secretKey = getSecretKey(publicKey, privateKey);  
//  
//        // 数据加密  
//        Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());  
//        cipher.init(Cipher.ENCRYPT_MODE, secretKey);  
//  
//        return cipher.doFinal(data);  
//    }  
//  
//    /** 
//     * 解密<br> 
//     *  
//     * @param data 
//     *            待解密数据 
//     * @param publicKey 
//     *            乙方公钥 
//     * @param privateKey 
//     *            乙方私钥 
//     * @return 
//     * @throws Exception 
//     */  
//    public static byte[] decrypt(byte[] data, String publicKey,  
//            String privateKey) throws Exception {  
//  
//        // 生成本地密钥  
//        SecretKey secretKey = getSecretKey(publicKey, privateKey);  
//        // 数据解密  
//        Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());  
//        cipher.init(Cipher.DECRYPT_MODE, secretKey);  
//  
//        return cipher.doFinal(data);  
//    }  
//  
//    /** 
//     * 构建密钥 
//     *  
//     * @param publicKey 
//     *            公钥 
//     * @param privateKey 
//     *            私钥 
//     * @return 
//     * @throws Exception 
//     */  
//    private static SecretKey getSecretKey(String publicKey, String privateKey)  
//            throws Exception {  
//        // 初始化公钥  
//        byte[] pubKeyBytes = decryptBASE64(publicKey);  
//  
//        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);  
//        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(pubKeyBytes);  
//        PublicKey pubKey = keyFactory.generatePublic(x509KeySpec);  
//  
//        // 初始化私钥  
//        byte[] priKeyBytes = decryptBASE64(privateKey);  
//  
//        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(priKeyBytes);  
//        Key priKey = keyFactory.generatePrivate(pkcs8KeySpec);  
//  
//        KeyAgreement keyAgree = KeyAgreement.getInstance(keyFactory  
//                .getAlgorithm());  
//        keyAgree.init(priKey);  
//        keyAgree.doPhase(pubKey, true);  
//  
//        // 生成本地密钥  
//        SecretKey secretKey = keyAgree.generateSecret(SECRET_ALGORITHM);  
//  
//        return secretKey;  
//    }  
//  
//    /** 
//     * 取得私钥 
//     *  
//     * @param keyMap 
//     * @return 
//     * @throws Exception 
//     */  
//    public static String getPrivateKey(Map<String, Object> keyMap)  
//            throws Exception {  
//        Key key = (Key) keyMap.get(PRIVATE_KEY);  
//  
//        return encryptBASE64(key.getEncoded());  
//    }  
//  
//    /** 
//     * 取得公钥 
//     *  
//     * @param keyMap 
//     * @return 
//     * @throws Exception 
//     */  
//    public static String getPublicKey(Map<String, Object> keyMap)  
//            throws Exception {  
//        Key key = (Key) keyMap.get(PUBLIC_KEY);  
//  
//        return encryptBASE64(key.getEncoded());  
//    } 
}
