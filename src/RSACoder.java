import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.xml.sax.HandlerBase;

public class RSACoder extends Coder{
	public static final String KEY_ALGORITHM = "RSA";
	public static final String SIGNATURE_ALGORITHM = "MD5withRSA";
	public static final String public_key = "RSApublickey";
	public static final String private_key = "RSAprivatekey";

	/***
	 * 
	 * 创建公钥和私钥
	 * 
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static Map<String, Object> initKey() throws NoSuchAlgorithmException {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator
				.getInstance(KEY_ALGORITHM);

		// 初始化确定秘钥的大小
		keyPairGenerator.initialize(1024);
		// 获取密钥对
		KeyPair keyPair = keyPairGenerator.genKeyPair();

		// 获取公钥
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
	
		Map<String, Object> keyMap=new HashMap<String, Object>();
		
		keyMap.put(private_key, privateKey);
		keyMap.put(public_key, publicKey);

		return keyMap;
	}

	/****
	 * 获取公钥
	 * @param keyMap
	 * @return
	 * @throws Exception
	 */
	public static String getPublickey(Map<String, Object> keyMap) throws Exception{
		Key key=(Key) keyMap.get(public_key);
		return encryptBASE64(key.getEncoded()) ;
	}
	
	/****
	 * 获取私钥
	 * @param keyMap
	 * @return
	 * @throws Exception
	 */
	public static String getPrivatekey(Map<String, Object> keyMap) throws Exception{
		Key key=(Key) keyMap.get(private_key);
		return encryptBASE64(key.getEncoded()) ;
	}
	
	
	/***
	 * 用私钥加密
	 * @return
	 * @throws Exception 
	 */
	public static byte[] encryptByPrivateKey(byte[] data, String key) throws Exception{
		
		//还原秘钥
		byte[] keyBytes=decryptBASE64(key);
		
		//取的私钥
		PKCS8EncodedKeySpec encodedKeySpec=new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory=KeyFactory.getInstance(KEY_ALGORITHM);
		Key privatekey=keyFactory.generatePrivate(encodedKeySpec);
		
		//对数据加密
		Cipher cipher=Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, privatekey);
		
		return cipher.doFinal(data);
	}
	
	/***
	 * 用公钥加密
	 * @return
	 * @throws Exception 
	 */
	public static byte[] encryptByPublicKey(byte[] data, String key) throws Exception{
		
		//还原秘钥
		byte[] keyBytes=decryptBASE64(key);
		
		//取得公钥
		X509EncodedKeySpec  encodedKeySpec=new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory=KeyFactory.getInstance(KEY_ALGORITHM);
		Key publickey=keyFactory.generatePublic(encodedKeySpec);
		
		//对数据加密
		Cipher cipher=Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, publickey);
		
		return cipher.doFinal(data);
	}
	
	/***
	 * 用私钥解密
	 * @param data
	 * @param key
	 * @throws Exception 
	 */
	public static byte[] decryptByPrivateKey(byte[] data, String key) throws Exception {

		//还原秘钥
		byte[] keyBytes=decryptBASE64(key);
		
		//取的私钥
		PKCS8EncodedKeySpec encodedKeySpec=new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory=KeyFactory.getInstance(KEY_ALGORITHM);
		Key privatekey=keyFactory.generatePrivate(encodedKeySpec);
		
		//对数据解密
		Cipher cipher=Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, privatekey);
		
		return cipher.doFinal(data);
		
	}
	
	
	/***
	 * 用公钥解密
	 * @param data
	 * @param key
	 * @throws Exception 
	 */
	public static byte[] decryptByPublicKey(byte[] data, String key) throws Exception {
		
		//还原秘钥
		byte[] keyBytes=decryptBASE64(key);
		
		//取得公钥
		X509EncodedKeySpec  encodedKeySpec=new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory=KeyFactory.getInstance(KEY_ALGORITHM);
		Key publickey=keyFactory.generatePublic(encodedKeySpec);
		
		//对数据加密
		Cipher cipher=Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, publickey);
		
		return cipher.doFinal(data);
	}
	
	/** 
     * 用公钥校验数字签名 
     *  
     * @param data 
     *            加密数据 
     * @param publicKey 
     *            公钥 
     * @param sign 
     *            数字签名 
     *  
     * @return 校验成功返回true 失败返回false 
     * @throws Exception 
     *  
     */  
    public static boolean verify(byte[] data, String publicKey, String sign)  
            throws Exception {  
  
        // 解密由base64编码的公钥  
        byte[] keyBytes = decryptBASE64(publicKey);  
  
        // 构造X509EncodedKeySpec对象  
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);  
  
        // KEY_ALGORITHM 指定的加密算法  
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);  
  
        // 取公钥匙对象  
        PublicKey pubKey = keyFactory.generatePublic(keySpec);  
  
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);  
        signature.initVerify(pubKey);  
        signature.update(data);  
  
        // 验证签名是否正常  
        return signature.verify(decryptBASE64(sign));  
    }  
    
    /** 
     * 用私钥对信息生成数字签名 
     *  
     * @param data 
     *            加密数据 
     * @param privateKey 
     *            私钥 
     *  
     * @return 
     * @throws Exception 
     */  
    public static String sign(byte[] data, String privateKey) throws Exception {  
        // 解密由base64编码的私钥  
        byte[] keyBytes = decryptBASE64(privateKey);  
  
        // 构造PKCS8EncodedKeySpec对象  
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);  
  
        // KEY_ALGORITHM 指定的加密算法  
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);  
  
        // 取私钥匙对象  
        PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);  
  
        // 用私钥对信息生成数字签名  
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);  
        signature.initSign(priKey);  
        signature.update(data);  
 
        return encryptBASE64(signature.sign());  
    }  
  
}
