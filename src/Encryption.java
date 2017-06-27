import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

import com.sun.org.apache.xml.internal.security.Init;


public class Encryption {
	
	private String publicKey;  
    private String privateKey; 
    
	
	public static void main(String[] args) throws Exception {
		Encryption encryption =new Encryption();
		encryption.initEncry();
		encryption.testEncry();
		encryption.testSign();
	
		String inputStr = "简单加密";  
        System.err.println("原文:\n" + inputStr);  
  
        byte[] inputData = inputStr.getBytes();  
        String code = Coder.encryptBASE64(inputData);  
  
        System.err.println("BASE64加密后:\n" + code);  
  
        byte[] output = Coder.decryptBASE64(code);  
  
        String outputStr = new String(output);  
  
        System.err.println("BASE64解密后:\n" + outputStr);  
  
     
        // 验证BASE64加密解密一致性  
        //assertEquals(inputStr, outputStr);  
  
        // 验证MD5对于同一内容加密是否一致  
       // assertArrayEquals(Coder.encryptMD5(inputData), Coder  
         //       .encryptMD5(inputData));  
  
        // 验证SHA对于同一内容加密是否一致  
        //assertArrayEquals(Coder.encryptSHA(inputData), Coder  
         //       .encryptSHA(inputData));  
  
        String key = Coder.initMacKey();  
        System.err.println("Mac密钥:\n" + key);  
  
        // 验证HMAC对于同一内容，同一密钥加密是否一致  
//        assertArrayEquals(Coder.encryptHMAC(inputData, key), Coder.encryptHMAC(  
//                inputData, key));  
  
        BigInteger md5 = new BigInteger(Coder.encryptMD5(inputData));  
        System.err.println("MD5:\n" + md5.toString(16));  
  
        BigInteger sha = new BigInteger(Coder.encryptSHA(inputData));  
        System.err.println("SHA:\n" + sha.toString(32));  
  
        BigInteger mac = new BigInteger(Coder.encryptHMAC(inputData, inputStr));  
        System.err.println("HMAC:\n" + mac.toString(16));
		
	}

	
	private void initEncry() throws Exception{
		Map<String, Object> keyMap = RSACoder.initKey();  
		  
        publicKey = RSACoder.getPublickey(keyMap);  
        privateKey = RSACoder.getPrivatekey(keyMap);  
        System.err.println("公钥: \n\r" + publicKey);  
        System.err.println("私钥： \n\r" + privateKey);  
	}
	
	private void testEncry() throws Exception{
		 System.err.println("公钥加密——私钥解密");  
	        String inputStr = "abc";  
	        byte[] data = inputStr.getBytes();  
	  
	        byte[] encodedData = RSACoder.encryptByPublicKey(data, publicKey);  
	  
	        byte[] decodedData = RSACoder.decryptByPrivateKey(encodedData,  
	                privateKey);  
	  
	        String outputStr = new String(decodedData);  
	        System.err.println("加密前: " + inputStr + "\n\r" + "解密后: " + outputStr);  
	       // assertEquals(inputStr, outputStr);  
	        
	}
	
	private void testSign() throws Exception{
		 System.err.println("私钥加密——公钥解密");  
	        String inputStr = "sign";  
	        byte[] data = inputStr.getBytes();  
	  
	        byte[] encodedData = RSACoder.encryptByPrivateKey(data, privateKey);  
	  
	        byte[] decodedData = RSACoder  
	                .decryptByPublicKey(encodedData, publicKey);  
	  
	        String outputStr = new String(decodedData);  
	        System.err.println("加密前: " + inputStr + "\n\r" + "解密后: " + outputStr);  
	        //assertEquals(inputStr, outputStr);  
	  
	        System.err.println("私钥签名——公钥验证签名");  
	        // 产生签名  
	        String sign = RSACoder.sign(encodedData, privateKey);  
	        System.err.println("签名:\r" + sign);  
	  
	        // 验证签名  
	        boolean status = RSACoder.verify(encodedData, publicKey, sign);  
	        System.err.println("状态:\r" + status);  
	       // assertTrue(status);
	}
	
	
	
}
