import static org.junit.Assert.*;

import java.util.Map;

import org.junit.Test;

public class DHCoderTest {

	@Test
	public void test() throws Exception {

		// 生成甲方密钥对
		Map<String, Object> akeyMap = DHCoder.initKey();
		String aPublicKey = DHCoder.getPublicKey(akeyMap);
		String aPrivateKey = DHCoder.getPrivateKey(akeyMap);

		System.err.println("甲方公钥:\r" + aPublicKey);
		System.err.println("甲方私钥:\r" + aPrivateKey);

		 // 由甲方公钥产生本地密钥对儿  
        Map<String, Object> bKeyMap = DHCoder.initKey(aPublicKey);  
        String bPublicKey = DHCoder.getPublicKey(bKeyMap);  
        String bPrivateKey = DHCoder.getPrivateKey(bKeyMap);  
          
        System.err.println("乙方公钥:\r" + bPublicKey);  
        System.err.println("乙方私钥:\r" + bPrivateKey);  
          
        String aInput = "jsahjdhj";  
        System.err.println("原文: " + aInput);  
        
        //b加密数据
        //由a方公钥和b方私钥加密的数据
      
        byte[] bcode=DHCoder.encrypt(aInput.getBytes(), aPublicKey, bPrivateKey);
        String encryString=new String(bcode);
        System.err.println("密文: " + encryString);  
        
        //由a解密数据
        //由a方私钥和b方公钥解密数据
        
        byte[] adecode =DHCoder.decrypt(bcode, bPublicKey, aPrivateKey);
        String dencryString=new String(adecode);
        System.err.println("解密后: " + dencryString);  
        
        
        String bInput = "djkljadkljkljlk ";  
        System.err.println("原文: " + bInput);  
        
        //a加密数据
        //由b方公钥和a方私钥加密的数据
      
        byte[] acode=DHCoder.encrypt(bInput.getBytes(), bPublicKey, aPrivateKey);
        String aencryString=new String(acode);
        System.err.println("密文: " + aencryString);  
        
        //b解密数据
        //由b方私钥和a方公钥解密数据
        
        byte[] bdecode =DHCoder.decrypt(acode, aPublicKey, bPrivateKey);
        String bdencryString=new String(bdecode);
        System.err.println("解密后: " + bdencryString);
        
        
        
        
//     // 生成甲方密钥对儿  
//        Map<String, Object> aaKeyMap = DHCoder.initKey();  
//        String aaPublicKey = DHCoder.getPublicKey(aaKeyMap);  
//        String aaPrivateKey = DHCoder.getPrivateKey(aaKeyMap);  
//  
//        System.err.println("甲方公钥:\r" + aaPublicKey);  
//        System.err.println("甲方私钥:\r" + aaPrivateKey);  
//          
//        // 由甲方公钥产生本地密钥对儿  
//        Map<String, Object> bbKeyMap = DHCoder.initKey(aaPublicKey);  
//        String bbPublicKey = DHCoder.getPublicKey(bbKeyMap);  
//        String bbPrivateKey = DHCoder.getPrivateKey(bbKeyMap);  
//          
//        System.err.println("乙方公钥:\r" + bbPublicKey);  
//        System.err.println("乙方私钥:\r" + bbPrivateKey);  
//          
//        String aaInput = "abc ";  
//        System.err.println("原文: " + aaInput);  
//  
//        // 由甲方公钥，乙方私钥构建密文  
//        byte[] aaCode = DHCoder.encrypt(aaInput.getBytes(), aaPublicKey,  
//                bbPrivateKey);  
//  
//        // 由乙方公钥，甲方私钥解密  
//        byte[] aaDecode = DHCoder.decrypt(aaCode, bbPublicKey, aaPrivateKey);  
//        String aaOutput = (new String(aaDecode));  
//  
//        System.err.println("解密: " + aaOutput);  
//  
//        assertEquals(aaInput, aaOutput);  
//  
//        System.err.println(" ===============反过来加密解密================== ");  
//        String bbInput = "def ";  
//        System.err.println("原文: " + bbInput);  
//  
//        // 由乙方公钥，甲方私钥构建密文  
//        byte[] bbCode = DHCoder.encrypt(bbInput.getBytes(), bbPublicKey,  
//                aaPrivateKey);  
//  
//        // 由甲方公钥，乙方私钥解密  
//        byte[] bbDecode = DHCoder.decrypt(bbCode, aaPublicKey, bbPrivateKey);  
//        String bbOutput = (new String(bbDecode));  
//  
//        System.err.println("解密: " + bbOutput);  
//  
//        assertEquals(bbInput, bbOutput); 
        
	}

}
