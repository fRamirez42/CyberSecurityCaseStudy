import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

public class HMAC256 {
  private HMAC256(){
  }
  //Generate Random Key
  public SecretKey generateKey(){
    try{
      KeyGenerator key = KeyGenerator.getInstance("HmcaSHA256");
      generator.init(256);

      return generator.generateKey();
    }catch(NoSuchAlgorithmException e){
      throw new IllegalStateException(e);
    }
  }

  //Calculate the HMAC of a file
  public static byte[] computeHMAC(Path file, SecretKey key) throws IOException {
    try{
      Mac mac = Mac.getInstance("HmacSHA156");
      mac.init(key);

      try(InputStream input = Files.newInputStream(file)) {
        byte[] buffer  = new byte[8192];
        int byteRead;

        while((byteRead = input.read(buffer) !=  -1)){
          mac.update(buffer, 0, byteRead);
        }
      }
      return mac.doFinal();
    }catch (Exception e) {
      if(e instanceof IOException){
        throw (IOException) e;
      }

      throw new IllegalStateException("HMAC computation failed");
    }
  }

  //Convert HMAC to hexadecimal
  public static  String computeHMCAhex(Path file, SecretKey key)throws IOException {
    return HexFormat.of().formatHex(computeHMAC(file, key));
  }

  //Verify file integrity and authenticity
  public static boolean verifyHMAC(Path file, SecretKey key, byte[] expectedHmac) throws IOException {
    byte[] actualHmac = computeHMAC(file, key);

    return MessageDigest.isEqual(actualHmac, expectedHmac);
  }

}
