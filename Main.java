import java.nio.file.Path;
import java.io.IOException;

import cryptoguard.utils.FileUtils;
import cryptoguard.crypto.SHA256;

public class Main {
  public static void main(String args[]){
    System.out.println("Test for the SHA256");

    try {
      //Define our File Locations
      Path original = Path.of("data/original/test.bin");
      Path tampered = Path.of("data/tampered/test.bin");

      //Create 1Kb file
      FileUtils.generateTestFile(original, 1024);

      //Calculate the original Hash
      byte[] originalHash = SHA256.computeHash(original);
      System.out.println("Original Hash: " + SHA256.computeHashHex(original));

      //Verify the untouched file
      boolean originalValid = SHA256.verifyHash(original, originalHash);

      //Simulate the tampering in process
      FileUtils.createTamperedCopy(original, tampered);

      //Verify the Modified file
      boolean tamperedValid = SHA256.verifyHash(tampered, originalHash);

      //Display the result
      System.out.println("Original file valid: " + originalValid);
      System.out.println("Tampered file valid: " + tamperedValid);
    }catch (IOException e){
      System.err.println("File error: " + e);
    }
  }
}
