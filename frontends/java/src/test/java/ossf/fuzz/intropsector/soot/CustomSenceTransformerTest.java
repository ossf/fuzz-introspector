package ossf.fuzz.introspector.soot;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.common.io.Files;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Properties;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Test;
import soot.SceneTransformer;

public class CustomSenceTransformerTest {
  @Test
  public void testNoException() {
    assertDoesNotThrow(() -> {});
  }

  @Test
  public void testBasic() {
    CustomSenceTransformer custom = new CustomSenceTransformer("", "", "");
    assertTrue(custom instanceof SceneTransformer);
    assertTrue(custom instanceof CustomSenceTransformer);
    assertEquals(custom.getExcludeList().size(), 0);
  }

  @Test
  public void testExcludePrefix() {
    CustomSenceTransformer custom = new CustomSenceTransformer("", "", "abc:def:ghi");
    assertEquals(custom.getExcludeList().size(), 3);
    Object[] expected = {"abc", "def", "ghi"};
    assertArrayEquals(custom.getExcludeList().toArray(), expected);
  }

  @Test
  public void sampleTestCases() throws IOException, InterruptedException {
    File baseDir = new File("../../tests/java");
    File jarDir = new File(baseDir, "test-jar");
    int i;

    for (i = 1; i <= 14; i++) {
      System.out.println("Testing test case " + i);

      Properties config = new Properties();
      File testDir = new File(baseDir, "test" + i);
      File sampleDir = new File(testDir, "sample");

      // Build jar file
      Runtime.getRuntime()
          .exec(String.format("%s/buildTest.sh test%d", baseDir.getAbsolutePath(), i))
          .waitFor();

      FileInputStream fis = new FileInputStream(new File(testDir, ".config"));
      config.load(fis);
      fis.close();

      String jarfile = config.getProperty("jarfile").replace("$PWD", jarDir.getAbsolutePath());
      String entryClasses = config.getProperty("entryclass");
      String entryMethod = "fuzzerTestOneInput";
      String excludePrefix = "jdk.:java.:javax.:sun.:sunw.:com.sun.:com.ibm.:com.apple.:apple.awt.";

      for (String entryClass : entryClasses.split(":")) {
      String[] args = {jarfile, entryClass, entryMethod, excludePrefix};
      CallGraphGenerator.main(args);

      String fileName = "fuzzerLogFile-" + entryClass + ".data";
        File sampleFile = new File(sampleDir, fileName);
        File actualFile = new File(fileName);

        if (i <= 9) {
          assertEquals(
              FileUtils.readFileToString(sampleFile, "utf-8"),
              FileUtils.readFileToString(actualFile, "utf-8"));
        } else {
          assertEquals(
              Files.readLines(sampleFile, Charset.defaultCharset()).get(0),
              Files.readLines(actualFile, Charset.defaultCharset()).get(0));
        }
      }

      System.out.println("Finish testing test case " + i);
    }
  }
}
